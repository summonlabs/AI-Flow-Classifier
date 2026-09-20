// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/store/flow_registry.hpp"

#include <algorithm>
#include <string>

#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

// History is bounded per key: an incarnation that was fenced long ago is only kept
// so that a replay of its generation can be rejected deterministically.  Beyond the
// bound the oldest incarnations are dropped, which can only turn an exact
// STALE_GENERATION into the same STALE_GENERATION via a different path, never into
// an acceptance.
constexpr std::size_t kMaxHistoryPerKey = 8;

}  // namespace

std::string_view to_string(FlowRegistryOutcome outcome) noexcept {
  switch (outcome) {
    case FlowRegistryOutcome::CREATED:
      return "CREATED";
    case FlowRegistryOutcome::REPEATED:
      return "REPEATED";
    case FlowRegistryOutcome::GENERATION_ADVANCED:
      return "GENERATION_ADVANCED";
  }
  return "UNRECOGNIZED_FLOW_REGISTRY_OUTCOME";
}

Result<FlowRegistration> FlowRegistry::register_flow(const FlowKey& key,
                                                     FlowGeneration requested_generation,
                                                     const SessionId& session, Tick tick) {
  stats_.registrations += 1;
  const Id128 id = derive_flow_id(key);

  auto history_entry = history_.find(id);
  std::uint64_t highest_known = 0;
  if (history_entry != history_.end()) {
    for (const FlowRecord& record : history_entry->second) {
      highest_known = std::max(highest_known, record.generation.value);
    }
  }
  auto current_entry = current_.find(key);
  if (current_entry != current_.end()) {
    highest_known = std::max(highest_known, current_entry->second.generation.value);
  }

  if (requested_generation.value > kMaxAcceptableGeneration) {
    // Refused before anything is recorded, so the key is never pinned and a later legitimate
    // registration still has room.  This is the input-validation half of the Counter discipline in
    // foundation/math.hpp: a counter that refuses to wrap is useless if a peer can hand it the
    // maximum value.
    return Status::failure(ErrorCode::OUT_OF_RANGE,
                           "flow generation " + requested_generation.to_string() +
                               " exceeds the largest acceptable generation " +
                               std::to_string(kMaxAcceptableGeneration));
  }

  FlowGeneration generation = requested_generation;
  if (generation.value == 0) {
    // The caller is asking for a fresh incarnation without naming it.  Generation
    // zero is never a valid incarnation, so it can safely mean "next".
    generation.value = highest_known + 1;
    if (generation.value == 0) {
      return Status::failure(ErrorCode::COUNTER_EXHAUSTED, "flow generation space exhausted");
    }
  }

  if (current_entry != current_.end()) {
    FlowRecord& existing = current_entry->second;
    if (existing.id != id) {
      // Two different identities for the same key would mean the identity function
      // is not injective, which is an internal defect rather than bad input.
      return Status::failure(ErrorCode::INTERNAL_ERROR,
                             "flow id derivation is not injective for this key");
    }
    if (generation < existing.generation) {
      return Status::failure(ErrorCode::STALE_GENERATION,
                             "flow " + id.to_hex() + " is at generation " +
                                 existing.generation.to_string() + "; registration requested by " +
                                 generation.to_string() + " was refused");
    }
    if (generation == existing.generation) {
      existing.last_activity_tick = tick;
      existing.renewals += 1;
      stats_.repeats += 1;
      FlowRegistration registration;
      registration.record = existing;
      registration.created = false;
      registration.fenced_previous = false;
      registration.previous_generation = existing.generation;
      return registration;
    }
    // Strictly larger generation: fence the previous incarnation.
    const FlowGeneration previous = existing.generation;
    FlowRecord fenced = existing;
    auto& history = history_[id];
    history.push_back(fenced);
    while (history.size() > kMaxHistoryPerKey) {
      history.erase(history.begin());
    }

    FlowRecord record;
    record.id = id;
    record.key = key;
    record.generation = generation;
    record.registered_seq = fenced.registered_seq;
    record.registered_tick = tick;
    record.last_activity_tick = tick;
    record.registered_by = session;
    record.renewals = 0;
    current_entry->second = record;
    stats_.generation_advances += 1;

    FlowRegistration registration;
    registration.record = record;
    registration.created = true;
    registration.fenced_previous = true;
    registration.previous_generation = previous;
    return registration;
  }

  // A retired or fenced generation may not be resurrected.  Reusing a generation
  // that has already been observed would let stale evidence for that generation
  // become current again, so it is refused outright.
  if (history_entry != history_.end()) {
    for (const FlowRecord& record : history_entry->second) {
      if (record.generation == generation) {
        return Status::failure(ErrorCode::STALE_GENERATION,
                               "flow " + id.to_hex() + " generation " + generation.to_string() +
                                   " has already been superseded and cannot be re-registered");
      }
    }
  }

  if (current_.size() >= static_cast<std::size_t>(max_flows_)) {
    stats_.capacity_rejections += 1;
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "flow registry is full at " + std::to_string(max_flows_) + " flows");
  }

  FlowRecord record;
  record.id = id;
  record.key = key;
  record.generation = generation;
  record.registered_seq = 0;
  record.registered_tick = tick;
  record.last_activity_tick = tick;
  record.registered_by = session;
  record.renewals = 0;
  current_.emplace(key, record);

  FlowRegistration registration;
  registration.record = record;
  registration.created = true;
  registration.fenced_previous = false;
  registration.previous_generation = FlowGeneration{};
  return registration;
}

Result<FlowRecord> FlowRegistry::find_by_key(const FlowKey& key) const {
  stats_.lookups += 1;
  auto entry = current_.find(key);
  if (entry == current_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_FLOW, "no flow registered for this key");
  }
  return entry->second;
}

Result<FlowRecord> FlowRegistry::find_by_id(const FlowId& id) const {
  stats_.lookups += 1;
  for (const auto& entry : current_) {
    if (entry.second.id == id) return entry.second;
  }
  return Status::failure(ErrorCode::UNKNOWN_FLOW, "no flow registered with this identity");
}

Result<FlowRecord> FlowRegistry::find_generation(const FlowId& id,
                                                 FlowGeneration generation) const {
  stats_.lookups += 1;
  for (const auto& entry : current_) {
    if (entry.second.id == id && entry.second.generation == generation) {
      return entry.second;
    }
  }
  auto history_entry = history_.find(id);
  if (history_entry != history_.end()) {
    for (const FlowRecord& record : history_entry->second) {
      if (record.generation == generation) return record;
    }
  }
  return Status::failure(ErrorCode::UNKNOWN_FLOW,
                         "flow " + id.to_hex() + " has no generation " + generation.to_string());
}

bool FlowRegistry::is_current(const FlowRecord& record) const {
  auto entry = current_.find(record.key);
  if (entry == current_.end()) return false;
  return entry->second.id == record.id && entry->second.generation == record.generation;
}

Status FlowRegistry::retire_flow(const FlowId& id, FlowGeneration generation, Tick tick) {
  for (auto entry = current_.begin(); entry != current_.end(); ++entry) {
    if (entry->second.id == id && entry->second.generation == generation) {
      FlowRecord record = entry->second;
      record.last_activity_tick = tick;
      auto& history = history_[id];
      history.push_back(record);
      while (history.size() > kMaxHistoryPerKey) {
        history.erase(history.begin());
      }
      current_.erase(entry);
      return Status::success();
    }
  }
  return Status::failure(ErrorCode::UNKNOWN_FLOW, "flow incarnation not found for retirement");
}

std::vector<FlowRecord> FlowRegistry::snapshot_flows() const {
  std::vector<FlowRecord> out;
  out.reserve(current_.size());
  for (const auto& entry : current_) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(), [](const FlowRecord& a, const FlowRecord& b) {
    return a.id < b.id;
  });
  return out;
}

Status FlowRegistry::restore_flow(const FlowRecord& record) {
  auto entry = current_.find(record.key);
  if (entry != current_.end()) {
    if (entry->second.generation == record.generation) {
      entry->second = record;
      return Status::success();
    }
    if (entry->second.generation > record.generation) {
      auto& history = history_[record.id];
      history.push_back(record);
      while (history.size() > kMaxHistoryPerKey) {
        history.erase(history.begin());
      }
      return Status::success();
    }
  }
  if (current_.size() >= static_cast<std::size_t>(max_flows_) && entry == current_.end()) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "flow registry is full while restoring state");
  }
  current_[record.key] = record;
  return Status::success();
}

void FlowRegistry::clear() {
  current_.clear();
  history_.clear();
  stats_ = FlowRegistryStats{};
}

}  // namespace aifc
