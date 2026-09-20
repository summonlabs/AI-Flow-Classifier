// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/store/classification_index.hpp"

#include <algorithm>
#include <string>

namespace aifc {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

void append_u64_hex(std::string& out, std::uint64_t value) {
  for (int shift = 60; shift >= 0; shift -= 4) {
    out.push_back(kHexDigits[(value >> shift) & 0x0FU]);
  }
}

}  // namespace

std::string make_decision_key_text(const DecisionKey& key) {
  std::string out;
  out.reserve(32 + 20 + 64 + 20 + 3);
  append_u64_hex(out, key.flow_id.hi);
  append_u64_hex(out, key.flow_id.lo);
  out.push_back('|');
  append_u64_hex(out, key.flow_generation.value);
  out.push_back('|');
  out += key.evidence_digest.to_hex();
  out.push_back('|');
  append_u64_hex(out, key.policy_generation.value);
  return out;
}

Result<Classification> ClassificationIndex::record(const Classification& classification) {
  FlowHistory& history = history_[classification.flow_id];
  Classification previous;
  bool have_previous = false;
  // The previous *current* decision for the same generation is the one that is
  // superseded.  A decision for a different generation is not a predecessor and
  // must not be reported as one.
  for (auto iterator = history.decisions.rbegin(); iterator != history.decisions.rend();
       ++iterator) {
    if (iterator->flow_generation == classification.flow_generation) {
      previous = *iterator;
      have_previous = true;
      break;
    }
  }

  history.decisions.push_back(classification);
  while (history.decisions.size() > static_cast<std::size_t>(max_decisions_per_flow_)) {
    history.decisions.pop_front();
    stats_.history_evictions += 1;
  }
  stats_.decisions_recorded += 1;
  stats_.flows_with_history = history_.size();

  // A contradiction record is itself bounded per flow, so a flow that flaps between
  // two declarations cannot grow history without limit.
  for (const ClassificationContradiction& contradiction : classification.contradictions) {
    history.contradictions.push_back(contradiction);
    stats_.contradictions_recorded += 1;
  }
  while (history.contradictions.size() > static_cast<std::size_t>(max_contradictions_)) {
    history.contradictions.pop_front();
  }

  if (!have_previous) {
    return Classification{};
  }
  return previous;
}

Result<Classification> ClassificationIndex::latest(const FlowId& flow,
                                                   FlowGeneration generation) const {
  auto entry = history_.find(flow);
  if (entry == history_.end()) {
    return Status::failure(ErrorCode::NOT_FOUND, "no classification history for this flow");
  }
  for (auto iterator = entry->second.decisions.rbegin();
       iterator != entry->second.decisions.rend(); ++iterator) {
    if (iterator->flow_generation == generation) {
      return *iterator;
    }
  }
  return Status::failure(ErrorCode::NOT_FOUND,
                         "no classification recorded for this flow generation");
}

bool ClassificationIndex::memo_lookup(const DecisionKey& key, Classification& out) {
  const std::string text = make_decision_key_text(key);
  auto entry = memo_.find(text);
  if (entry == memo_.end()) {
    stats_.memo_misses += 1;
    return false;
  }
  out = entry->second;
  stats_.memo_hits += 1;
  return true;
}

void ClassificationIndex::memo_store(const DecisionKey& key, const Classification& classification) {
  const std::string text = make_decision_key_text(key);
  auto entry = memo_.find(text);
  if (entry != memo_.end()) {
    entry->second = classification;
    return;
  }
  if (memo_.size() >= static_cast<std::size_t>(max_memo_entries_)) {
    // Insertion-order eviction.  The memo has no authority, so an approximate
    // eviction policy costs nothing but recomputation.
    while (!memo_order_.empty() && memo_.size() >= static_cast<std::size_t>(max_memo_entries_)) {
      const std::string oldest = memo_order_.front();
      memo_order_.pop_front();
      if (memo_.erase(oldest) > 0) {
        stats_.memo_evictions += 1;
      }
    }
    if (memo_.size() >= static_cast<std::size_t>(max_memo_entries_)) {
      return;
    }
  }
  memo_.emplace(text, classification);
  memo_order_.push_back(text);
  stats_.memo_entries = memo_.size();
}

Status ClassificationIndex::record_contradiction(const FlowId& flow,
                                                 const ClassificationContradiction& contradiction,
                                                 Tick tick) {
  FlowHistory& history = history_[flow];
  history.contradictions.push_back(contradiction);
  while (history.contradictions.size() > static_cast<std::size_t>(max_contradictions_)) {
    history.contradictions.pop_front();
  }
  stats_.contradictions_recorded += 1;
  (void)tick;
  return Status::success();
}

Status ClassificationIndex::record_supersession(const SupersessionRecord& record) {
  if (supersessions_.size() >= static_cast<std::size_t>(max_supersessions_)) {
    supersessions_.erase(supersessions_.begin());
  }
  supersessions_.push_back(record);
  stats_.supersessions += 1;
  return Status::success();
}

Status ClassificationIndex::record_revocation(const RevocationRecord& record) {
  if (revocations_.size() >= static_cast<std::size_t>(max_revocations_)) {
    revocations_.erase(revocations_.begin());
  }
  revocations_.push_back(record);
  stats_.revocations += 1;
  return Status::success();
}

Result<std::vector<ClassificationContradiction>> ClassificationIndex::contradictions_for(
    const FlowId& flow) const {
  auto entry = history_.find(flow);
  if (entry == history_.end()) {
    return std::vector<ClassificationContradiction>{};
  }
  return std::vector<ClassificationContradiction>(entry->second.contradictions.begin(),
                                                  entry->second.contradictions.end());
}

std::vector<RevocationRecord> ClassificationIndex::revocations() const { return revocations_; }

std::vector<SupersessionRecord> ClassificationIndex::supersessions() const {
  return supersessions_;
}

bool ClassificationIndex::is_revoked(const FlowId& flow, FlowGeneration generation) const {
  for (const RevocationRecord& record : revocations_) {
    // A record that names one evidence identity is a withdrawal of that record: the
    // generation is not revoked, the withdrawn evidence simply stops being current.  Only a
    // generation level revocation, which names no evidence identity, revokes the incarnation.
    if (record.flow_id == flow && record.flow_generation == generation &&
        record.evidence_id.empty()) {
      return true;
    }
  }
  return false;
}

std::uint32_t ClassificationIndex::supersede_generation(const FlowId& flow,
                                                        FlowGeneration superseded_by, Tick tick) {
  auto entry = history_.find(flow);
  if (entry == history_.end()) return 0;
  std::uint32_t affected = 0;
  for (Classification& classification : entry->second.decisions) {
    if (classification.flow_generation >= superseded_by) continue;
    if (classification.state == ClassificationState::STALE) continue;
    classification.state = ClassificationState::STALE;
    ++affected;
  }
  (void)tick;
  return affected;
}

std::vector<Classification> ClassificationIndex::snapshot_classifications() const {
  std::vector<Classification> out;
  for (const auto& entry : history_) {
    for (const Classification& classification : entry.second.decisions) {
      out.push_back(classification);
    }
  }
  std::sort(out.begin(), out.end(), [](const Classification& a, const Classification& b) {
    if (a.flow_id != b.flow_id) return a.flow_id < b.flow_id;
    return a.flow_generation < b.flow_generation;
  });
  return out;
}

Status ClassificationIndex::restore_classification(const Classification& classification) {
  FlowHistory& history = history_[classification.flow_id];
  history.decisions.push_back(classification);
  while (history.decisions.size() > static_cast<std::size_t>(max_decisions_per_flow_)) {
    history.decisions.pop_front();
  }
  // The memo is deliberately not rebuilt from durable state.  A memo entry is only
  // valid if it was produced from the exact same evidence set in this process, and
  // the evidence set is not part of the snapshot.
  return Status::success();
}

Status ClassificationIndex::restore_revocation(const RevocationRecord& record) {
  if (revocations_.size() >= static_cast<std::size_t>(max_revocations_)) {
    revocations_.erase(revocations_.begin());
  }
  revocations_.push_back(record);
  return Status::success();
}

Status ClassificationIndex::restore_supersession(const SupersessionRecord& record) {
  if (supersessions_.size() >= static_cast<std::size_t>(max_supersessions_)) {
    supersessions_.erase(supersessions_.begin());
  }
  supersessions_.push_back(record);
  return Status::success();
}

void ClassificationIndex::clear() {
  history_.clear();
  memo_.clear();
  memo_order_.clear();
  revocations_.clear();
  supersessions_.clear();
  stats_ = ClassificationIndexStats{};
}

}  // namespace aifc
