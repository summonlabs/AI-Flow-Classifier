// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/store/evidence_store.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace aifc {
namespace {

[[nodiscard]] std::string key_of(const EvidenceId& id) { return id.value(); }

}  // namespace

Status EvidenceStore::insert(EvidenceRecord record) {
  if (record.id.empty()) {
    stats_.rejected += 1;
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "evidence identity is empty");
  }
  const std::string key = key_of(record.id);
  auto existing = by_id_.find(key);
  if (existing != by_id_.end()) {
    if (existing->second.content_digest == record.content_digest &&
        existing->second.publisher == record.publisher) {
      // An identical repeat of an accepted record.  Idempotent: the caller's earlier
      // acknowledgement stands and nothing changes.
      return Status::success();
    }
    stats_.rejected += 1;
    return Status::failure(ErrorCode::DUPLICATE_IDENTITY,
                           "evidence id " + record.id.value() +
                               " already exists with different content");
  }

  if (by_id_.size() >= static_cast<std::size_t>(max_records_)) {
    // The ring is full: the oldest accepted record is evicted.  Eviction is counted
    // and reported, never silent.
    evict_oldest();
    if (by_id_.size() >= static_cast<std::size_t>(max_records_)) {
      stats_.capacity_rejections += 1;
      return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                             "evidence store is full at " + std::to_string(max_records_) +
                                 " records and nothing could be evicted");
    }
  }

  auto flow_index = by_flow_.find(record.flow_id);
  if (flow_index == by_flow_.end() && by_flow_.size() >= static_cast<std::size_t>(max_flow_index_)) {
    stats_.capacity_rejections += 1;
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "evidence flow index is full at " + std::to_string(max_flow_index_) +
                               " flows");
  }

  if (flow_index != by_flow_.end()) {
    std::deque<std::string>& ids = flow_index->second;
    while (!ids.empty() && ids.size() >= static_cast<std::size_t>(max_per_flow_)) {
      // The per-flow bound is a ring too.  The evicted record stays in the store
      // until the global ring reaches it; it is simply no longer reachable from its
      // flow, which is what bounds classification cost.
      ids.pop_front();
      stats_.evicted_per_flow += 1;
    }
    ids.push_back(key);
  } else {
    std::deque<std::string> ids;
    ids.push_back(key);
    by_flow_.emplace(record.flow_id, std::move(ids));
  }

  by_id_.emplace(key, std::move(record));
  order_.push_back(key);
  stats_.accepted += 1;
  stats_.records = by_id_.size();
  stats_.indexed_flows = by_flow_.size();
  return Status::success();
}

Result<EvidenceRecord> EvidenceStore::find(const EvidenceId& id) const {
  auto entry = by_id_.find(key_of(id));
  if (entry == by_id_.end()) {
    return Status::failure(ErrorCode::NOT_FOUND, "no evidence record " + id.value());
  }
  return entry->second;
}

Result<std::vector<EvidenceId>> EvidenceStore::evidence_for_flow(const FlowId& id) const {
  std::vector<EvidenceId> out;
  auto entry = by_flow_.find(id);
  if (entry == by_flow_.end()) {
    return out;
  }
  out.reserve(entry->second.size());
  // Collected through the id index, which keeps the flow index small and makes the
  // ordering explicitly the insertion order of the per-flow ring.
  std::vector<const EvidenceRecord*> records;
  records.reserve(entry->second.size());
  for (const std::string& key : entry->second) {
    auto record_entry = by_id_.find(key);
    if (record_entry == by_id_.end()) continue;
    records.push_back(&record_entry->second);
  }
  std::sort(records.begin(), records.end(), [](const EvidenceRecord* a, const EvidenceRecord* b) {
    return a->accepted_seq < b->accepted_seq;
  });
  for (const EvidenceRecord* record : records) {
    out.push_back(record->id);
  }
  return out;
}

Status EvidenceStore::set_state(const EvidenceId& id, EvidenceState state, std::string reason,
                                Tick tick) {
  auto entry = by_id_.find(key_of(id));
  if (entry == by_id_.end()) {
    return Status::failure(ErrorCode::NOT_FOUND, "no evidence record " + id.value());
  }
  EvidenceRecord& record = entry->second;
  if (record.state == state) {
    return Status::success();
  }
  // A record may move from CURRENT to a weaker state, or between weaker states.  It
  // may never move back to CURRENT: re-establishing authority requires a new
  // publication with a new generation, never a state edit.
  if (record.state != EvidenceState::EVIDENCE_CURRENT && state == EvidenceState::EVIDENCE_CURRENT) {
    return Status::failure(ErrorCode::UNAUTHORIZED,
                           "evidence " + id.value() +
                               " cannot be returned to CURRENT; republish with a new generation");
  }
  if (state == EvidenceState::EVIDENCE_STALE) stats_.stale_transitions += 1;
  if (state == EvidenceState::EVIDENCE_SUPERSEDED) stats_.superseded += 1;
  if (state == EvidenceState::EVIDENCE_REVOKED) stats_.withdrawn += 1;
  record.state = state;
  record.state_reason = std::move(reason);
  if (tick != kTickNone) {
    record.fresh_until = record.fresh_until;  // freshness deadline is not rewritten by a state change
  }
  return Status::success();
}

std::uint32_t EvidenceStore::mark_stale_by_predicate(
    const std::function<bool(const EvidenceRecord&)>& predicate, std::string reason, Tick tick) {
  std::uint32_t changed = 0;
  for (auto& entry : by_id_) {
    EvidenceRecord& record = entry.second;
    if (record.state != EvidenceState::EVIDENCE_CURRENT) continue;
    if (!predicate(record)) continue;
    record.state = EvidenceState::EVIDENCE_STALE;
    record.state_reason = reason;
    ++changed;
    stats_.stale_transitions += 1;
  }
  (void)tick;
  return changed;
}

std::uint32_t EvidenceStore::mark_epoch_stale(CoordinatorEpoch current_epoch, Tick tick) {
  std::uint32_t changed = 0;
  for (auto& entry : by_id_) {
    EvidenceRecord& record = entry.second;
    if (record.state != EvidenceState::EVIDENCE_CURRENT) continue;
    if (record.accepted_epoch == current_epoch) continue;
    record.state = EvidenceState::EVIDENCE_STALE;
    record.state_reason = "accepted in coordinator epoch " + record.accepted_epoch.to_string() +
                          "; the coordinator is now at epoch " + current_epoch.to_string() +
                          " and dynamic authority does not survive a restart";
    ++changed;
    stats_.revalidation_transitions += 1;
  }
  (void)tick;
  return changed;
}

std::vector<EvidenceRecord> EvidenceStore::snapshot_records() const {
  std::vector<EvidenceRecord> out;
  out.reserve(by_id_.size());
  for (const auto& entry : by_id_) out.push_back(entry.second);
  std::sort(out.begin(), out.end(), [](const EvidenceRecord& a, const EvidenceRecord& b) {
    return a.id < b.id;
  });
  return out;
}

Status EvidenceStore::restore_record(EvidenceRecord record) {
  const std::string key = key_of(record.id);
  if (by_id_.find(key) != by_id_.end()) {
    return Status::failure(ErrorCode::DUPLICATE_IDENTITY,
                           "evidence " + record.id.value() + " restored twice");
  }
  if (by_id_.size() >= static_cast<std::size_t>(max_records_)) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "evidence store is full while restoring persisted state");
  }
  // A restored record is never CURRENT.  Currentness is not a property that
  // survives a process boundary, and this is the single place where that is
  // enforced for evidence.
  if (record.state == EvidenceState::EVIDENCE_CURRENT) {
    record.state = EvidenceState::EVIDENCE_STALE;
    record.state_reason =
        "reloaded from durable state: authority must be re-established by a new publication";
  }
  index_flow(record.flow_id, record.id);
  by_id_.emplace(key, std::move(record));
  order_.push_back(key);
  stats_.records = by_id_.size();
  stats_.indexed_flows = by_flow_.size();
  return Status::success();
}

void EvidenceStore::index_flow(const FlowId& flow, const EvidenceId& id) {
  auto entry = by_flow_.find(flow);
  if (entry == by_flow_.end()) {
    std::deque<std::string> ids;
    ids.push_back(id.value());
    by_flow_.emplace(flow, std::move(ids));
    return;
  }
  std::deque<std::string>& ids = entry->second;
  while (!ids.empty() && ids.size() >= static_cast<std::size_t>(max_per_flow_)) {
    // The empty check is not defensive padding.  A configured per-flow bound of zero is legal, and
    // it means "index nothing"; without the check this pops from an empty deque, which is an
    // assertion failure in a checked standard library and undefined behaviour in a release one.
    ids.pop_front();
    stats_.evicted_per_flow += 1;
  }
  if (max_per_flow_ == 0) {
    // A zero bound means the flow index retains nothing for this flow.  The record is still stored
    // and still reachable by identity; it is simply not reachable from its flow, which is what a
    // zero per-flow bound asks for.
    return;
  }
  ids.push_back(id.value());
}

void EvidenceStore::unindex_flow(const FlowId& flow, const EvidenceId& id) {
  auto entry = by_flow_.find(flow);
  if (entry == by_flow_.end()) return;
  std::deque<std::string>& ids = entry->second;
  ids.erase(std::remove(ids.begin(), ids.end(), id.value()), ids.end());
  if (ids.empty()) {
    by_flow_.erase(entry);
  }
}

void EvidenceStore::evict_oldest() {
  while (!order_.empty() && by_id_.size() >= static_cast<std::size_t>(max_records_)) {
    const std::string key = order_.front();
    order_.pop_front();
    auto entry = by_id_.find(key);
    if (entry == by_id_.end()) continue;
    unindex_flow(entry->second.flow_id, entry->second.id);
    by_id_.erase(entry);
    stats_.evicted_records += 1;
  }
}

void EvidenceStore::clear() {
  by_id_.clear();
  by_flow_.clear();
  order_.clear();
  stats_ = EvidenceStoreStats{};
}

}  // namespace aifc
