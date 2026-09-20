// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Evidence store.
//
// The store keeps records in a bounded ring and maintains two indexes:
//
//   id index       evidence id -> record
//   flow index     flow id -> bounded list of evidence ids
//
// Classification reads through the flow index, so classifying one flow is
// proportional to the evidence about that flow, not to the size of the store.  The
// store refuses to grow without bound and reports every eviction it performs.

#ifndef AI_FLOW_CLASSIFIER_STORE_EVIDENCE_STORE_HPP
#define AI_FLOW_CLASSIFIER_STORE_EVIDENCE_STORE_HPP

#include <ostream>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

struct EvidenceStoreStats {
  std::uint64_t accepted = 0;
  std::uint64_t rejected = 0;
  std::uint64_t evicted_records = 0;
  std::uint64_t evicted_per_flow = 0;
  std::uint64_t withdrawn = 0;
  std::uint64_t superseded = 0;
  std::uint64_t stale_transitions = 0;
  std::uint64_t revalidation_transitions = 0;
  std::uint64_t capacity_rejections = 0;
  std::size_t records = 0;
  std::size_t indexed_flows = 0;
};

class EvidenceStore {
 public:
  EvidenceStore(std::uint32_t max_records, std::uint32_t max_per_flow,
                std::uint32_t max_flow_index)
      : max_records_(max_records),
        max_per_flow_(max_per_flow),
        max_flow_index_(max_flow_index) {}

  // Inserts a record that has already passed authority checks.  The store does not
  // decide authority; it enforces structure and bounds.  A record whose id already
  // exists with different content is DUPLICATE_IDENTITY, because silently replacing
  // an accepted record would make an earlier acknowledgement a lie.
  Status insert(EvidenceRecord record);

  [[nodiscard]] Result<EvidenceRecord> find(const EvidenceId& id) const;

  // Evidence ids for a flow, in canonical acceptance order (ascending seq).  Bounded
  // by max_evidence_per_flow.  An unknown flow returns an empty vector with ok().
  [[nodiscard]] Result<std::vector<EvidenceId>> evidence_for_flow(const FlowId& id) const;

  // Withdraws a record by setting its state.  The record is retained so that an
  // explanation can show what used to be believed.
  Status set_state(const EvidenceId& id, EvidenceState state, std::string reason, Tick tick);

  // Marks every record that is not already stale as stale because its publisher
  // boot, epoch or generation no longer holds.  Returns how many changed.
  std::uint32_t mark_stale_by_predicate(
      const std::function<bool(const EvidenceRecord&)>& predicate, std::string reason, Tick tick);

  // Marks every record accepted in an epoch other than the supplied one as
  // REVALIDATION_REQUIRED-stale.  Called on coordinator epoch advance.
  std::uint32_t mark_epoch_stale(CoordinatorEpoch current_epoch, Tick tick);

  [[nodiscard]] std::vector<EvidenceRecord> snapshot_records() const;
  Status restore_record(EvidenceRecord record);

  void clear();
  [[nodiscard]] std::size_t size() const noexcept { return by_id_.size(); }
  [[nodiscard]] std::uint32_t capacity() const noexcept { return max_records_; }
  [[nodiscard]] const EvidenceStoreStats& stats() const noexcept { return stats_; }

 private:
  void evict_oldest();
  void index_flow(const FlowId& flow, const EvidenceId& id);
  void unindex_flow(const FlowId& flow, const EvidenceId& id);

  std::unordered_map<std::string, EvidenceRecord> by_id_;
  std::unordered_map<Id128, std::deque<std::string>> by_flow_;
  std::deque<std::string> order_;
  std::uint32_t max_records_ = 0;
  std::uint32_t max_per_flow_ = 0;
  std::uint32_t max_flow_index_ = 0;
  EvidenceStoreStats stats_{};
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_STORE_EVIDENCE_STORE_HPP
