// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Classification history, revocation records, supersession records and the
// decision memo.
//
// Two ideas are kept separate on purpose:
//
//   * history is authoritative: the sequence of classifications actually produced,
//     each bound to a flow generation and a policy generation, plus the explicit
//     revocation and supersession records that explain why an old decision stopped
//     counting;
//   * the memo is not authoritative: it is a bounded cache keyed by the exact inputs of a
//     decision, and a miss simply means the engine recomputes.  A memo entry whose inputs have
//     changed can never be returned, because the key includes everything the answer depends on --
//     see DecisionKey.  What that set is, and why the tick, the authority sequence, the epoch and
//     the boot incarnation are in it, is documented in classify/decision_engine.hpp where the digest
//     is computed; this header only stores the result.

#ifndef AI_FLOW_CLASSIFIER_STORE_CLASSIFICATION_INDEX_HPP
#define AI_FLOW_CLASSIFIER_STORE_CLASSIFICATION_INDEX_HPP

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

// The exact inputs of a decision.  Two decisions with equal keys are the same decision, which is
// what makes the memo sound.
//
// `evidence_digest` is not just the evidence: it is the canonical digest of everything the answer
// depends on, including the decision tick, the authority sequence, the coordinator epoch and boot.
// The name is historical; the content is "the whole input".  A key that omitted the tick allowed a
// decision computed while a record was still fresh to be reused after it expired, which reported the
// past as the present; that defect is documented in docs/design.md.
struct DecisionKey {
  FlowId flow_id;
  FlowGeneration flow_generation;
  Digest256 evidence_digest;
  ClassifierPolicyGeneration policy_generation;
};

struct ClassificationIndexStats {
  std::uint64_t decisions_recorded = 0;
  std::uint64_t history_evictions = 0;
  std::uint64_t memo_hits = 0;
  std::uint64_t memo_misses = 0;
  std::uint64_t memo_evictions = 0;
  std::uint64_t revocations = 0;
  std::uint64_t supersessions = 0;
  std::uint64_t contradictions_recorded = 0;
  std::size_t flows_with_history = 0;
  std::size_t memo_entries = 0;
};

class ClassificationIndex {
 public:
  ClassificationIndex(std::uint32_t max_decisions_per_flow, std::uint32_t max_memo_entries,
                      std::uint32_t max_contradictions, std::uint32_t max_supersessions,
                      std::uint32_t max_revocations)
      : max_decisions_per_flow_(max_decisions_per_flow),
        max_memo_entries_(max_memo_entries),
        max_contradictions_(max_contradictions),
        max_supersessions_(max_supersessions),
        max_revocations_(max_revocations) {}

  // Records a decision in history.  Returns the previous current decision for the
  // same (flow, generation) when this one replaces it, so the caller can report a
  // supersession.
  Result<Classification> record(const Classification& classification);

  // The most recent decision for a (flow, generation).  A decision for another
  // generation is not returned: history is generation bound.
  [[nodiscard]] Result<Classification> latest(const FlowId& flow, FlowGeneration generation) const;

  [[nodiscard]] bool memo_lookup(const DecisionKey& key, Classification& out);
  void memo_store(const DecisionKey& key, const Classification& classification);

  Status record_contradiction(const FlowId& flow, const ClassificationContradiction& contradiction,
                              Tick tick);
  Status record_supersession(const SupersessionRecord& record);
  Status record_revocation(const RevocationRecord& record);

  [[nodiscard]] Result<std::vector<ClassificationContradiction>> contradictions_for(
      const FlowId& flow) const;
  [[nodiscard]] std::vector<RevocationRecord> revocations() const;
  [[nodiscard]] std::vector<SupersessionRecord> supersessions() const;

  // True when this exact flow generation has an explicit revocation recorded.  A
  // revoked generation must not be re-reported as current even if evidence remains.
  [[nodiscard]] bool is_revoked(const FlowId& flow, FlowGeneration generation) const;

  // Marks history entries for a generation as superseded by a generation advance.
  // Returns how many were affected.
  std::uint32_t supersede_generation(const FlowId& flow, FlowGeneration superseded_by, Tick tick);

  [[nodiscard]] std::vector<Classification> snapshot_classifications() const;
  Status restore_classification(const Classification& classification);
  [[nodiscard]] std::vector<RevocationRecord> snapshot_revocations() const { return revocations(); }
  [[nodiscard]] std::vector<SupersessionRecord> snapshot_supersessions() const {
    return supersessions();
  }
  Status restore_revocation(const RevocationRecord& record);
  Status restore_supersession(const SupersessionRecord& record);

  void clear();
  [[nodiscard]] std::uint32_t decision_capacity_per_flow() const noexcept {
    return max_decisions_per_flow_;
  }
  [[nodiscard]] std::size_t history_flows() const noexcept { return history_.size(); }
  [[nodiscard]] std::size_t memo_entries() const noexcept { return memo_.size(); }
  [[nodiscard]] const ClassificationIndexStats& stats() const noexcept { return stats_; }

 private:
  struct FlowHistory {
    std::deque<Classification> decisions;
    std::deque<ClassificationContradiction> contradictions;
  };

  std::unordered_map<Id128, FlowHistory> history_;
  std::unordered_map<std::string, Classification> memo_;
  std::deque<std::string> memo_order_;
  std::vector<RevocationRecord> revocations_;
  std::vector<SupersessionRecord> supersessions_;
  std::uint32_t max_decisions_per_flow_ = 0;
  std::uint32_t max_memo_entries_ = 0;
  std::uint32_t max_contradictions_ = 0;
  std::uint32_t max_supersessions_ = 0;
  std::uint32_t max_revocations_ = 0;
  ClassificationIndexStats stats_{};
};

// Canonical text key for a decision key, used by the memo map.
[[nodiscard]] std::string make_decision_key_text(const DecisionKey& key);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_STORE_CLASSIFICATION_INDEX_HPP
