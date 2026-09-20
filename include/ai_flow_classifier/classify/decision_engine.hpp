// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The deterministic decision engine.
//
// The engine is a pure function.  It receives a fully described request and returns
// a classification; it holds no state, takes no locks, performs no I/O and reads no
// clock.  Everything that could make two runs differ is either an input to the
// request or explicitly excluded from the decision digest.
//
// Precedence, in order:
//
//   1. currentness      a record that is not CURRENT cannot win, whatever it says
//   2. source rank      DECLARED_AUTHENTICATED > CONTRACT_DERIVED >
//                       COORDINATOR_CORRELATED > TOPOLOGY_CORRELATED > HEURISTIC
//   3. workload generation   a higher generation of the same workload outranks a
//                       lower one, because it is the same declaration, later
//   4. acceptance order a later accepted sequence outranks an earlier one
//   5. evidence id      the lexicographically smaller id wins, so the result never
//                       depends on hash iteration order
//
// Rules 4 and 5 exist so that the order is total.  A total order is what makes the
// answer reproducible and what makes "which record won" a question with one answer.
//
// Contradiction handling:
//
//   * two CURRENT records with the same rank that disagree are a contradiction:
//     both are cited, the winner is chosen by rules 4 and 5, and the configured
//     penalty is applied and reported;
//   * heuristic records never contradict: they are recorded as SUBORDINATE;
//   * a record that is not CURRENT never contradicts: it is recorded as STALE,
//     WITHDRAWN or REVOKED with the reason it lost.

#ifndef AI_FLOW_CLASSIFIER_CLASSIFY_DECISION_ENGINE_HPP
#define AI_FLOW_CLASSIFIER_CLASSIFY_DECISION_ENGINE_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

// The authority context in effect at decision time.  Supplied by the caller; the
// engine never derives it.
struct AuthorityContext {
  CoordinatorEpoch epoch;
  CoordinatorBootId coordinator_boot;
  Tick tick = kTickNone;
  // A monotonic counter that the classifier advances whenever a *volatile* authority fact changes:
  // a session is bound or ends, liveness expires, or the epoch advances.
  //
  // This exists because the decision memo keys on the evidence-set digest, and a record's own
  // content does not change when its publisher dies.  Without this, a memoised classification
  // computed while a publisher was live could be served after it died -- the memo would have
  // cached an answer whose inputs had changed underneath it.  Folding the sequence into the digest
  // makes a memo entry unreachable the moment liveness moves.
  Seq authority_sequence = 0;
  // Publisher incarnations that are live in this epoch.  A record whose publisher is
  // absent from this set cannot be CURRENT, whatever its recorded state says.
  std::unordered_set<std::string> live_publisher_boots;
  // Publisher incarnations that are known to the registry at all.  Used to phrase
  // the denial reason precisely.
  std::unordered_set<std::string> known_publishers;

  [[nodiscard]] static std::string boot_key(const PublisherId& publisher, PublisherBootId boot) {
    return publisher.value() + "@" + boot.to_string();
  }
  [[nodiscard]] bool is_live(const EvidenceRecord& record) const {
    return live_publisher_boots.find(boot_key(record.publisher, record.publisher_boot)) !=
           live_publisher_boots.end();
  }
  [[nodiscard]] bool is_known(const EvidenceRecord& record) const {
    return known_publishers.find(record.publisher.value()) != known_publishers.end();
  }
};

struct DecisionInput {
  // The flow incarnation being classified.  Required.
  FlowRecord flow;
  // Evidence records about this flow.  The engine re-checks every one of them; it
  // does not assume the caller filtered anything.
  std::vector<EvidenceRecord> evidence;
  // Active contracts, in canonical order.  Contract-derived evidence is synthesised
  // from these rather than stored, so a contract change cannot leave a stale derived
  // record behind.
  std::vector<WorkloadContract> active_contracts;
  // Workload records, used to fence contract-derived evidence by generation and to
  // name the workload in the explanation.
  std::vector<WorkloadRecord> workloads;
  AuthorityContext authority;
  ClassifierPolicy policy;
  // True when an explicit revocation exists for this exact flow generation.  A
  // revoked generation is reported as REVOKED even if evidence remains.
  bool generation_revoked = false;
  // Reason text for the revocation, when generation_revoked is true.
  std::string revocation_reason;
};

// Canonical digest of everything a decision depends on: the flow generation, the policy
// generation, the authority sequence, the coordinator epoch and boot, the tick, every record's
// content digest and freshness deadline, and the contracts that shaped the answer.
//
// Two runs with equal digests must produce equal decisions -- that is the property the memo relies
// on, and it is why the volatile facts and the tick are in here rather than being assumed constant.
[[nodiscard]] Digest256 compute_evidence_set_digest(const DecisionInput& input);

class DecisionEngine {
 public:
  DecisionEngine() = default;

  [[nodiscard]] Classification decide(const DecisionInput& input) const;

  // Exposed for explanations and for the property tests, which assert the invariants
  // directly rather than through the rendered text.
  [[nodiscard]] static std::string render_explanation(const Classification& classification,
                                                     const DecisionInput& input);
};

// Orders two evidence records by the total order described at the top of this file.
// Returns true when left outranks right.  Exposed so that property tests can assert
// the order is total and antisymmetric over generated inputs.
[[nodiscard]] bool evidence_outranks(const EvidenceRecord& left, const EvidenceRecord& right);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_CLASSIFY_DECISION_ENGINE_HPP
