// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The classifier facade.
//
// This type owns the policy, the registries, the stores and the sequence counters,
// and exposes the operations a coordinator or an embedding application needs:
// registration, evidence admission, classification, explanation, revocation and
// lifecycle.
//
// The single most important rule in this file is the split between the *payload* and
// the *envelope*.  A payload is untrusted text and numbers from a peer.  An envelope
// is what the authenticated session layer established.  The facade derives every
// authority decision from the envelope and only ever uses the payload for content.
// A peer can therefore never promote its own evidence: there is no field it can set
// that raises a source above the ceiling its session was admitted at.

#ifndef AI_FLOW_CLASSIFIER_CLASSIFY_CLASSIFIER_HPP
#define AI_FLOW_CLASSIFIER_CLASSIFY_CLASSIFIER_HPP

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "ai_flow_classifier/classify/decision_engine.hpp"
#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/publisher.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/foundation/log.hpp"
#include "ai_flow_classifier/store/classification_index.hpp"
#include "ai_flow_classifier/store/evidence_store.hpp"
#include "ai_flow_classifier/store/flow_registry.hpp"
#include "ai_flow_classifier/store/publisher_registry.hpp"
#include "ai_flow_classifier/store/workload_registry.hpp"

namespace aifc {

// What the authenticated session layer established about the sender.  Nothing in
// this structure is supplied by the peer's payload.
struct SessionEnvelope {
  PublisherId publisher;
  PublisherBootId publisher_boot;
  SessionId session;
  CoordinatorEpoch epoch;
  CoordinatorBootId coordinator_boot;
  // The strongest evidence source this session may assert.  Chosen by the
  // coordinator at admission time.
  EvidenceSource max_source = EvidenceSource::HEURISTIC;
  Tick received_tick = kTickNone;
};

// Untrusted content from a peer.  Every field is validated; none is authority.
struct EvidencePayload {
  WorkloadId workload;
  WorkloadGeneration workload_generation;
  ContractId contract;
  FlowKey flow_key;
  FlowGeneration flow_generation = FlowGeneration{0};
  EvidenceGeneration evidence_generation;
  SemanticClass semantic = SemanticClass::UNKNOWN;
  // The source the peer *claims*.  Always clamped to the envelope ceiling.
  EvidenceSource claimed_source = EvidenceSource::HEURISTIC;
  std::uint64_t freshness_window = 0;
  EvidenceMetadata metadata;
};

struct EvidenceSubmissionOutcome {
  EvidenceRecord record;
  bool accepted = false;
  // True when this submission replaced an older generation of the same topic from
  // the same publisher.
  bool superseded_previous = false;
  EvidenceId superseded_id;
  // True when admitting the evidence required a new flow generation, which fenced
  // derived classifications for the previous generation.
  bool fenced_flow_generation = false;
  FlowGeneration previous_flow_generation;
  // The source actually recorded, after clamping.  Reported so that a caller can see
  // that its claim was reduced.
  EvidenceSource effective_source = EvidenceSource::UNKNOWN;
  // Per-invocation log of admission warnings that were not fatal.
  std::vector<std::string> notes;
};

struct ClassificationQuery {
  FlowKey flow_key;
  FlowGeneration flow_generation = FlowGeneration{0};
  bool explain = false;
  // A decision is only returned for the generation asked about.  Asking without a
  // generation means "the current incarnation", which is reported explicitly.
  bool accept_current_generation = true;
};

struct ClassificationResult {
  Classification classification;
  std::string explanation;
  // True when the answer came from the memo rather than from a fresh evaluation.
  // Reported because it is a real property of the answer that a caller may care
  // about, and because the test suite asserts that a memo hit and a miss agree.
  bool memo_hit = false;
  // True when the classification is a historical statement about a generation that
  // is no longer current.
  bool historical = false;
};

struct ClassifierCounters {
  std::uint64_t flows_registered = 0;
  std::uint64_t evidence_accepted = 0;
  std::uint64_t evidence_refused = 0;
  std::uint64_t classifications = 0;
  std::uint64_t batch_requests = 0;
  std::uint64_t batch_keys = 0;
  std::uint64_t revocations = 0;
  std::uint64_t supersessions = 0;
  std::uint64_t contradictions = 0;
  std::uint64_t policy_updates = 0;
  std::uint64_t generation_fences = 0;
};

struct ClassifierOptions {
  ClassifierPolicy policy = ClassifierPolicy::initial();
  Logger logger;
  CoordinatorEpoch epoch{1};
  CoordinatorBootId coordinator_boot{1};
  // The time source every freshness and liveness decision is expressed in.
  //
  // The engine never reads a clock itself: it is given a tick, so that a decision is reproducible
  // and so that a test can walk to an exact freshness boundary instead of sleeping past it.  This
  // pointer is the single place the process supplies that tick.  It defaults to a monotonic
  // source, which means freshness genuinely expires in a long-running process; a test substitutes
  // a manual source and gets exact control.
  const TickSource* clock = nullptr;
};

class Classifier {
 public:
  explicit Classifier(ClassifierOptions options);

  // --- lifecycle -----------------------------------------------------------
  // Clears every volatile decision, memo and session and advances the coordinator
  // epoch, which invalidates every record accepted before the call.  Returns the new
  // epoch.  Called on coordinator restart.
  Result<CoordinatorEpoch> advance_epoch(CoordinatorBootId boot);

  [[nodiscard]] CoordinatorEpoch epoch() const;
  [[nodiscard]] CoordinatorBootId coordinator_boot() const;

  // --- identity -----------------------------------------------------------
  // The policy in force, by value.  It is returned by value on purpose: the classifier may replace
  // its policy at any moment, and handing out a reference to state that is protected by a mutex
  // would make every caller responsible for a lock it cannot take.
  [[nodiscard]] ClassifierPolicy policy() const;
  [[nodiscard]] Digest256 policy_digest() const;
  Result<ClassifierPolicyGeneration> set_policy(ClassifierPolicy policy);

  // --- publishers ---------------------------------------------------------
  Result<PublisherRegistration> register_publisher(const PublisherId& id, PublisherBootId boot,
                                                   EvidenceSource max_source,
                                                   const SessionId& session, std::string description);
  // Ends one session of a publisher incarnation, or every session of it when the session identity
  // is empty.  Evidence published through an ended session stops being current; evidence published
  // through another still-open session of the same incarnation does not.
  Status end_publisher_session(const PublisherId& id, PublisherBootId boot,
                               const SessionId& session = SessionId{});
  // Contact with a live session, which is the only thing that refreshes liveness.
  // A heartbeat is not evidence and does not create authority; it merely prevents an
  // existing session from going idle.
  Status heartbeat(const PublisherId& id, PublisherBootId boot);
  std::uint32_t expire_publisher_liveness();
  [[nodiscard]] Result<PublisherRegistration> find_publisher(const PublisherId& id) const;

  // --- workloads and contracts --------------------------------------------
  Result<WorkloadRecord> declare_workload(const WorkloadId& id, const PublisherId& owner,
                                          WorkloadGeneration generation, std::string description);
  Result<WorkloadContract> propose_contract(WorkloadContract contract);
  Result<WorkloadContract> activate_contract(const ContractId& id, const PublisherId& caller);
  Status retire_contract(const ContractId& id, const PublisherId& caller);
  Status retire_workload(const WorkloadId& id, WorkloadGeneration generation);
  [[nodiscard]] Result<WorkloadRecord> find_workload(const WorkloadId& id) const;
  [[nodiscard]] Result<WorkloadContract> find_contract(const ContractId& id) const;

  // --- flows --------------------------------------------------------------
  Result<FlowRegistration> register_flow(const FlowKey& key, FlowGeneration generation,
                                         const SessionId& session);
  [[nodiscard]] Result<FlowRecord> find_flow(const FlowKey& key) const;
  [[nodiscard]] Result<FlowRecord> find_flow_generation(const FlowId& id,
                                                        FlowGeneration generation) const;

  // --- evidence -----------------------------------------------------------
  Result<EvidenceSubmissionOutcome> submit_evidence(const SessionEnvelope& envelope,
                                                    const EvidencePayload& payload);
  Status withdraw_evidence(const SessionEnvelope& envelope, const EvidenceId& id,
                           std::string reason);
  [[nodiscard]] Result<EvidenceRecord> find_evidence(const EvidenceId& id) const;
  [[nodiscard]] Result<std::vector<EvidenceId>> evidence_for_flow(const FlowId& id) const;

  // --- classification -----------------------------------------------------
  Result<ClassificationResult> classify(const ClassificationQuery& query);

  struct BatchOutcome {
    std::vector<ClassificationResult> results;
    // Index-aligned status: a key that could not be classified has a non-OK status
    // here and an empty result.  The batch as a whole succeeds, because one unknown
    // flow in a batch of a thousand is not a failure of the other 999.
    std::vector<Status> statuses;
    std::uint32_t succeeded = 0;
    std::uint32_t failed = 0;
  };
  Result<BatchOutcome> classify_batch(const std::vector<ClassificationQuery>& queries);

  // --- revocation and supersession ----------------------------------------
  Status revoke_generation(const SessionEnvelope& envelope, const FlowId& flow,
                           FlowGeneration generation, std::string reason);
  [[nodiscard]] Result<std::vector<ClassificationContradiction>> contradictions_for(
      const FlowId& flow) const;
  [[nodiscard]] std::vector<RevocationRecord> revocations() const;
  [[nodiscard]] std::vector<SupersessionRecord> supersessions() const;

  // --- introspection ------------------------------------------------------
  struct Stats {
    ClassifierCounters counters;
    FlowRegistryStats flows;
    PublisherRegistryStats publishers;
    WorkloadRegistryStats workloads;
    EvidenceStoreStats evidence;
    ClassificationIndexStats classifications;
    ClassifierPolicyGeneration policy_generation;
    Digest256 policy_digest;
    CoordinatorEpoch epoch;
    CoordinatorBootId coordinator_boot;
    std::uint64_t next_sequence = 0;
    std::size_t memo_entries = 0;
  };
  [[nodiscard]] Stats stats() const;

  // Renders the exact evidence behind one classification, including the records that
  // lost and why.
  [[nodiscard]] Result<std::string> explain(const FlowKey& key, FlowGeneration generation);

  // --- persistence --------------------------------------------------------
  // Everything durable about the classifier, copied under one acquisition of the classifier lock.
  //
  // This exists instead of exposing the stores, because exposing them let the snapshot path walk
  // five containers while other threads mutated them under a mutex it never took.  That is a data
  // race with no diagnostic until it corrupts the heap, and no amount of care at the call site can
  // fix it: the lock is private, so the only correct design is a single method that takes it.
  struct DurableState {
    ClassifierPolicy policy;
    CoordinatorEpoch epoch;
    CoordinatorBootId coordinator_boot;
    std::uint64_t sequence_high_water = 0;
    std::vector<PublisherRecord> publishers;
    std::vector<WorkloadRecord> workloads;
    std::vector<WorkloadContract> contracts;
    std::vector<FlowRecord> flows;
    std::vector<EvidenceRecord> evidence;
    std::vector<Classification> classifications;
    std::vector<RevocationRecord> revocations;
    std::vector<SupersessionRecord> supersessions;
  };

  [[nodiscard]] DurableState durable_state() const;

  // The most recent recorded decision for one (flow, generation), copied under the lock.  This is
  // the queryable form of history: an audit asks about one incarnation, not about every map the
  // classifier owns.
  [[nodiscard]] Result<Classification> recorded_decision(const FlowId& flow,
                                                         FlowGeneration generation) const;

  // Every publisher registration, copied under the lock.  This is the volatile half of the
  // publisher state: it is what a caller needs to reason about liveness, and it is deliberately not
  // part of the durable image.
  [[nodiscard]] std::vector<PublisherRegistration> publisher_registrations() const;

  // Restores durable state.  Crucially, this does *not* restore authority: every
  // restored publisher session is non-live and every restored evidence record is
  // non-current, so a restart cannot resurrect liveness or freshness.
  //
  // The durable incarnation counters are a different matter and are observed, never
  // lowered: an epoch or a sequence number that a previous incarnation already issued must
  // not be issued again.  A restart that reused an epoch would let a pre-restart session
  // envelope pass the epoch fence, and a restart that reused a sequence number would make
  // "monotonic, never reused" false.  Both arguments have defaults so that a caller which
  // has no durable image to offer keeps the previous behaviour exactly.
  Status restore(CoordinatorBootId boot, std::vector<PublisherRecord> publishers,
                 std::vector<WorkloadRecord> workloads, std::vector<WorkloadContract> contracts,
                 std::vector<FlowRecord> flows, std::vector<EvidenceRecord> evidence,
                 std::vector<Classification> classifications,
                 std::vector<RevocationRecord> revocations,
                 std::vector<SupersessionRecord> supersessions,
                 CoordinatorEpoch persisted_epoch = CoordinatorEpoch{},
                 std::uint64_t persisted_sequence = 0);

  [[nodiscard]] std::uint64_t next_sequence() const;

 private:
  [[nodiscard]] AuthorityContext build_authority_context(Tick tick) const;
  Result<EvidenceRecord> admit_evidence(const SessionEnvelope& envelope,
                                        const EvidencePayload& payload,
                                        EvidenceSubmissionOutcome& outcome, Tick tick);
  Status refresh_flow(const FlowKey& key, FlowGeneration requested, const SessionId& session,
                      Tick tick, FlowRegistration& registration);
  void mark_flow_generation_stale(const FlowId& flow, FlowGeneration superseded_by, Tick tick);

  [[nodiscard]] Tick now() const noexcept { return clock_->now(); }

  const TickSource* clock_ = nullptr;
  mutable std::mutex mutex_;
  ClassifierPolicy policy_;
  Digest256 policy_digest_;
  Logger logger_;
  FlowRegistry flows_;
  PublisherRegistry publishers_;
  WorkloadRegistry workloads_;
  EvidenceStore evidence_;
  ClassificationIndex decisions_;
  DecisionEngine engine_;
  CoordinatorEpoch epoch_;
  CoordinatorBootId coordinator_boot_;
  Counter sequence_;
  // Advanced by every change to a volatile authority fact.  See AuthorityContext::authority_sequence.
  Seq authority_sequence_ = 1;
  ClassifierCounters counters_{};
};

// Builds the payload-free envelope a coordinator would construct for a peer, used by
// the CLI and by the tests.  Kept here so that every caller derives the envelope the
// same way.
[[nodiscard]] SessionEnvelope make_session_envelope(const PublisherRegistration& registration,
                                                    Tick tick);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_CLASSIFY_CLASSIFIER_HPP
