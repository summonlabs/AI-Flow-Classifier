// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Unit proof surface: the decision engine.
//
// DecisionEngine::decide is the pure-function surface of the runtime -- no clock, no I/O, no
// state -- so this is the right place to pin precedence, contradiction handling and the
// publishable threshold exactly.  Every case hands the engine a hand-built DecisionInput and
// asserts the returned Classification field by field.
//
// Capability labels: REAL means the shipped engine produced the answer; SYNTHETIC means the
// evidence set was invented here.  The one randomized case prints its reproduction seed in
// every failure message.

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "test_framework.hpp"

#include "synthetic.hpp"

namespace {

[[nodiscard]] bool contains(const std::string& haystack, std::string_view needle) {
  return haystack.find(needle) != std::string::npos;
}

// A live publisher incarnation, in the form the authority context stores it.
[[nodiscard]] std::string boot_key(const char* publisher, std::uint64_t boot) {
  return std::string(publisher) + "@" + std::to_string(boot);
}

struct Rig {
  aifc::DecisionEngine engine;
  aifc::ClassifierPolicy policy;
  aifc::AuthorityContext authority;
  aifc::FlowRecord flow;
  std::vector<aifc::EvidenceRecord> evidence;
  std::vector<aifc::WorkloadContract> contracts;
  std::vector<aifc::WorkloadRecord> workloads;

  Rig() {
    policy = aifc::ClassifierPolicy::initial();
    flow.key = aifc_test::synthetic_flow_key(0U);
    flow.id = aifc::derive_flow_id(flow.key);
    flow.generation = aifc::FlowGeneration{1};
    authority.epoch = aifc::CoordinatorEpoch{2};
    authority.coordinator_boot = aifc::CoordinatorBootId{5};
    authority.tick = aifc::kTickNone;
    make_live("publisher-0", 1);
  }

  void make_live(const char* publisher, std::uint64_t boot) {
    authority.known_publishers.insert(publisher);
    authority.live_publisher_boots.insert(boot_key(publisher, boot));
  }

  void make_known_only(const char* publisher) { authority.known_publishers.insert(publisher); }

  [[nodiscard]] aifc::EvidenceRecord make_record(const char* id, aifc::SemanticClass semantic,
                                                 aifc::EvidenceSource source, aifc::Seq seq,
                                                 const char* publisher = "publisher-0",
                                                 std::uint64_t boot = 1) const {
    aifc::EvidenceRecord record;
    record.id = aifc::make_evidence_id(id);
    record.publisher = aifc::make_publisher_id(publisher);
    record.publisher_boot = aifc::PublisherBootId{boot};
    record.session = aifc::SessionId("session-0");
    record.accepted_epoch = authority.epoch;
    record.accepted_boot = authority.coordinator_boot;
    record.flow_id = flow.id;
    record.flow_generation = flow.generation;
    record.generation = aifc::EvidenceGeneration{seq};
    record.accepted_seq = seq;
    record.accepted_tick = 1;
    record.fresh_until = 4096;
    record.semantic = semantic;
    record.source = source;
    record.state = aifc::EvidenceState::EVIDENCE_CURRENT;
    record.confidence = aifc::source_confidence(source);
    record.metadata.topic = std::string("topic.") + id;
    record.content_digest = aifc::compute_evidence_digest(record);
    return record;
  }

  [[nodiscard]] aifc::DecisionInput input() const {
    aifc::DecisionInput in;
    in.flow = flow;
    in.evidence = evidence;
    in.active_contracts = contracts;
    in.workloads = workloads;
    in.authority = authority;
    in.policy = policy;
    return in;
  }

  [[nodiscard]] aifc::Classification decide() const { return engine.decide(input()); }
};

[[nodiscard]] const aifc::EvidenceCitation* citation_for(const aifc::Classification& classification,
                                                         std::string_view id) {
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    if (citation.id.value() == id) return &citation;
  }
  return nullptr;
}

[[nodiscard]] std::size_t count_disposition(const aifc::Classification& classification,
                                            aifc::EvidenceDisposition disposition) {
  std::size_t count = 0;
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    if (citation.disposition == disposition) ++count;
  }
  return count;
}

}  // namespace

// ---------------------------------------------------------------------------
// Precedence
// ---------------------------------------------------------------------------

AIFC_TEST("decision_engine/precedence: source rank decides, in the documented order (REAL)") {
  Rig rig;
  // Heuristics must be permitted for the HEURISTIC rung to be represented at all; with the
  // global switch off the engine rejects such a record outright (a separate case below).
  rig.policy.allow_heuristic_evidence = true;

  const aifc::SemanticClass declared_class = aifc::SemanticClass::KV_STATE_TRANSFER;
  const aifc::SemanticClass contract_class = aifc::SemanticClass::MODEL_STATE_TRANSFER;
  const aifc::SemanticClass coordinator_class = aifc::SemanticClass::COLLECTIVE;
  const aifc::SemanticClass topology_class = aifc::SemanticClass::TELEMETRY;
  const aifc::SemanticClass heuristic_class = aifc::SemanticClass::SHUFFLE;

  rig.evidence = {
      rig.make_record("ev-0000000000000001", declared_class,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 5),
      rig.make_record("ev-0000000000000002", contract_class,
                      aifc::EvidenceSource::CONTRACT_DERIVED, 4),
      rig.make_record("ev-0000000000000003", coordinator_class,
                      aifc::EvidenceSource::COORDINATOR_CORRELATED, 3),
      rig.make_record("ev-0000000000000004", topology_class,
                      aifc::EvidenceSource::TOPOLOGY_CORRELATED, 2),
      rig.make_record("ev-0000000000000005", heuristic_class, aifc::EvidenceSource::HEURISTIC, 1),
  };

  // The total order the engine documents, checked pairwise through the exposed comparator first.
  struct Rung {
    aifc::EvidenceSource stronger;
    aifc::EvidenceSource weaker;
  };
  const Rung rungs[] = {
      {aifc::EvidenceSource::DECLARED_AUTHENTICATED, aifc::EvidenceSource::CONTRACT_DERIVED},
      {aifc::EvidenceSource::CONTRACT_DERIVED, aifc::EvidenceSource::COORDINATOR_CORRELATED},
      {aifc::EvidenceSource::COORDINATOR_CORRELATED, aifc::EvidenceSource::TOPOLOGY_CORRELATED},
      {aifc::EvidenceSource::TOPOLOGY_CORRELATED, aifc::EvidenceSource::HEURISTIC},
      {aifc::EvidenceSource::DECLARED_AUTHENTICATED, aifc::EvidenceSource::HEURISTIC},
  };
  for (const Rung& rung : rungs) {
    const aifc::EvidenceRecord strong = rig.make_record("ev-strong", declared_class, rung.stronger, 1);
    const aifc::EvidenceRecord weak = rig.make_record("ev-weak", contract_class, rung.weaker, 2);
    AIFC_CHECK_MSG(aifc::evidence_outranks(strong, weak),
                   "the engine does not report " << aifc::to_string(rung.stronger)
                                                 << " as outranking "
                                                 << aifc::to_string(rung.weaker));
    AIFC_CHECK_MSG(!aifc::evidence_outranks(weak, strong),
                   "evidence_outranks is not antisymmetric for " << aifc::to_string(rung.stronger)
                                                                 << " and "
                                                                 << aifc::to_string(rung.weaker));
  }

  // With all five present the declaration wins, whatever order they arrived in.
  const aifc::Classification all = rig.decide();
  AIFC_CHECK(all.semantic == declared_class);
  AIFC_CHECK(all.state == aifc::ClassificationState::CONTRADICTED);
  AIFC_CHECK(all.selected_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  AIFC_CHECK_EQ(all.selected_evidence.value(), std::string("ev-0000000000000001"));
  const aifc::EvidenceCitation* declared_citation =
      citation_for(all, "ev-0000000000000001");
  AIFC_CHECK(declared_citation != nullptr);
  if (declared_citation != nullptr) {
    AIFC_CHECK(declared_citation->disposition == aifc::EvidenceDisposition::SELECTED);
  }
  for (const char* weaker : {"ev-0000000000000002", "ev-0000000000000003",
                             "ev-0000000000000004"}) {
    const aifc::EvidenceCitation* citation = citation_for(all, weaker);
    AIFC_CHECK(citation != nullptr);
    if (citation != nullptr) {
      AIFC_CHECK_MSG(citation->disposition == aifc::EvidenceDisposition::CONTRADICTING,
                     "citation " << weaker << " has disposition "
                                 << aifc::to_string(citation->disposition)
                                 << " but should be CONTRADICTING");
    }
  }
  const aifc::EvidenceCitation* heuristic_citation = citation_for(all, "ev-0000000000000005");
  AIFC_CHECK(heuristic_citation != nullptr);
  if (heuristic_citation != nullptr) {
    AIFC_CHECK(heuristic_citation->disposition == aifc::EvidenceDisposition::SUBORDINATE);
  }

  // Removing the strongest rung at a time walks the answer down the documented order.
  struct Step {
    const char* removed;
    aifc::SemanticClass expected_class;
    aifc::EvidenceSource expected_source;
  };
  const Step steps[] = {
      {"ev-0000000000000001", contract_class, aifc::EvidenceSource::CONTRACT_DERIVED},
      {"ev-0000000000000002", coordinator_class, aifc::EvidenceSource::COORDINATOR_CORRELATED},
      {"ev-0000000000000003", topology_class, aifc::EvidenceSource::TOPOLOGY_CORRELATED},
  };
  for (const Step& step : steps) {
    std::vector<aifc::EvidenceRecord> remaining;
    for (const aifc::EvidenceRecord& record : rig.evidence) {
      if (record.id.value() != step.removed) remaining.push_back(record);
    }
    rig.evidence = remaining;
    const aifc::Classification answer = rig.decide();
    AIFC_CHECK_MSG(answer.selected_source == step.expected_source,
                   "after removing " << step.removed << " the winner is "
                                     << aifc::to_string(answer.selected_source) << " but "
                                     << aifc::to_string(step.expected_source) << " was expected");
    AIFC_CHECK_MSG(answer.semantic == step.expected_class,
                   "after removing " << step.removed << " the class is "
                                     << aifc::to_string(answer.semantic) << " but "
                                     << aifc::to_string(step.expected_class) << " was expected");
  }

  // Only the heuristic rung is left.  A guess is never sufficient on its own, so the answer is
  // UNKNOWN with INSUFFICIENT state rather than the guessed class.
  std::vector<aifc::EvidenceRecord> heuristic_only;
  for (const aifc::EvidenceRecord& record : rig.evidence) {
    if (record.source == aifc::EvidenceSource::HEURISTIC) heuristic_only.push_back(record);
  }
  rig.evidence = heuristic_only;
  const aifc::Classification lone_guess = rig.decide();
  AIFC_CHECK_MSG(lone_guess.semantic == aifc::SemanticClass::UNKNOWN,
                 "a lone heuristic record must not select a class, but it selected "
                     << aifc::to_string(lone_guess.semantic));
  AIFC_CHECK(lone_guess.state == aifc::ClassificationState::INSUFFICIENT);
  AIFC_CHECK_EQ(lone_guess.confidence.basis_points(), 0U);
  AIFC_CHECK(lone_guess.selected_evidence.empty());
}

AIFC_TEST("decision_engine/precedence: a later accepted sequence wins at equal rank (REAL)") {
  Rig rig;
  // Two current records of the same rank and different classes: the later accepted sequence
  // outranks the earlier one, so the answer does not depend on the order they were handed over.
  const aifc::EvidenceRecord early = rig.make_record("ev-0000000000000001",
                                                     aifc::SemanticClass::COLLECTIVE,
                                                     aifc::EvidenceSource::DECLARED_AUTHENTICATED, 3);
  const aifc::EvidenceRecord late = rig.make_record("ev-0000000000000002",
                                                    aifc::SemanticClass::TELEMETRY,
                                                    aifc::EvidenceSource::DECLARED_AUTHENTICATED, 9);
  rig.evidence = {early, late};
  const aifc::Classification forward = rig.decide();
  AIFC_CHECK(forward.semantic == aifc::SemanticClass::TELEMETRY);
  AIFC_CHECK_EQ(forward.selected_evidence.value(), std::string("ev-0000000000000002"));
  AIFC_CHECK(forward.state == aifc::ClassificationState::CONTRADICTED);

  rig.evidence = {late, early};
  const aifc::Classification reversed = rig.decide();
  AIFC_CHECK_MSG(reversed.semantic == forward.semantic,
                 "the winner changed when the same two records were handed over in the other "
                 "order: " << aifc::to_string(reversed.semantic) << " vs "
                           << aifc::to_string(forward.semantic));
  AIFC_CHECK_EQ(reversed.selected_evidence.value(), forward.selected_evidence.value());

  // Same rank and same sequence: the lexicographically smaller identity wins, so the order is
  // total and the answer is still unique.
  const aifc::EvidenceRecord smaller = rig.make_record("ev-0000000000000001",
                                                       aifc::SemanticClass::CHECKPOINT,
                                                       aifc::EvidenceSource::DECLARED_AUTHENTICATED, 7);
  const aifc::EvidenceRecord larger = rig.make_record("ev-0000000000000009",
                                                      aifc::SemanticClass::STORAGE_DATA,
                                                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 7);
  rig.evidence = {larger, smaller};
  const aifc::Classification tie = rig.decide();
  AIFC_CHECK_MSG(tie.semantic == aifc::SemanticClass::CHECKPOINT,
                 "with equal rank and sequence the smaller evidence identity must win, but the "
                 "winner was "
                     << aifc::to_string(tie.semantic));
  AIFC_CHECK_EQ(tie.selected_evidence.value(), std::string("ev-0000000000000001"));
}

// ---------------------------------------------------------------------------
// Currentness
// ---------------------------------------------------------------------------

AIFC_TEST("decision_engine/currentness: a stale record never wins (REAL)") {
  Rig rig;
  aifc::EvidenceRecord stale = rig.make_record("ev-0000000000000001",
                                               aifc::SemanticClass::KV_STATE_TRANSFER,
                                               aifc::EvidenceSource::DECLARED_AUTHENTICATED, 9);
  stale.state = aifc::EvidenceState::EVIDENCE_STALE;
  stale.state_reason = "superseded by a newer incarnation";
  const aifc::EvidenceRecord current =
      rig.make_record("ev-0000000000000002", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  rig.evidence = {stale, current};

  const aifc::Classification answer = rig.decide();
  AIFC_CHECK_MSG(answer.semantic == aifc::SemanticClass::COLLECTIVE,
                 "a stale record with a later sequence must not win, but the class was "
                     << aifc::to_string(answer.semantic));
  AIFC_CHECK_EQ(answer.selected_evidence.value(), std::string("ev-0000000000000002"));
  AIFC_CHECK(answer.state == aifc::ClassificationState::CURRENT);
  const aifc::EvidenceCitation* loser = citation_for(answer, "ev-0000000000000001");
  AIFC_CHECK(loser != nullptr);
  if (loser != nullptr) {
    AIFC_CHECK(loser->disposition == aifc::EvidenceDisposition::STALE);
    AIFC_CHECK_EQ(loser->detail, std::string("superseded by a newer incarnation"));
  }

  // Only a stale record is left: the answer is a historical statement, not a current class.
  rig.evidence = {stale};
  const aifc::Classification only_stale = rig.decide();
  AIFC_CHECK(only_stale.state == aifc::ClassificationState::STALE);
  AIFC_CHECK_MSG(only_stale.semantic == aifc::SemanticClass::UNKNOWN,
                 "a stale record must not produce a class, but it produced "
                     << aifc::to_string(only_stale.semantic));
  AIFC_CHECK_EQ(only_stale.confidence.basis_points(), 0U);
  AIFC_CHECK(only_stale.selected_evidence.empty());
}

AIFC_TEST("decision_engine/currentness: a record whose publisher is not live is STALE (REAL)") {
  Rig rig;
  rig.make_known_only("publisher-1");
  const aifc::EvidenceRecord orphan =
      rig.make_record("ev-0000000000000001", aifc::SemanticClass::KV_STATE_TRANSFER,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1, "publisher-1", 2);
  rig.evidence = {orphan};

  const aifc::Classification answer = rig.decide();
  AIFC_CHECK(answer.state == aifc::ClassificationState::STALE);
  AIFC_CHECK(answer.semantic == aifc::SemanticClass::UNKNOWN);
  const aifc::EvidenceCitation* citation = citation_for(answer, "ev-0000000000000001");
  AIFC_CHECK(citation != nullptr);
  if (citation != nullptr) {
    AIFC_CHECK(citation->state == aifc::EvidenceState::EVIDENCE_STALE);
    AIFC_CHECK(citation->disposition == aifc::EvidenceDisposition::STALE);
    AIFC_CHECK_MSG(contains(citation->detail, "publisher-1"),
                   "the reason must name the publisher, got: " << citation->detail);
    AIFC_CHECK_MSG(contains(citation->detail, "boot 2"),
                   "the reason must name the boot incarnation, got: " << citation->detail);
    AIFC_CHECK_MSG(contains(citation->detail, "not live"),
                   "the reason must say the incarnation is not live, got: " << citation->detail);
  }

  // A publisher that is not registered at all is reported differently: the denial reason must be
  // accurate rather than merely present.
  rig.authority.known_publishers.clear();
  const aifc::Classification unknown = rig.decide();
  AIFC_CHECK(unknown.state == aifc::ClassificationState::STALE);
  const aifc::EvidenceCitation* unknown_citation = citation_for(unknown, "ev-0000000000000001");
  AIFC_CHECK(unknown_citation != nullptr);
  if (unknown_citation != nullptr) {
    AIFC_CHECK_MSG(contains(unknown_citation->detail, "no longer registered"),
                   "an unregistered publisher must be reported as such, got: "
                       << unknown_citation->detail);
  }

  // A contract-derived record is not an observation made by a session, so it does not depend on
  // publisher liveness; its currentness is governed by the contract.
  const aifc::EvidenceRecord derived =
      rig.make_record("ev-0000000000000002", aifc::SemanticClass::MODEL_STATE_TRANSFER,
                      aifc::EvidenceSource::CONTRACT_DERIVED, 2, "publisher-1", 2);
  rig.evidence = {derived};
  const aifc::Classification contract_answer = rig.decide();
  AIFC_CHECK_MSG(contract_answer.semantic == aifc::SemanticClass::MODEL_STATE_TRANSFER,
                 "a contract-derived record must not depend on session liveness, but the answer "
                 "was "
                     << aifc::to_string(contract_answer.semantic) << " in state "
                     << aifc::to_string(contract_answer.state));
  AIFC_CHECK(contract_answer.state == aifc::ClassificationState::CURRENT);

  // The same is true of a heuristic record, which never had authority to lose.  Permitting
  // heuristics keeps it current; it is still subordinate.
  rig.policy.allow_heuristic_evidence = true;
  rig.evidence = {rig.make_record("ev-0000000000000003", aifc::SemanticClass::SHUFFLE,
                                  aifc::EvidenceSource::HEURISTIC, 3, "publisher-1", 2)};
  const aifc::Classification heuristic_answer = rig.decide();
  const aifc::EvidenceCitation* heuristic_citation =
      citation_for(heuristic_answer, "ev-0000000000000003");
  AIFC_CHECK(heuristic_citation != nullptr);
  if (heuristic_citation != nullptr) {
    AIFC_CHECK(heuristic_citation->state == aifc::EvidenceState::EVIDENCE_CURRENT);
    AIFC_CHECK(heuristic_citation->disposition == aifc::EvidenceDisposition::SUBORDINATE);
  }
}

AIFC_TEST("decision_engine/currentness: a record from another epoch is STALE (REAL)") {
  Rig rig;
  aifc::EvidenceRecord other_epoch =
      rig.make_record("ev-0000000000000001", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  other_epoch.accepted_epoch = aifc::CoordinatorEpoch{1};
  rig.authority.epoch = aifc::CoordinatorEpoch{2};
  rig.evidence = {other_epoch};

  const aifc::Classification answer = rig.decide();
  AIFC_CHECK(answer.state == aifc::ClassificationState::STALE);
  AIFC_CHECK(answer.semantic == aifc::SemanticClass::UNKNOWN);
  const aifc::EvidenceCitation* citation = citation_for(answer, "ev-0000000000000001");
  AIFC_CHECK(citation != nullptr);
  if (citation != nullptr) {
    AIFC_CHECK(citation->state == aifc::EvidenceState::EVIDENCE_STALE);
    AIFC_CHECK_MSG(contains(citation->detail, "epoch 1") &&
                       contains(citation->detail, "rather than 2"),
                   "the reason must name the epoch the record was accepted in and the current "
                   "one, got: "
                       << citation->detail);
  }

  // The same record accepted in the current epoch is current: the fencing value is the epoch.
  aifc::EvidenceRecord same_epoch = other_epoch;
  same_epoch.accepted_epoch = rig.authority.epoch;
  rig.evidence = {same_epoch};
  const aifc::Classification current = rig.decide();
  AIFC_CHECK_MSG(current.semantic == aifc::SemanticClass::COLLECTIVE,
                 "a record accepted in the current epoch must be current, but the answer was "
                     << aifc::to_string(current.semantic) << " in state "
                     << aifc::to_string(current.state));
  AIFC_CHECK(current.state == aifc::ClassificationState::CURRENT);

  // Observed behaviour, recorded here so a change is deliberate: the engine fences on the epoch,
  // not on the coordinator boot incarnation, and the boot never enters the decision.  The
  // classification reports both values, and neither participates in the decision digest.
  aifc::EvidenceRecord other_boot = same_epoch;
  other_boot.accepted_boot = aifc::CoordinatorBootId{99};
  other_boot.content_digest = aifc::compute_evidence_digest(other_boot);
  rig.evidence = {other_boot};
  const aifc::Classification boot_answer = rig.decide();
  AIFC_CHECK_MSG(boot_answer.state == aifc::ClassificationState::CURRENT,
                 "the coordinator boot incarnation is not an engine input; the record should "
                 "still be current, but the state was "
                     << aifc::to_string(boot_answer.state));
  AIFC_CHECK(boot_answer.coordinator_boot.value == rig.authority.coordinator_boot.value);
}

AIFC_TEST("decision_engine/currentness: a record past its freshness deadline is STALE (REAL)") {
  Rig rig;
  aifc::EvidenceRecord expiring =
      rig.make_record("ev-0000000000000001", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  expiring.fresh_until = 999;
  rig.evidence = {expiring};

  // Exactly at the deadline the record is still live; one tick past it, it is not.
  rig.authority.tick = 999;
  AIFC_CHECK_MSG(rig.decide().state == aifc::ClassificationState::CURRENT,
                 "a record is live up to and including its freshness deadline");
  rig.authority.tick = 1000;
  const aifc::Classification expired = rig.decide();
  AIFC_CHECK(expired.state == aifc::ClassificationState::STALE);
  AIFC_CHECK(expired.semantic == aifc::SemanticClass::UNKNOWN);
  const aifc::EvidenceCitation* citation = citation_for(expired, "ev-0000000000000001");
  AIFC_CHECK(citation != nullptr);
  if (citation != nullptr) {
    AIFC_CHECK(citation->state == aifc::EvidenceState::EVIDENCE_STALE);
    AIFC_CHECK_MSG(contains(citation->detail, "999"),
                   "the reason must name the deadline, got: " << citation->detail);
  }

  // A record with no deadline is not aged out by a tick, and a decision taken without a clock
  // does not apply freshness at all.  Neither is a licence to treat the record as fresh: the
  // liveness, generation and epoch rules still apply in full.
  aifc::EvidenceRecord no_deadline = expiring;
  no_deadline.fresh_until = aifc::kTickNone;
  no_deadline.content_digest = aifc::compute_evidence_digest(no_deadline);
  rig.evidence = {no_deadline};
  rig.authority.tick = 100000;
  AIFC_CHECK(rig.decide().state == aifc::ClassificationState::CURRENT);
  rig.authority.tick = aifc::kTickNone;
  AIFC_CHECK(rig.decide().state == aifc::ClassificationState::CURRENT);

  // A stale-but-present record is still cited, so an operator can see what used to be believed.
  rig.evidence = {expiring};
  rig.authority.tick = 5000;
  const aifc::Classification stale = rig.decide();
  AIFC_CHECK_EQ(stale.citations.size(), std::size_t{1});
  AIFC_CHECK(stale.state == aifc::ClassificationState::STALE);
}

// ---------------------------------------------------------------------------
// Contradiction and subordination
// ---------------------------------------------------------------------------

AIFC_TEST("decision_engine/heuristic: a heuristic record is SUBORDINATE and never contradicts (REAL)") {
  Rig rig;
  const aifc::EvidenceRecord declaration =
      rig.make_record("ev-0000000000000001", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  const aifc::EvidenceRecord guess =
      rig.make_record("ev-0000000000000002", aifc::SemanticClass::TELEMETRY,
                      aifc::EvidenceSource::HEURISTIC, 9);
  rig.policy.allow_heuristic_evidence = true;
  rig.evidence = {declaration, guess};

  const aifc::Classification answer = rig.decide();
  AIFC_CHECK(answer.semantic == aifc::SemanticClass::COLLECTIVE);
  AIFC_CHECK_MSG(answer.state == aifc::ClassificationState::CURRENT,
                 "a disagreeing guess must not create a contradiction, but the state was "
                     << aifc::to_string(answer.state));
  AIFC_CHECK_MSG(answer.contradictions.empty(),
                 "a heuristic record produced " << answer.contradictions.size()
                                                << " contradictions");
  AIFC_CHECK_EQ(answer.applied_penalty_basis_points, 0U);
  AIFC_CHECK_EQ(answer.confidence.basis_points(), 9000U);
  AIFC_CHECK_EQ(answer.corroboration_count, 0U);
  const aifc::EvidenceCitation* guess_citation = citation_for(answer, "ev-0000000000000002");
  AIFC_CHECK(guess_citation != nullptr);
  if (guess_citation != nullptr) {
    AIFC_CHECK(guess_citation->disposition == aifc::EvidenceDisposition::SUBORDINATE);
    AIFC_CHECK_MSG(contains(guess_citation->detail, "heuristic"),
                   "the subordinate citation must say why, got: " << guess_citation->detail);
  }

  // A heuristic that agrees is subordinate too: it is never corroboration, because a guess
  // cannot strengthen a declaration.
  const aifc::EvidenceRecord agreeing_guess =
      rig.make_record("ev-0000000000000003", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::HEURISTIC, 2);
  rig.evidence = {declaration, agreeing_guess};
  const aifc::Classification agreeing = rig.decide();
  AIFC_CHECK(agreeing.state == aifc::ClassificationState::CURRENT);
  AIFC_CHECK_EQ(agreeing.corroboration_count, 0U);
  AIFC_CHECK_EQ(count_disposition(agreeing, aifc::EvidenceDisposition::CORROBORATING), 0U);
  AIFC_CHECK_EQ(count_disposition(agreeing, aifc::EvidenceDisposition::SUBORDINATE), 1U);

  // With the global switch off, a heuristic record is refused by policy and cited as rejected --
  // not as subordinate truth and not as a contradiction.
  rig.policy.allow_heuristic_evidence = false;
  rig.evidence = {declaration, guess};
  const aifc::Classification refused = rig.decide();
  AIFC_CHECK(refused.semantic == aifc::SemanticClass::COLLECTIVE);
  AIFC_CHECK(refused.state == aifc::ClassificationState::CURRENT);
  const aifc::EvidenceCitation* rejected = citation_for(refused, "ev-0000000000000002");
  AIFC_CHECK(rejected != nullptr);
  if (rejected != nullptr) {
    AIFC_CHECK(rejected->disposition == aifc::EvidenceDisposition::REJECTED);
    AIFC_CHECK(rejected->state == aifc::EvidenceState::EVIDENCE_REJECTED);
    AIFC_CHECK_MSG(contains(rejected->detail, "heuristic"),
                   "the rejection reason must name the heuristic rule, got: " << rejected->detail);
  }
}

AIFC_TEST("decision_engine/contradiction: disagreement is reported with the configured penalty (REAL)") {
  Rig rig;
  rig.policy.contradiction_penalty = 2500U;
  const aifc::EvidenceRecord left =
      rig.make_record("ev-0000000000000001", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 4);
  const aifc::EvidenceRecord right =
      rig.make_record("ev-0000000000000002", aifc::SemanticClass::TELEMETRY,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 5);
  rig.evidence = {left, right};

  const aifc::Classification answer = rig.decide();
  AIFC_CHECK(answer.state == aifc::ClassificationState::CONTRADICTED);
  AIFC_CHECK_EQ(answer.contradictions.size(), std::size_t{1});
  AIFC_CHECK_EQ(answer.applied_penalty_basis_points, 2500U);
  // The winner is the later sequence, and its confidence is the source constant minus the
  // reported penalty -- never a silent average and never silently absorbed.
  AIFC_CHECK(answer.semantic == aifc::SemanticClass::TELEMETRY);
  AIFC_CHECK_EQ(answer.selected_evidence.value(), std::string("ev-0000000000000002"));
  AIFC_CHECK_EQ(answer.confidence.basis_points(), 9000U - 2500U);
  AIFC_CHECK_EQ(count_disposition(answer, aifc::EvidenceDisposition::SELECTED), 1U);
  AIFC_CHECK_EQ(count_disposition(answer, aifc::EvidenceDisposition::CONTRADICTING), 1U);
  if (answer.contradictions.size() == 1U) {
    const aifc::ClassificationContradiction& contradiction = answer.contradictions[0];
    AIFC_CHECK_EQ(contradiction.left_id.value(), std::string("ev-0000000000000002"));
    AIFC_CHECK(contradiction.left_class == aifc::SemanticClass::TELEMETRY);
    AIFC_CHECK_EQ(contradiction.right_id.value(), std::string("ev-0000000000000001"));
    AIFC_CHECK(contradiction.right_class == aifc::SemanticClass::COLLECTIVE);
    AIFC_CHECK(!contradiction.resolved_by.empty());
    AIFC_CHECK_MSG(contains(contradiction.resolved_by, "5"),
                   "the resolution must cite the winning source rank, got: "
                       << contradiction.resolved_by);
  }

  // A penalty large enough to drop the winner below the publishable threshold makes the answer
  // UNKNOWN/INSUFFICIENT, and the penalty is then not reported as applied because no class was
  // published from it.
  rig.policy.contradiction_penalty = 8500U;
  rig.policy.minimum_publishable_confidence = 1000U;
  const aifc::Classification suppressed = rig.decide();
  AIFC_CHECK(suppressed.semantic == aifc::SemanticClass::UNKNOWN);
  AIFC_CHECK(suppressed.state == aifc::ClassificationState::INSUFFICIENT);
  AIFC_CHECK_EQ(suppressed.confidence.basis_points(), 0U);
  AIFC_CHECK(suppressed.contradictions.empty());
  AIFC_CHECK_EQ(suppressed.applied_penalty_basis_points, 0U);

  // A record may lower its own confidence but never raise it above the source constant.
  Rig low;
  aifc::EvidenceRecord modest =
      low.make_record("ev-0000000000000001", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  modest.confidence = aifc::Confidence::from_basis_points(3000U);
  low.evidence = {modest};
  AIFC_CHECK_EQ(low.decide().confidence.basis_points(), 3000U);
  modest.confidence = aifc::Confidence::from_basis_points(10000U);
  low.evidence = {modest};
  AIFC_CHECK_MSG(low.decide().confidence.basis_points() == 9000U,
                 "the engine must not raise a record above its source confidence, but it "
                 "reported "
                     << low.decide().confidence.basis_points());
}

AIFC_TEST("decision_engine/threshold: below the publishable threshold is UNKNOWN, not a weaker class (REAL)") {
  Rig rig;
  rig.policy.minimum_publishable_confidence = 5000U;
  aifc::EvidenceRecord quiet =
      rig.make_record("ev-0000000000000001", aifc::SemanticClass::KV_STATE_TRANSFER,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  quiet.confidence = aifc::Confidence::from_basis_points(4999U);
  rig.evidence = {quiet};

  const aifc::Classification below = rig.decide();
  AIFC_CHECK_MSG(below.semantic == aifc::SemanticClass::UNKNOWN,
                 "a candidate below the publishable threshold must not be published, but the "
                 "class was "
                     << aifc::to_string(below.semantic));
  AIFC_CHECK(below.state == aifc::ClassificationState::INSUFFICIENT);
  AIFC_CHECK_EQ(below.confidence.basis_points(), 0U);
  AIFC_CHECK(below.selected_evidence.empty());
  AIFC_CHECK(below.selected_source == aifc::EvidenceSource::UNKNOWN);
  AIFC_CHECK_EQ(below.corroboration_count, 0U);
  // The candidate is still cited, as BELOW_THRESHOLD, so the operator sees what fell short.
  const aifc::EvidenceCitation* citation = citation_for(below, "ev-0000000000000001");
  AIFC_CHECK(citation != nullptr);
  if (citation != nullptr) {
    AIFC_CHECK_MSG(citation->disposition == aifc::EvidenceDisposition::BELOW_THRESHOLD,
                   "the losing candidate must be cited as BELOW_THRESHOLD, not "
                       << aifc::to_string(citation->disposition));
    AIFC_CHECK_MSG(contains(citation->detail, "threshold"),
                   "the citation must explain the threshold, got: " << citation->detail);
  }

  // Exactly at the threshold the class is published: the rule is "below", not "at or below".
  quiet.confidence = aifc::Confidence::from_basis_points(5000U);
  rig.evidence = {quiet};
  const aifc::Classification at_threshold = rig.decide();
  AIFC_CHECK_MSG(at_threshold.semantic == aifc::SemanticClass::KV_STATE_TRANSFER,
                 "a candidate exactly at the publishable threshold must be published, but the "
                 "class was "
                     << aifc::to_string(at_threshold.semantic));
  AIFC_CHECK(at_threshold.state == aifc::ClassificationState::CURRENT);
  AIFC_CHECK_EQ(at_threshold.confidence.basis_points(), 5000U);

  // A zero threshold publishes whatever the source justifies, which is the shortest possible
  // path from evidence to a class -- and it still cannot publish UNKNOWN.
  rig.policy.minimum_publishable_confidence = 0U;
  const aifc::Classification zero_threshold = rig.decide();
  AIFC_CHECK(zero_threshold.semantic == aifc::SemanticClass::KV_STATE_TRANSFER);
}

// ---------------------------------------------------------------------------
// Consideration cap
// ---------------------------------------------------------------------------

AIFC_TEST("decision_engine/cap: decisive citations are kept and the rest are EXCLUDED_BY_LIMIT (REAL)") {
  Rig rig;
  const aifc::EvidenceRecord winner =
      rig.make_record("ev-0000000000000001", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 6);
  const aifc::EvidenceRecord contradicting =
      rig.make_record("ev-0000000000000002", aifc::SemanticClass::TELEMETRY,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 5);
  const aifc::EvidenceRecord corroborating =
      rig.make_record("ev-0000000000000003", aifc::SemanticClass::COLLECTIVE,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 4);
  aifc::EvidenceRecord stale = rig.make_record("ev-0000000000000004", aifc::SemanticClass::SHUFFLE,
                                               aifc::EvidenceSource::DECLARED_AUTHENTICATED, 3);
  stale.state = aifc::EvidenceState::EVIDENCE_STALE;
  aifc::EvidenceRecord withdrawn = rig.make_record(
      "ev-0000000000000005", aifc::SemanticClass::CHECKPOINT,
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 2);
  withdrawn.state = aifc::EvidenceState::EVIDENCE_SUPERSEDED;
  aifc::EvidenceRecord revoked =
      rig.make_record("ev-0000000000000006", aifc::SemanticClass::STORAGE_DATA,
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  revoked.state = aifc::EvidenceState::EVIDENCE_REVOKED;
  rig.evidence = {winner, contradicting, corroborating, stale, withdrawn, revoked};

  // A cap below the number of decisive citations cannot hide any of them.
  rig.policy.max_evidence_considered = 3U;
  const aifc::Classification tight = rig.decide();
  AIFC_CHECK_EQ(tight.citations.size(), std::size_t{6});
  AIFC_CHECK_EQ(count_disposition(tight, aifc::EvidenceDisposition::SELECTED), 1U);
  AIFC_CHECK_EQ(count_disposition(tight, aifc::EvidenceDisposition::CONTRADICTING), 1U);
  AIFC_CHECK_EQ(count_disposition(tight, aifc::EvidenceDisposition::CORROBORATING), 1U);
  AIFC_CHECK_EQ(count_disposition(tight, aifc::EvidenceDisposition::EXCLUDED_BY_LIMIT), 3U);
  for (const char* id : {"ev-0000000000000001", "ev-0000000000000002", "ev-0000000000000003"}) {
    const aifc::EvidenceCitation* citation = citation_for(tight, id);
    AIFC_CHECK(citation != nullptr);
    if (citation != nullptr) {
      AIFC_CHECK_MSG(citation->disposition != aifc::EvidenceDisposition::EXCLUDED_BY_LIMIT,
                     "decisive citation " << id << " must never be dropped by the cap");
    }
  }
  const aifc::EvidenceCitation* excluded = citation_for(tight, "ev-0000000000000004");
  AIFC_CHECK(excluded != nullptr);
  if (excluded != nullptr) {
    AIFC_CHECK(excluded->disposition == aifc::EvidenceDisposition::EXCLUDED_BY_LIMIT);
    AIFC_CHECK_MSG(contains(excluded->detail, "3"),
                   "the exclusion must name the cap, got: " << excluded->detail);
  }

  // A cap that leaves room keeps the leading non-decisive citations in canonical order and
  // excludes only the tail, so the cap itself is deterministic.
  rig.policy.max_evidence_considered = 5U;
  const aifc::Classification partial = rig.decide();
  AIFC_CHECK_EQ(partial.citations.size(), std::size_t{6});
  AIFC_CHECK_EQ(count_disposition(partial, aifc::EvidenceDisposition::EXCLUDED_BY_LIMIT), 1U);
  AIFC_CHECK_EQ(count_disposition(partial, aifc::EvidenceDisposition::STALE), 1U);
  AIFC_CHECK_EQ(count_disposition(partial, aifc::EvidenceDisposition::WITHDRAWN), 1U);
  AIFC_CHECK_EQ(count_disposition(partial, aifc::EvidenceDisposition::REVOKED), 0U);
  const aifc::EvidenceCitation* tail = citation_for(partial, "ev-0000000000000006");
  AIFC_CHECK(tail != nullptr);
  if (tail != nullptr) {
    AIFC_CHECK(tail->disposition == aifc::EvidenceDisposition::EXCLUDED_BY_LIMIT);
  }

  // A cap above the number of citations excludes nothing.
  rig.policy.max_evidence_considered = 10U;
  const aifc::Classification roomy = rig.decide();
  AIFC_CHECK_EQ(roomy.citations.size(), std::size_t{6});
  AIFC_CHECK_EQ(count_disposition(roomy, aifc::EvidenceDisposition::EXCLUDED_BY_LIMIT), 0U);
  AIFC_CHECK_EQ(count_disposition(roomy, aifc::EvidenceDisposition::WITHDRAWN), 1U);
  AIFC_CHECK_EQ(count_disposition(roomy, aifc::EvidenceDisposition::REVOKED), 1U);
  AIFC_CHECK_MSG(roomy.semantic == aifc::SemanticClass::COLLECTIVE,
                 "the cap must not change the answer, but the class was "
                     << aifc::to_string(roomy.semantic));
}

// ---------------------------------------------------------------------------
// Invariants and the digest
// ---------------------------------------------------------------------------

AIFC_TEST("decision_engine/invariants: no class without a cited current record (REAL, randomized)") {
  // Seeded randomness only.  Every failure message carries the seed and the iteration, so a
  // failing case can be replayed exactly.
  constexpr std::uint64_t kSeed = 0x0A1FC1A551F1EDULL;
  const std::string seed_text = aifc::format_seed(kSeed);
  aifc::Rng rng(kSeed);

  const aifc::SemanticClass classes[] = {
      aifc::SemanticClass::COLLECTIVE,     aifc::SemanticClass::TRAINING_SYNC,
      aifc::SemanticClass::INFERENCE_REQUEST, aifc::SemanticClass::KV_STATE_TRANSFER,
      aifc::SemanticClass::MODEL_STATE_TRANSFER, aifc::SemanticClass::SHUFFLE,
      aifc::SemanticClass::CHECKPOINT,     aifc::SemanticClass::TELEMETRY,
  };
  const aifc::EvidenceSource sources[] = {
      aifc::EvidenceSource::HEURISTIC,
      aifc::EvidenceSource::TOPOLOGY_CORRELATED,
      aifc::EvidenceSource::COORDINATOR_CORRELATED,
      aifc::EvidenceSource::CONTRACT_DERIVED,
      aifc::EvidenceSource::DECLARED_AUTHENTICATED,
  };
  const aifc::EvidenceState states[] = {
      aifc::EvidenceState::EVIDENCE_CURRENT,      aifc::EvidenceState::EVIDENCE_STALE,
      aifc::EvidenceState::EVIDENCE_SUPERSEDED,   aifc::EvidenceState::EVIDENCE_REVOKED,
      aifc::EvidenceState::EVIDENCE_INSUFFICIENT, aifc::EvidenceState::EVIDENCE_REJECTED,
  };

  for (int iteration = 0; iteration < 512; ++iteration) {
    const std::string context =
        seed_text + " iteration " + std::to_string(iteration);
    Rig rig;
    rig.policy.allow_heuristic_evidence = true;
    rig.policy.minimum_publishable_confidence =
        static_cast<std::uint32_t>(rng.next_below(10001U));
    rig.policy.contradiction_penalty = static_cast<std::uint32_t>(rng.next_below(10001U));
    rig.policy.max_evidence_considered = static_cast<std::uint32_t>(1U + rng.next_below(8U));
    rig.authority.tick = rng.next_bool() ? aifc::kTickNone
                                         : static_cast<aifc::Tick>(rng.next_below(20000U));
    rig.flow.generation = aifc::FlowGeneration{1U + rng.next_below(3U)};

    const std::size_t count = 1U + static_cast<std::size_t>(rng.next_below(8U));
    for (std::size_t index = 0; index < count; ++index) {
      std::string id = "ev-00000000000000";
      id += static_cast<char>('0' + (index % 10U));
      aifc::EvidenceRecord record =
          rig.make_record(id.c_str(), classes[rng.next_below(8U)], sources[rng.next_below(5U)],
                          static_cast<aifc::Seq>(rng.next_below(50U)));
      record.state = states[rng.next_below(6U)];
      if (rng.next_bool()) {
        record.confidence = aifc::Confidence::from_basis_points(
            static_cast<std::uint32_t>(rng.next_below(10001U)));
      }
      if (rng.next_bool()) record.fresh_until = aifc::kTickNone;
      if (rng.next_bool()) {
        // Half of the records come from an incarnation that is not live, which exercises the
        // liveness rule against a record that claims CURRENT.
        record.publisher = aifc::make_publisher_id("publisher-1");
        record.publisher_boot = aifc::PublisherBootId{2};
        rig.make_known_only("publisher-1");
      }
      if (rng.next_bool()) {
        // A record about another incarnation of the flow is not about this question.
        record.flow_generation = aifc::FlowGeneration{99};
      }
      if (rng.next_bool()) {
        record.accepted_epoch = aifc::CoordinatorEpoch{1};
      }
      record.content_digest = aifc::compute_evidence_digest(record);
      rig.evidence.push_back(record);
    }

    const aifc::Classification answer = rig.decide();

    // Invariant 1: UNKNOWN never carries confidence.
    AIFC_CHECK_MSG(!(answer.semantic == aifc::SemanticClass::UNKNOWN &&
                     answer.confidence.basis_points() != 0U),
                   context << ": UNKNOWN was reported with confidence "
                           << answer.confidence.basis_points());

    // Invariant 2 (the engine's own check): a class is only reported when a SELECTED, CURRENT
    // citation carries exactly that class.
    if (answer.semantic != aifc::SemanticClass::UNKNOWN &&
        answer.state != aifc::ClassificationState::REVOKED) {
      bool justified = false;
      for (const aifc::EvidenceCitation& citation : answer.citations) {
        if (citation.disposition == aifc::EvidenceDisposition::SELECTED &&
            citation.state == aifc::EvidenceState::EVIDENCE_CURRENT &&
            citation.semantic == answer.semantic) {
          justified = true;
          break;
        }
      }
      AIFC_CHECK_MSG(justified,
                     context << ": class " << aifc::to_string(answer.semantic)
                             << " was reported without a SELECTED, CURRENT citation carrying it");
      AIFC_CHECK_MSG(!answer.selected_evidence.empty(),
                     context << ": a class was reported with no selected evidence id");
    } else {
      AIFC_CHECK_MSG(answer.confidence.basis_points() == 0U,
                     context << ": an unpublished answer carried confidence "
                             << answer.confidence.basis_points());
      AIFC_CHECK_MSG(answer.selected_evidence.empty(),
                     context << ": an unpublished answer named selected evidence "
                             << answer.selected_evidence.value());
      AIFC_CHECK_MSG(answer.selected_source == aifc::EvidenceSource::UNKNOWN,
                     context << ": an unpublished answer named a selected source "
                             << aifc::to_string(answer.selected_source));
    }

    // Invariant 3: every considered record produces exactly one citation, so the explanation is
    // exhaustive over what the engine looked at.
    AIFC_CHECK_MSG(answer.citations.size() == rig.evidence.size(),
                   context << ": " << answer.citations.size() << " citations for "
                           << rig.evidence.size() << " records");
    for (const aifc::EvidenceCitation& citation : answer.citations) {
      bool found = false;
      for (const aifc::EvidenceRecord& record : rig.evidence) {
        if (record.id == citation.id) {
          found = true;
          break;
        }
      }
      AIFC_CHECK_MSG(found, context << ": citation " << citation.id.value()
                                    << " does not correspond to any input record");
    }

    // Invariant 4: the reported penalty is exactly the configured one, and a contradiction is
    // reported with CONTRADICTED state.
    if (!answer.contradictions.empty()) {
      AIFC_CHECK_MSG(answer.applied_penalty_basis_points == rig.policy.contradiction_penalty,
                     context << ": " << answer.contradictions.size()
                             << " contradictions were reported with penalty "
                             << answer.applied_penalty_basis_points << " instead of "
                             << rig.policy.contradiction_penalty);
      AIFC_CHECK_MSG(answer.state == aifc::ClassificationState::CONTRADICTED,
                     context << ": contradictions were reported in state "
                             << aifc::to_string(answer.state));
    } else {
      AIFC_CHECK_MSG(answer.applied_penalty_basis_points == 0U,
                     context << ": a penalty of " << answer.applied_penalty_basis_points
                             << " was reported with no contradiction");
    }

    // Invariant 5: corroboration counts citations that actually corroborate.
    std::size_t corroborating = 0;
    for (const aifc::EvidenceCitation& citation : answer.citations) {
      if (citation.disposition == aifc::EvidenceDisposition::CORROBORATING) ++corroborating;
    }
    AIFC_CHECK_MSG(answer.corroboration_count == corroborating,
                   context << ": corroboration_count is " << answer.corroboration_count
                           << " but " << corroborating << " citations corroborate");

    // Invariant 6: the decision digest is a pure function of the decision content, so deciding
    // the same input again must produce the same digest.
    const aifc::Classification again = rig.decide();
    AIFC_CHECK_MSG(again.digest == answer.digest,
                   context << ": two runs over the same evidence set produced different decision "
                              "digests ("
                           << answer.digest.to_hex() << " vs " << again.digest.to_hex() << ")");
  }
}

AIFC_TEST("decision_engine/digest: equal content digests equally regardless of citation order (REAL)") {
  aifc::Classification classification;
  classification.flow_id = aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U));
  classification.flow_generation = aifc::FlowGeneration{2};
  classification.semantic = aifc::SemanticClass::COLLECTIVE;
  classification.state = aifc::ClassificationState::CONTRADICTED;
  classification.confidence = aifc::Confidence::from_basis_points(7000U);
  classification.selected_evidence = aifc::make_evidence_id("ev-0000000000000002");
  classification.selected_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  classification.corroboration_count = 1;
  classification.applied_penalty_basis_points = 2000;
  classification.policy_generation = aifc::ClassifierPolicyGeneration{3};
  classification.policy_digest = aifc::compute_policy_digest(aifc::ClassifierPolicy::initial());

  const auto make_citation = [](const char* id, aifc::EvidenceDisposition disposition) {
    aifc::EvidenceCitation citation;
    citation.id = aifc::make_evidence_id(id);
    citation.publisher = aifc::make_publisher_id("publisher-0");
    citation.source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    citation.state = aifc::EvidenceState::EVIDENCE_CURRENT;
    citation.semantic = aifc::SemanticClass::COLLECTIVE;
    citation.disposition = disposition;
    citation.confidence = aifc::Confidence::from_basis_points(9000U);
    citation.generation = aifc::EvidenceGeneration{4};
    return citation;
  };
  classification.citations = {
      make_citation("ev-0000000000000003", aifc::EvidenceDisposition::CONTRADICTING),
      make_citation("ev-0000000000000001", aifc::EvidenceDisposition::CORROBORATING),
      make_citation("ev-0000000000000002", aifc::EvidenceDisposition::SELECTED),
  };

  const aifc::Digest256 forward = aifc::compute_classification_digest(classification);
  AIFC_CHECK(!forward.is_zero());
  AIFC_CHECK_EQ(aifc::compute_classification_digest(classification).to_hex(), forward.to_hex());

  aifc::Classification reversed = classification;
  std::reverse(reversed.citations.begin(), reversed.citations.end());
  AIFC_CHECK_MSG(aifc::compute_classification_digest(reversed) == forward,
                 "the decision digest depends on citation order: "
                     << aifc::compute_classification_digest(reversed).to_hex() << " vs "
                     << forward.to_hex());

  aifc::Classification rotate = classification;
  std::rotate(rotate.citations.begin(), rotate.citations.begin() + 1, rotate.citations.end());
  AIFC_CHECK_MSG(aifc::compute_classification_digest(rotate) == forward,
                 "the decision digest changed under a rotation of the citation list");

  // Every content field participates, so a decision can never be silently reinterpreted as
  // another decision.
  aifc::Classification semantic_changed = classification;
  semantic_changed.semantic = aifc::SemanticClass::TELEMETRY;
  aifc::Classification state_changed = classification;
  state_changed.state = aifc::ClassificationState::CURRENT;
  aifc::Classification confidence_changed = classification;
  confidence_changed.confidence = aifc::Confidence::from_basis_points(6999U);
  aifc::Classification selected_changed = classification;
  selected_changed.selected_evidence = aifc::make_evidence_id("ev-0000000000000009");
  aifc::Classification source_changed = classification;
  source_changed.selected_source = aifc::EvidenceSource::CONTRACT_DERIVED;
  aifc::Classification generation_changed = classification;
  generation_changed.flow_generation = aifc::FlowGeneration{3};
  aifc::Classification corroboration_changed = classification;
  corroboration_changed.corroboration_count = 2;
  aifc::Classification penalty_changed = classification;
  penalty_changed.applied_penalty_basis_points = 1999;
  aifc::Classification policy_changed = classification;
  policy_changed.policy_generation = aifc::ClassifierPolicyGeneration{4};
  aifc::Classification citation_changed = classification;
  citation_changed.citations[0].semantic = aifc::SemanticClass::SHUFFLE;
  aifc::Classification citation_disposition_changed = classification;
  citation_disposition_changed.citations[1].disposition = aifc::EvidenceDisposition::STALE;

  struct Mutation {
    const char* what;
    const aifc::Classification& value;
  };
  const Mutation mutations[] = {
      {"semantic", semantic_changed},
      {"state", state_changed},
      {"confidence", confidence_changed},
      {"selected_evidence", selected_changed},
      {"selected_source", source_changed},
      {"flow_generation", generation_changed},
      {"corroboration_count", corroboration_changed},
      {"applied_penalty_basis_points", penalty_changed},
      {"policy_generation", policy_changed},
      {"citations[].semantic", citation_changed},
      {"citations[].disposition", citation_disposition_changed},
  };
  for (const Mutation& mutation : mutations) {
    AIFC_CHECK_MSG(aifc::compute_classification_digest(mutation.value) != forward,
                   "changing " << mutation.what << " did not change the decision digest "
                               << forward.to_hex());
  }

  // The engine itself excludes the fields that describe when and by which process a decision
  // was made, so two runs in different incarnations agree.
  Rig first;
  first.evidence = {first.make_record("ev-0000000000000001", aifc::SemanticClass::COLLECTIVE,
                                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1)};
  first.authority.epoch = aifc::CoordinatorEpoch{2};
  first.authority.coordinator_boot = aifc::CoordinatorBootId{7};
  first.authority.tick = 100;
  Rig second = first;
  second.authority.epoch = aifc::CoordinatorEpoch{9};
  second.authority.coordinator_boot = aifc::CoordinatorBootId{11};
  second.authority.tick = 999;
  // The record moves with the incarnation so that it is current in both runs: the epoch is an
  // input to currentness, so changing it without moving the record would change the decision
  // for a reason that has nothing to do with the digest.
  second.evidence[0].accepted_epoch = second.authority.epoch;
  second.evidence[0].accepted_boot = aifc::CoordinatorBootId{11};
  second.evidence[0].content_digest = aifc::compute_evidence_digest(second.evidence[0]);
  const aifc::Classification first_answer = first.decide();
  const aifc::Classification second_answer = second.decide();
  AIFC_CHECK_MSG(first_answer.digest == second_answer.digest,
                 "the decision digest must not depend on the epoch, the boot or the tick: "
                     << first_answer.digest.to_hex() << " vs " << second_answer.digest.to_hex());
  AIFC_CHECK_NE(first_answer.coordinator_epoch.value, second_answer.coordinator_epoch.value);
}
