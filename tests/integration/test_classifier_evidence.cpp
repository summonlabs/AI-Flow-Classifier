// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Integration proof surface: evidence admission end to end through the classifier facade.
//
// The single rule this file exists to prove is that authority comes from the authenticated
// session envelope and never from anything the peer's payload says about itself.  Every case
// here mutates one input and asserts the exact refusal code, so a refusal cannot be confused
// with a parse failure or with a capacity failure.
//
// Inputs are SYNTHETIC; the admission, staleness and withdrawal behaviour is REAL.

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

[[nodiscard]] aifc::EvidencePayload make_payload(const aifc::FlowRecord& flow,
                                                 aifc::SemanticClass semantic,
                                                 aifc::EvidenceGeneration generation,
                                                 aifc::EvidenceSource claimed,
                                                 std::string topic = "synthetic.topic",
                                                 std::uint64_t hint_binding = 0) {
  aifc::EvidencePayload payload;
  payload.flow_key = flow.key;
  payload.flow_generation = flow.generation;
  payload.evidence_generation = generation;
  payload.semantic = semantic;
  payload.claimed_source = claimed;
  payload.metadata.topic = std::move(topic);
  payload.metadata.reason = "synthetic evidence";
  // The binding field is how a heuristic submission cites the hint it claims to have observed:
  // the low 16 bits are the port and the next byte is the transport.  A zero binding cites nothing,
  // which admission refuses when heuristics are permitted.
  payload.metadata.binding = hint_binding;
  return payload;
}

[[nodiscard]] aifc::ClassificationQuery query_for(const aifc::FlowKey& key) {
  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.accept_current_generation = true;
  return query;
}

// The classifier measures freshness in ticks from its clock, and the default clock is a
// monotonic millisecond source.  A surface that is not testing freshness therefore runs with a
// window large enough that nothing can expire while it executes; the exact boundaries are pinned
// with a manual clock in the classifier/memo case, and the default window is asserted in the
// unit surfaces.
[[nodiscard]] aifc::ClassifierPolicy steady_policy() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.default_freshness_window = 1ULL << 32U;
  return policy;
}

}  // namespace

AIFC_TEST("evidence/declared: an authenticated declaration produces the declared class (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(0U);
  const aifc::FlowRecord flow = harness.register_flow(peer, 0U);

  // The payload carries no identity, no session and no source ceiling; the coordinator mints the
  // evidence identity and takes every authority field from the envelope.
  const aifc::EvidencePayload payload =
      make_payload(flow, aifc::SemanticClass::INFERENCE_REQUEST, aifc::EvidenceGeneration{1},
                   aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  AIFC_CHECK(payload.metadata.contract.empty());
  AIFC_CHECK(payload.workload.empty());

  const auto outcome = harness.classifier().submit_evidence(peer.envelope, payload);
  AIFC_CHECK_OK(outcome);
  if (!outcome) return;
  AIFC_CHECK_EQ(outcome.value().accepted, true);
  AIFC_CHECK(outcome.value().effective_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  AIFC_CHECK_MSG(outcome.value().notes.empty(),
                 "an unclamped declaration must not carry a warning, got "
                     << outcome.value().notes.size() << " note(s)");
  AIFC_CHECK_EQ(outcome.value().superseded_previous, false);
  AIFC_CHECK_EQ(outcome.value().fenced_flow_generation, false);

  const aifc::EvidenceRecord& record = outcome.value().record;
  AIFC_CHECK_MSG(contains(record.id.value(), "ev-"),
                 "the evidence identity must be minted by the coordinator, got "
                     << record.id.value());
  AIFC_CHECK_EQ(record.publisher.value(), peer.publisher.value());
  AIFC_CHECK_EQ(record.publisher_boot.value, peer.boot.value);
  AIFC_CHECK_EQ(record.session.value(), peer.session.value());
  AIFC_CHECK_EQ(record.accepted_epoch.value, harness.classifier().epoch().value);
  AIFC_CHECK_EQ(record.accepted_boot.value, harness.classifier().coordinator_boot().value);
  AIFC_CHECK_EQ(record.flow_id.to_hex(), flow.id.to_hex());
  AIFC_CHECK_EQ(record.flow_generation.value, flow.generation.value);
  AIFC_CHECK_EQ(record.generation.value, 1U);
  AIFC_CHECK_EQ(record.confidence.to_decimal(), std::string("0.9000"));
  AIFC_CHECK(record.state == aifc::EvidenceState::EVIDENCE_CURRENT);
  AIFC_CHECK(record.carries_authority());
  AIFC_CHECK_EQ(record.content_digest.to_hex(), aifc::compute_evidence_digest(record).to_hex());
  AIFC_CHECK(record.accepted_seq > 0U);

  const aifc::ClassificationResult answer = harness.classify(key);
  AIFC_CHECK(answer.classification.semantic == aifc::SemanticClass::INFERENCE_REQUEST);
  AIFC_CHECK(answer.classification.state == aifc::ClassificationState::CURRENT);
  AIFC_CHECK_EQ(answer.classification.confidence.to_decimal(), std::string("0.9000"));
  AIFC_CHECK_EQ(answer.classification.selected_evidence.value(), record.id.value());
  AIFC_CHECK(answer.classification.selected_source ==
             aifc::EvidenceSource::DECLARED_AUTHENTICATED);

  // The declaration is bound to the epoch it was accepted in: advancing the epoch makes it
  // stale rather than current, even though the publisher session is untouched.
  const auto advanced = harness.classifier().advance_epoch(aifc::CoordinatorBootId{2});
  AIFC_CHECK_OK(advanced);
  const auto after_restart = harness.classifier().find_evidence(record.id);
  AIFC_CHECK_OK(after_restart);
  if (after_restart) {
    AIFC_CHECK_MSG(after_restart.value().state == aifc::EvidenceState::EVIDENCE_STALE,
                   "evidence accepted before an epoch advance is "
                       << aifc::to_string(after_restart.value().state) << " rather than STALE");
  }
  const aifc::ClassificationResult restarted = harness.classify(key);
  AIFC_CHECK(restarted.classification.state == aifc::ClassificationState::STALE);
  AIFC_CHECK(restarted.classification.semantic == aifc::SemanticClass::UNKNOWN);
}

AIFC_TEST("evidence/clamping: a claim above the session ceiling is reduced and reported (REAL)") {
  // Heuristics must be permitted for the clamped source to be admissible at all; with them off
  // the submission is refused outright, which the second half of this case checks.
  aifc::ClassifierPolicy policy = steady_policy();
  policy.allow_heuristic_evidence = true;
  // An enabled adapter and a declared hint, because admission requires the submission to cite a hint
  // that an enabled adapter declares.  The claim below is still made through the session envelope, so
  // what this case measures is the ceiling, not the gate.
  policy.heuristic_adapters = {{"clamp-adapter", true, 2000U, 1U}};
  policy.port_hints = {{aifc::TransportProtocol::TCP, 29500U, aifc::SemanticClass::COLLECTIVE, 500U,
                        "clamp-adapter"}};
  aifc_test::Harness harness(policy);
  const aifc_test::Harness::Peer heuristic_peer =
      harness.add_peer(0U, aifc::EvidenceSource::HEURISTIC);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(0U);
  const aifc::FlowRecord flow = harness.register_flow(heuristic_peer, 0U);

  const auto outcome = harness.classifier().submit_evidence(
      heuristic_peer.envelope,
      make_payload(flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                   aifc::EvidenceSource::DECLARED_AUTHENTICATED, "synthetic.topic",
                   aifc::ClassifierPolicy::hint_binding_of(aifc::TransportProtocol::TCP, 29500U)));
  AIFC_CHECK_OK(outcome);
  if (!outcome) return;
  AIFC_CHECK_MSG(outcome.value().effective_source != aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                 "a peer admitted as HEURISTIC must not be recorded as DECLARED_AUTHENTICATED");
  AIFC_CHECK_MSG(outcome.value().effective_source == aifc::EvidenceSource::HEURISTIC,
                 "the claim must be clamped to the session ceiling HEURISTIC, got "
                     << aifc::to_string(outcome.value().effective_source));
  AIFC_CHECK_MSG(
      aifc::source_rank(outcome.value().effective_source) <=
          aifc::source_rank(aifc::EvidenceSource::CONTRACT_DERIVED),
      "a clamped claim must be CONTRACT_DERIVED or weaker, got "
          << aifc::to_string(outcome.value().effective_source));
  AIFC_CHECK_EQ(outcome.value().notes.size(), std::size_t{1});
  if (outcome.value().notes.size() == 1U) {
    const std::string& note = outcome.value().notes[0];
    AIFC_CHECK_MSG(contains(note, "DECLARED_AUTHENTICATED"),
                   "the note must name the claim, got: " << note);
    AIFC_CHECK_MSG(contains(note, "HEURISTIC"), "the note must name the effective source, got: "
                                                    << note);
    AIFC_CHECK_MSG(contains(note, "reduced") || contains(note, "ceiling"),
                   "the note must explain the reduction, got: " << note);
  }
  AIFC_CHECK(outcome.value().record.source == aifc::EvidenceSource::HEURISTIC);
  AIFC_CHECK_EQ(outcome.value().record.confidence.to_decimal(), std::string("0.2000"));

  // A heuristic record is current but never decisive, so the clamped claim cannot select a
  // class: the answer is UNKNOWN with the guess visible as SUBORDINATE.
  const aifc::ClassificationResult answer = harness.classify(key);
  AIFC_CHECK_MSG(answer.classification.semantic == aifc::SemanticClass::UNKNOWN,
                 "a clamped heuristic claim must not select a class, but it selected "
                     << aifc::to_string(answer.classification.semantic));
  AIFC_CHECK(answer.classification.state == aifc::ClassificationState::INSUFFICIENT);
  AIFC_CHECK_EQ(answer.classification.confidence.to_decimal(), std::string("0.0000"));
  AIFC_CHECK_EQ(answer.classification.citations.size(), std::size_t{1});
  if (answer.classification.citations.size() == 1U) {
    AIFC_CHECK(answer.classification.citations[0].disposition ==
               aifc::EvidenceDisposition::SUBORDINATE);
    AIFC_CHECK(answer.classification.citations[0].source == aifc::EvidenceSource::HEURISTIC);
  }

  // The same claim through the same session with heuristics globally disabled is refused before
  // it can be stored, and the refusal says why.
  aifc::ClassifierPolicy strict_policy = steady_policy();
  aifc_test::Harness strict(strict_policy);
  const aifc_test::Harness::Peer strict_peer = strict.add_peer(0U, aifc::EvidenceSource::HEURISTIC);
  const aifc::FlowRecord strict_flow = strict.register_flow(strict_peer, 0U);
  const auto refused = strict.classifier().submit_evidence(
      strict_peer.envelope,
      make_payload(strict_flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                   aifc::EvidenceSource::DECLARED_AUTHENTICATED));
  AIFC_CHECK_ERR(refused, aifc::ErrorCode::HEURISTIC_DISABLED);
  if (!refused) {
    AIFC_CHECK_MSG(contains(refused.status().message, "heuristic"),
                   "the refusal must name the heuristic rule, got: " << refused.status().message);
  }
  AIFC_CHECK_EQ(strict.classifier().stats().evidence.records, std::size_t{0});
  AIFC_CHECK_EQ(strict.classifier().stats().counters.evidence_refused, 1U);

  // A session admitted at the declaration ceiling that merely claims less is clamped down to its
  // own claim: the ceiling is a maximum, not a floor.
  aifc_test::Harness honest(steady_policy());
  const aifc_test::Harness::Peer honest_peer = honest.add_peer(0U);
  const aifc::FlowRecord honest_flow = honest.register_flow(honest_peer, 0U);
  const auto modest = honest.classifier().submit_evidence(
      honest_peer.envelope,
      make_payload(honest_flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                   aifc::EvidenceSource::HEURISTIC));
  AIFC_CHECK_ERR(modest, aifc::ErrorCode::HEURISTIC_DISABLED);
}

AIFC_TEST("evidence/identity: a peer cannot publish under another publisher's identity (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer first = harness.add_peer(0U);
  const aifc_test::Harness::Peer second = harness.add_peer(1U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(1U);
  const aifc::FlowRecord flow = harness.register_flow(first, 1U);

  struct Case {
    const char* what;
    aifc::SessionEnvelope envelope;
    aifc::ErrorCode expected;
  };

  // Claiming another publisher's identity while carrying this session's identity.
  aifc::SessionEnvelope swapped = first.envelope;
  swapped.publisher = second.publisher;
  // Claiming another incarnation of a registered publisher.
  aifc::SessionEnvelope wrong_boot = first.envelope;
  wrong_boot.publisher_boot = aifc::PublisherBootId{5};
  // Claiming a session that was never issued.
  aifc::SessionEnvelope forged_session = first.envelope;
  forged_session.session = aifc_test::synthetic_session(99U);
  // Claiming an identity that was never registered.
  aifc::SessionEnvelope unknown_publisher = first.envelope;
  unknown_publisher.publisher = aifc_test::synthetic_publisher(9U);
  unknown_publisher.session = aifc_test::synthetic_session(9U);
  // Claiming a coordinator epoch and boot that this coordinator does not serve.
  aifc::SessionEnvelope wrong_epoch = first.envelope;
  wrong_epoch.epoch = aifc::CoordinatorEpoch{99};
  aifc::SessionEnvelope wrong_coordinator_boot = first.envelope;
  wrong_coordinator_boot.coordinator_boot = aifc::CoordinatorBootId{99};

  const Case cases[] = {
      {"publisher swapped to another registered publisher", swapped,
       aifc::ErrorCode::UNAUTHENTICATED},
      {"publisher boot that is not the bound incarnation", wrong_boot,
       aifc::ErrorCode::STALE_BOOT_ID},
      {"session identity that was never issued", forged_session,
       aifc::ErrorCode::UNAUTHENTICATED},
      {"publisher that was never registered", unknown_publisher,
       aifc::ErrorCode::UNKNOWN_PUBLISHER},
      {"stale coordinator epoch", wrong_epoch, aifc::ErrorCode::STALE_EPOCH},
      {"stale coordinator boot", wrong_coordinator_boot, aifc::ErrorCode::STALE_BOOT_ID},
  };

  for (std::size_t index = 0; index < std::size(cases); ++index) {
    const Case& test_case = cases[index];
    const auto outcome = harness.classifier().submit_evidence(
        test_case.envelope,
        make_payload(flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                     aifc::EvidenceSource::DECLARED_AUTHENTICATED));
    AIFC_CHECK_MSG(!outcome.ok(), "case " << index << " (" << test_case.what
                                          << ") must be refused");
    if (!outcome) {
      AIFC_CHECK_MSG(outcome.code() == test_case.expected,
                     "case " << index << " (" << test_case.what << ") produced "
                             << aifc::to_string(outcome.code()) << " ("
                             << outcome.status().message << ") instead of "
                             << aifc::to_string(test_case.expected));
    }
  }

  // Nothing was stored under any of those identities, and the publisher's own session has not
  // been credited with a publication either.
  AIFC_CHECK_EQ(harness.classifier().stats().evidence.records, std::size_t{0});
  AIFC_CHECK_EQ(harness.classifier().stats().counters.evidence_accepted, 0U);
  const auto for_flow = harness.classifier().evidence_for_flow(flow.id);
  AIFC_CHECK_OK(for_flow);
  if (for_flow) {
    AIFC_CHECK(for_flow.value().empty());
  }

  // The second publisher's *own* envelope is accepted, which shows the refusals above are about
  // the mismatch rather than about the publisher being unable to publish at all.
  const auto accepted = harness.classifier().submit_evidence(
      second.envelope,
      make_payload(flow, aifc::SemanticClass::TELEMETRY, aifc::EvidenceGeneration{1},
                   aifc::EvidenceSource::DECLARED_AUTHENTICATED, "second.topic"));
  AIFC_CHECK_OK(accepted);
  if (accepted) {
    AIFC_CHECK_EQ(accepted.value().record.publisher.value(), second.publisher.value());
    AIFC_CHECK_EQ(accepted.value().record.session.value(), second.session.value());
  }
  AIFC_CHECK_EQ(harness.classifier().stats().evidence.records, std::size_t{1});
  const aifc::ClassificationResult answer = harness.classify(key);
  AIFC_CHECK(answer.classification.semantic == aifc::SemanticClass::TELEMETRY);
  AIFC_CHECK_EQ(answer.classification.selected_evidence.value(),
                accepted ? accepted.value().record.id.value() : std::string());

  // A publisher restarted at a higher boot cannot reuse its previous incarnation's envelope.
  const aifc_test::Harness::Peer restarted =
      harness.restart_peer(0U, aifc::PublisherBootId{3});
  const auto stale_envelope = harness.classifier().submit_evidence(
      first.envelope,
      make_payload(flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{2},
                   aifc::EvidenceSource::DECLARED_AUTHENTICATED, "restart.topic"));
  AIFC_CHECK_ERR(stale_envelope, aifc::ErrorCode::STALE_BOOT_ID);
  // ... but its new envelope is accepted, and the generation high water mark restarted with the
  // incarnation, so generation 1 is usable again.
  const auto after_restart = harness.classifier().submit_evidence(
      restarted.envelope,
      make_payload(flow, aifc::SemanticClass::CHECKPOINT, aifc::EvidenceGeneration{1},
                   aifc::EvidenceSource::DECLARED_AUTHENTICATED, "restart.topic"));
  AIFC_CHECK_OK(after_restart);
  if (after_restart) {
    AIFC_CHECK_EQ(after_restart.value().record.publisher_boot.value, 3U);
  }
}

AIFC_TEST("evidence/binding: citing a contract or workload the publisher does not own is UNAUTHORIZED (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer owner = harness.add_peer(0U);
  const aifc_test::Harness::Peer stranger = harness.add_peer(1U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(2U);
  const aifc::FlowRecord flow = harness.register_flow(owner, 2U);

  const aifc::WorkloadRecord workload = harness.declare_workload(owner, 0U);
  const aifc::WorkloadContract contract =
      harness.activate_contract(owner, workload, 0U, aifc::SemanticClass::KV_STATE_TRANSFER);

  // Citing the contract without naming the workload: the ownership of the contract is what is
  // checked, and the refusal names the publisher and the contract.
  aifc::EvidencePayload cites_contract = make_payload(
      flow, aifc::SemanticClass::KV_STATE_TRANSFER, aifc::EvidenceGeneration{1},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "stranger.contract");
  cites_contract.contract = contract.id;
  const auto contract_refusal = harness.classifier().submit_evidence(stranger.envelope, cites_contract);
  AIFC_CHECK_ERR(contract_refusal, aifc::ErrorCode::UNAUTHORIZED);
  if (!contract_refusal) {
    AIFC_CHECK_MSG(contains(contract_refusal.status().message, contract.id.value()),
                   "the refusal must name the contract, got: "
                       << contract_refusal.status().message);
    AIFC_CHECK_MSG(contains(contract_refusal.status().message, stranger.publisher.value()),
                   "the refusal must name the publisher, got: "
                       << contract_refusal.status().message);
  }

  // Naming the workload it does not own is refused before the contract is even considered.
  aifc::EvidencePayload cites_workload = make_payload(
      flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{2},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "stranger.workload");
  cites_workload.workload = workload.id;
  cites_workload.workload_generation = workload.generation;
  const auto workload_refusal = harness.classifier().submit_evidence(stranger.envelope, cites_workload);
  AIFC_CHECK_ERR(workload_refusal, aifc::ErrorCode::UNAUTHORIZED);
  if (!workload_refusal) {
    AIFC_CHECK_MSG(contains(workload_refusal.status().message, workload.id.value()),
                   "the refusal must name the workload, got: "
                       << workload_refusal.status().message);
  }

  // An unknown contract is a different failure from one owned by somebody else.
  aifc::EvidencePayload unknown = make_payload(
      flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{3},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "stranger.unknown");
  unknown.contract = aifc_test::synthetic_contract(9U);
  AIFC_CHECK_ERR(harness.classifier().submit_evidence(stranger.envelope, unknown),
                 aifc::ErrorCode::UNKNOWN_CONTRACT);

  // The owner may cite its own contract, and the claim is validated against the workload the
  // contract is bound to.
  aifc::EvidencePayload owned = make_payload(
      flow, aifc::SemanticClass::KV_STATE_TRANSFER, aifc::EvidenceGeneration{1},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "owner.contract");
  owned.contract = contract.id;
  owned.workload = workload.id;
  owned.workload_generation = workload.generation;
  const auto accepted = harness.classifier().submit_evidence(owner.envelope, owned);
  AIFC_CHECK_OK(accepted);
  if (accepted) {
    AIFC_CHECK_EQ(accepted.value().record.contract.value(), contract.id.value());
    AIFC_CHECK_EQ(accepted.value().record.workload.value(), workload.id.value());
  }
  // The owner may not cite its own contract while naming a different workload generation: the
  // claim is internally inconsistent, so it is refused rather than recorded.
  aifc::EvidencePayload inconsistent = make_payload(
      flow, aifc::SemanticClass::KV_STATE_TRANSFER, aifc::EvidenceGeneration{2},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "owner.inconsistent");
  inconsistent.contract = contract.id;
  inconsistent.workload = workload.id;
  inconsistent.workload_generation = aifc::WorkloadGeneration{7};
  AIFC_CHECK_ERR(harness.classifier().submit_evidence(owner.envelope, inconsistent),
                 aifc::ErrorCode::STALE_GENERATION);

  // No refused submission left a record behind: the store holds exactly the accepted one.
  AIFC_CHECK_EQ(harness.classifier().stats().evidence.records, std::size_t{1});
  AIFC_CHECK_EQ(harness.classifier().stats().counters.evidence_accepted, 1U);
  AIFC_CHECK_EQ(harness.classifier().stats().counters.evidence_refused, 4U);
}

AIFC_TEST("evidence/binding: a workload generation mismatch is STALE_GENERATION (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(3U);
  const aifc::FlowRecord flow = harness.register_flow(peer, 3U);
  const aifc::WorkloadRecord workload = harness.declare_workload(peer, 0U, aifc::WorkloadGeneration{2});

  // Naming a generation the workload is not at.
  aifc::EvidencePayload future = make_payload(
      flow, aifc::SemanticClass::TRAINING_SYNC, aifc::EvidenceGeneration{1},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "workload.future");
  future.workload = workload.id;
  future.workload_generation = aifc::WorkloadGeneration{3};
  const auto mismatch = harness.classifier().submit_evidence(peer.envelope, future);
  AIFC_CHECK_ERR(mismatch, aifc::ErrorCode::STALE_GENERATION);
  if (!mismatch) {
    AIFC_CHECK_MSG(contains(mismatch.status().message, "generation 3") &&
                       contains(mismatch.status().message, "2"),
                   "the refusal must name both generations, got: "
                       << mismatch.status().message);
  }

  // Naming a generation that has already been superseded.
  aifc::EvidencePayload past = make_payload(
      flow, aifc::SemanticClass::TRAINING_SYNC, aifc::EvidenceGeneration{2},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "workload.past");
  past.workload = workload.id;
  past.workload_generation = aifc::WorkloadGeneration{1};
  AIFC_CHECK_ERR(harness.classifier().submit_evidence(peer.envelope, past),
                 aifc::ErrorCode::STALE_GENERATION);

  // An undeclared workload is a different failure again.
  aifc::EvidencePayload undeclared = make_payload(
      flow, aifc::SemanticClass::TRAINING_SYNC, aifc::EvidenceGeneration{3},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "workload.undeclared");
  undeclared.workload = aifc_test::synthetic_workload(9U);
  undeclared.workload_generation = aifc::WorkloadGeneration{1};
  AIFC_CHECK_ERR(harness.classifier().submit_evidence(peer.envelope, undeclared),
                 aifc::ErrorCode::UNKNOWN_WORKLOAD);

  // The matching generation is accepted, and the record carries the binding verbatim.
  aifc::EvidencePayload matching = make_payload(
      flow, aifc::SemanticClass::TRAINING_SYNC, aifc::EvidenceGeneration{4},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "workload.matching");
  matching.workload = workload.id;
  matching.workload_generation = workload.generation;
  const auto accepted = harness.classifier().submit_evidence(peer.envelope, matching);
  AIFC_CHECK_OK(accepted);
  if (accepted) {
    AIFC_CHECK_EQ(accepted.value().record.workload.value(), workload.id.value());
    AIFC_CHECK_EQ(accepted.value().record.workload_generation.value, 2U);
  }
  AIFC_CHECK(harness.classify(key).classification.semantic == aifc::SemanticClass::TRAINING_SYNC);

  // Advancing the workload generation makes evidence bound to the old generation inadmissible
  // for the new one: the same payload is now stale.
  AIFC_CHECK_OK(harness.classifier().declare_workload(workload.id, peer.publisher,
                                                      aifc::WorkloadGeneration{3}, "advanced"));
  aifc::EvidencePayload after_advance = make_payload(
      flow, aifc::SemanticClass::TRAINING_SYNC, aifc::EvidenceGeneration{5},
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "workload.after-advance");
  after_advance.workload = workload.id;
  after_advance.workload_generation = aifc::WorkloadGeneration{2};
  const auto stale_binding = harness.classifier().submit_evidence(peer.envelope, after_advance);
  AIFC_CHECK_ERR(stale_binding, aifc::ErrorCode::STALE_GENERATION);
  if (!stale_binding) {
    AIFC_CHECK_MSG(contains(stale_binding.status().message, "3"),
                   "the refusal must name the current generation, got: "
                       << stale_binding.status().message);
  }
  // The record accepted before the advance is still stored and still cites its own generation:
  // the advance does not rewrite history, it changes what is current.
  const auto retained = harness.classifier().find_evidence(accepted.value().record.id);
  AIFC_CHECK_OK(retained);
  if (retained) {
    AIFC_CHECK_EQ(retained.value().workload_generation.value, 2U);
  }
}

AIFC_TEST("evidence/withdrawal: withdrawing evidence leaves the class STALE and visible (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc_test::Harness::Peer other = harness.add_peer(1U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(4U);
  const aifc::FlowRecord flow = harness.register_flow(peer, 4U);
  const aifc::EvidenceRecord record =
      harness.publish(peer, flow, aifc::SemanticClass::MODEL_STATE_TRANSFER, aifc::EvidenceGeneration{1});
  AIFC_CHECK(harness.classify(key).classification.state == aifc::ClassificationState::CURRENT);

  // Only the publisher that published a record may withdraw it.
  AIFC_CHECK_ERR(harness.classifier().withdraw_evidence(other.envelope, record.id, "not mine"),
                 aifc::ErrorCode::UNAUTHORIZED);
  AIFC_CHECK_ERR(harness.classifier().withdraw_evidence(
                     peer.envelope, aifc::make_evidence_id("ev-0000000000000000"), "unknown"),
                 aifc::ErrorCode::NOT_FOUND);

  const std::string reason = "operator requested withdrawal";
  AIFC_CHECK_OK(harness.classifier().withdraw_evidence(peer.envelope, record.id, reason));

  const auto stored = harness.classifier().find_evidence(record.id);
  AIFC_CHECK_OK(stored);
  if (stored) {
    // The record is retained and marked, never deleted: an explanation must still be able to
    // show what used to be believed and why it stopped counting.
    AIFC_CHECK(stored.value().state == aifc::EvidenceState::EVIDENCE_SUPERSEDED);
    AIFC_CHECK_EQ(stored.value().state_reason, reason);
  }

  const aifc::ClassificationResult withdrawn = harness.classify(key, aifc::FlowGeneration{}, true);
  AIFC_CHECK_MSG(withdrawn.classification.semantic == aifc::SemanticClass::UNKNOWN,
                 "withdrawing the only evidence must not leave the class published, but it "
                 "reported "
                     << aifc::to_string(withdrawn.classification.semantic));
  AIFC_CHECK(withdrawn.classification.state == aifc::ClassificationState::STALE);
  AIFC_CHECK_EQ(withdrawn.classification.confidence.to_decimal(), std::string("0.0000"));
  AIFC_CHECK_EQ(withdrawn.classification.citations.size(), std::size_t{1});
  if (withdrawn.classification.citations.size() == 1U) {
    const aifc::EvidenceCitation& citation = withdrawn.classification.citations[0];
    AIFC_CHECK_MSG(citation.disposition == aifc::EvidenceDisposition::WITHDRAWN,
                   "the withdrawal must be visible in the citations, but the disposition is "
                       << aifc::to_string(citation.disposition));
    AIFC_CHECK(citation.state == aifc::EvidenceState::EVIDENCE_SUPERSEDED);
    AIFC_CHECK_EQ(citation.detail, reason);
  }
  AIFC_CHECK_MSG(contains(withdrawn.explanation, reason),
                 "the explanation must carry the withdrawal reason, got: "
                     << withdrawn.explanation);

  // A withdrawal is recorded as a revocation, so a later reader can see who withdrew what.
  const std::vector<aifc::RevocationRecord> revocations = harness.classifier().revocations();
  AIFC_CHECK_EQ(revocations.size(), std::size_t{1});
  if (revocations.size() == 1U) {
    AIFC_CHECK_EQ(revocations[0].evidence_id.value(), record.id.value());
    AIFC_CHECK_EQ(revocations[0].flow_id.to_hex(), flow.id.to_hex());
    AIFC_CHECK_EQ(revocations[0].flow_generation.value, flow.generation.value);
    AIFC_CHECK_EQ(revocations[0].revoked_by_publisher.value(), peer.publisher.value());
    AIFC_CHECK_EQ(revocations[0].revoked_by_session.value(), peer.session.value());
    AIFC_CHECK_EQ(revocations[0].reason, reason);
  }
  AIFC_CHECK_EQ(harness.classifier().stats().counters.revocations, 1U);

  // Withdrawing again is idempotent rather than an error, and it does not resurrect anything.
  AIFC_CHECK_OK(harness.classifier().withdraw_evidence(peer.envelope, record.id, reason));
  AIFC_CHECK(harness.classify(key).classification.state == aifc::ClassificationState::STALE);

  // Republishing under a new generation restores a current class; the withdrawn record stays
  // withdrawn.
  const aifc::EvidenceRecord replacement =
      harness.publish(peer, flow, aifc::SemanticClass::SHUFFLE, aifc::EvidenceGeneration{2},
                      aifc::EvidenceSource::DECLARED_AUTHENTICATED, "replacement.topic");
  const aifc::ClassificationResult restored = harness.classify(key);
  AIFC_CHECK(restored.classification.semantic == aifc::SemanticClass::SHUFFLE);
  AIFC_CHECK(restored.classification.state == aifc::ClassificationState::CURRENT);
  AIFC_CHECK_EQ(restored.classification.selected_evidence.value(), replacement.id.value());
  const auto old_record = harness.classifier().find_evidence(record.id);
  AIFC_CHECK_OK(old_record);
  if (old_record) {
    AIFC_CHECK(old_record.value().state == aifc::EvidenceState::EVIDENCE_SUPERSEDED);
  }
}

AIFC_TEST("evidence/session_end: ending a session stales its declaration and names the publisher (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(5U);
  const aifc::FlowRecord flow = harness.register_flow(peer, 5U);
  const aifc::EvidenceRecord record =
      harness.publish(peer, flow, aifc::SemanticClass::KV_STATE_TRANSFER, aifc::EvidenceGeneration{1});
  AIFC_CHECK(harness.classify(key).classification.state == aifc::ClassificationState::CURRENT);

  AIFC_CHECK_OK(harness.classifier().end_publisher_session(peer.publisher, peer.boot));
  // The session is gone, so the incarnation is no longer live and nothing it published is
  // current -- but the record is marked, not deleted.
  const auto stored = harness.classifier().find_evidence(record.id);
  AIFC_CHECK_OK(stored);
  if (stored) {
    AIFC_CHECK_MSG(stored.value().state == aifc::EvidenceState::EVIDENCE_STALE,
                   "evidence from an ended session is " << aifc::to_string(stored.value().state)
                                                        << " rather than STALE");
    AIFC_CHECK_MSG(contains(stored.value().state_reason, peer.publisher.value()),
                   "the reason must name the publisher, got: " << stored.value().state_reason);
    AIFC_CHECK_MSG(contains(stored.value().state_reason, peer.boot.to_string()),
                   "the reason must name the boot incarnation, got: "
                       << stored.value().state_reason);
    AIFC_CHECK_MSG(contains(stored.value().state_reason, "session") &&
                       contains(stored.value().state_reason, "no longer current"),
                   "the reason must say the session ended, got: " << stored.value().state_reason);
  }

  const aifc::ClassificationResult after = harness.classify(key, aifc::FlowGeneration{}, true);
  AIFC_CHECK(after.classification.state == aifc::ClassificationState::STALE);
  AIFC_CHECK_MSG(after.classification.semantic == aifc::SemanticClass::UNKNOWN,
                 "evidence from an ended session must not keep a class published, but it "
                 "reported "
                     << aifc::to_string(after.classification.semantic));
  AIFC_CHECK_EQ(after.classification.confidence.to_decimal(), std::string("0.0000"));
  AIFC_CHECK_EQ(after.classification.citations.size(), std::size_t{1});
  if (after.classification.citations.size() == 1U) {
    const aifc::EvidenceCitation& citation = after.classification.citations[0];
    AIFC_CHECK(citation.disposition == aifc::EvidenceDisposition::STALE);
    AIFC_CHECK(citation.state == aifc::EvidenceState::EVIDENCE_STALE);
    AIFC_CHECK_MSG(contains(citation.detail, peer.publisher.value()) &&
                       contains(citation.detail, peer.boot.to_string()),
                   "the citation must name the publisher and boot, got: " << citation.detail);
  }

  // Further submissions from the closed session are refused: an ended session is not a way to
  // publish, and liveness is never inferred from the fact that a session once existed.
  const auto refused = harness.classifier().submit_evidence(
      peer.envelope, make_payload(flow, aifc::SemanticClass::TELEMETRY, aifc::EvidenceGeneration{2},
                                  aifc::EvidenceSource::DECLARED_AUTHENTICATED, "after-end.topic"));
  // The refusal is an authority failure.  The session binding is checked before liveness, so
  // a closed session is reported as UNAUTHENTICATED rather than PUBLISHER_DEAD; both are
  // truthful, and the property that matters is that the closed session cannot publish.
  AIFC_CHECK(!refused.ok());
  if (!refused) {
    AIFC_CHECK_MSG(refused.code() == aifc::ErrorCode::PUBLISHER_DEAD ||
                       refused.code() == aifc::ErrorCode::UNAUTHENTICATED,
                   "a closed session must be refused as an authority failure, got "
                       << aifc::to_string(refused.code()) << " (" << refused.status().message << ")");
    AIFC_CHECK(aifc::is_authority_failure(refused.code()));
  }

  // A new incarnation is a new session: it can publish again, and the previous incarnation's
  // declaration stays stale rather than being resurrected.
  const aifc_test::Harness::Peer restarted = harness.restart_peer(0U, aifc::PublisherBootId{2});
  const aifc::EvidenceRecord replacement = harness.publish(
      restarted, flow, aifc::SemanticClass::CHECKPOINT, aifc::EvidenceGeneration{1});
  const aifc::ClassificationResult recovered = harness.classify(key);
  AIFC_CHECK(recovered.classification.semantic == aifc::SemanticClass::CHECKPOINT);
  AIFC_CHECK(recovered.classification.state == aifc::ClassificationState::CURRENT);
  AIFC_CHECK_EQ(recovered.classification.selected_evidence.value(), replacement.id.value());
  AIFC_CHECK_EQ(recovered.classification.citations.size(), std::size_t{2});
  const auto old_record = harness.classifier().find_evidence(record.id);
  AIFC_CHECK_OK(old_record);
  if (old_record) {
    AIFC_CHECK_MSG(old_record.value().state == aifc::EvidenceState::EVIDENCE_STALE,
                   "the previous incarnation's evidence must stay STALE, but it is "
                       << aifc::to_string(old_record.value().state));
  }
  AIFC_CHECK_EQ(harness.classifier().find_publisher(peer.publisher).value().boot.value, 2U);
}
