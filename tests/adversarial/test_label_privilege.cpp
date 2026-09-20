// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The central adversarial claim of this project: a malformed label cannot produce a
// privileged semantic class.
//
// Capability labels
// -----------------
//   REAL        Classifier::submit_evidence, Classifier::classify and the strict label
//               parsers, driven exactly as a coordinator drives them.  There is no
//               stand-in for the classifier anywhere in this file.
//   SYNTHETIC   every publisher, workload, contract, flow and payload.  Nothing here
//               was observed on a real fabric; what is real is the runtime's behaviour.
//   UNSUPPORTED nothing is stubbed or skipped.
//
// What "privileged" means here, stated before it is used.  This runtime has no notion
// of a class being higher than another class -- a semantic class is a description, not a
// verdict.  "Privileged" therefore means: a class that the admissible evidence did not
// legitimately declare.  Every case below asserts the same shape --
//
//     the reported class is the class of an admissible record, or UNKNOWN
//
// -- and never merely that some particular attack string was rejected.  The companion
// claim, that a session admitted at a low authority ceiling can never make its evidence
// look authoritative, is asserted on the citation and not on the label: the label is
// content, the source is authority.

#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "ai_flow_classifier/foundation/text.hpp"
#include "synthetic.hpp"
#include "test_framework.hpp"

namespace {

using aifc::ByteBuffer;
using aifc::ClassificationResult;
using aifc::ErrorCode;
using aifc::EvidenceSource;
using aifc::SemanticClass;
// The port a synthetic heuristic submission cites, and the value that travels in the record's
// opaque binding field as (transport << 16) | port.  It must match a hint the policy declares.
constexpr std::uint16_t kHeuristicPort = 8443U;

// A policy that admits heuristic evidence.  Without this switch, heuristic submissions
// are refused with HEURISTIC_DISABLED, which would hide the clamping behaviour this file
// exists to prove.
[[nodiscard]] aifc::ClassifierPolicy heuristic_policy() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.allow_heuristic_evidence = true;
  policy.allow_heuristic_evidence = true;
  // A heuristic submission must cite a declared, enabled hint: the runtime refuses a
  // heuristic observation that names no usable hint, which is what makes "an adapter must be
  // enabled by name" an enforced rule rather than a documented intention.  The policy below
  // declares one adapter and one port hint so that heuristic evidence can legitimately enter.
  aifc::HeuristicAdapterPolicy adapter;
  adapter.name = "synthetic.adapter";
  adapter.enabled = true;
  adapter.max_basis_points = 2000U;
  adapter.priority = 0;
  policy.heuristic_adapters.push_back(adapter);
  aifc::PortHint hint;
  hint.transport = aifc::TransportProtocol::TCP;
  hint.port = kHeuristicPort;
  hint.semantic = aifc::SemanticClass::SHUFFLE;
  hint.basis_points = 500U;
  hint.adapter = "synthetic.adapter";
  policy.port_hints.push_back(hint);
  (void)0;
  return policy;
}


// How a heuristic submission cites the hint it claims: the claim travels in the record's
// opaque binding field as (transport << 16) | port.  The hint must be declared by the policy
// and must name an adapter the policy enables.
[[nodiscard]] std::uint64_t heuristic_binding() {
  return static_cast<std::uint64_t>(kHeuristicPort) |
         (static_cast<std::uint64_t>(aifc::TransportProtocol::TCP) << 16U);
}

// Renders a classification for a failure message: the class, the state, the source and
// every citation, so a failure can be diagnosed without re-running the case.
[[nodiscard]] std::string describe(const ClassificationResult& result) {
  std::string out;
  out += "class=";
  out += aifc::to_string(result.classification.semantic);
  out += " state=";
  out += aifc::to_string(result.classification.state);
  out += " confidence=";
  out += result.classification.confidence.to_decimal();
  out += " selected_source=";
  out += aifc::to_string(result.classification.selected_source);
  out += " selected_evidence=";
  out += result.classification.selected_evidence.empty()
             ? std::string("<none>")
             : result.classification.selected_evidence.value();
  out += " citations=";
  out += std::to_string(result.classification.citations.size());
  for (const aifc::EvidenceCitation& citation : result.classification.citations) {
    out += " [";
    out += citation.id.value();
    out += " pub=";
    out += citation.publisher.value();
    out += " source=";
    out += aifc::to_string(citation.source);
    out += " state=";
    out += aifc::to_string(citation.state);
    out += " class=";
    out += aifc::to_string(citation.semantic);
    out += " disposition=";
    out += aifc::to_string(citation.disposition);
    out += "]";
  }
  return out;
}

// The assertion every case in this file is built on: the reported class must be the
// class of admissible evidence, or UNKNOWN.  Naming the admissible set explicitly is
// what makes "a class the evidence did not declare" detectable.
void expect_class_is_admissible(const ClassificationResult& result,
                                const std::vector<SemanticClass>& admissible,
                                const std::string& context) {
  const SemanticClass actual = result.classification.semantic;
  if (actual == SemanticClass::UNKNOWN) return;
  for (const SemanticClass allowed : admissible) {
    if (actual == allowed) return;
  }
  std::string allowed_text;
  for (const SemanticClass allowed : admissible) {
    if (!allowed_text.empty()) allowed_text += ", ";
    allowed_text += aifc::to_string(allowed);
  }
  AIFC_FAIL(context << ": the reported class " << aifc::to_string(actual)
                    << " is not UNKNOWN and was not declared by any admissible record ["
                    << allowed_text << "]; " << describe(result));
}

// True when the classification reports a class as current authority.  "Current" here
// means the state the decision engine uses for a class that may be acted on now.
[[nodiscard]] bool reports_current_class(const ClassificationResult& result) {
  switch (result.classification.state) {
    case aifc::ClassificationState::CURRENT:
    case aifc::ClassificationState::CORROBORATED:
    case aifc::ClassificationState::CONTRADICTED:
      return true;
    default:
      return false;
  }
}

[[nodiscard]] aifc::EvidencePayload payload_for(const aifc::FlowRecord& flow,
                                               SemanticClass semantic,
                                               aifc::EvidenceGeneration generation,
                                               EvidenceSource claimed,
                                               const std::string& topic) {
  aifc::EvidencePayload payload;
  payload.flow_key = flow.key;
  payload.flow_generation = flow.generation;
  payload.evidence_generation = generation;
  payload.semantic = semantic;
  payload.claimed_source = claimed;
  payload.metadata.topic = topic;
  payload.metadata.reason = "adversarial synthetic payload";
  payload.metadata.binding = heuristic_binding();
  return payload;
}

}  // namespace

AIFC_TEST("label privilege: a near-miss label is refused and never becomes a class") {
  // Every one of these is a label a peer could put on the wire.  None of them may be
  // accepted as a class, and none of them may turn into UNKNOWN by accident either:
  // UNKNOWN is a legitimate classification and must not be reachable by misspelling.
  const std::string near_misses[] = {std::string(),
                                     "collective",
                                     "Collective",
                                     "COLLECTIVE ",
                                     " COLLECTIVE",
                                     "COLLECTIV",
                                     "COLLECTIVEE",
                                     "COLLECTIVE\n",
                                     "COLLECTIVE\r\n",
                                     "COLLECTIVE\t",
                                     "COLLECTIVE\x01",
                                     "UNKNOWN ",
                                     "unknown",
                                     std::string("COLLECTIVE\0", 11U),
                                     std::string("\xFF\xFE", 2U),
                                     std::string(600U, 'X')};
  for (const std::string& label : near_misses) {
    auto parsed = aifc::parse_semantic_class(label);
    if (parsed) {
      AIFC_FAIL("near-miss label ["
                << label << "] was accepted as " << aifc::to_string(parsed.value())
                << "; a label that is not exactly a canonical class name must be refused, "
                   "because accepting it would let a typo promote a flow");
      continue;
    }
    if (parsed.code() != ErrorCode::MALFORMED_INPUT) {
      AIFC_FAIL("near-miss label [" << label << "] was refused with " << aifc::to_string(parsed.code())
                                    << " rather than MALFORMED_INPUT");
    }
  }

  // The canonical names themselves are accepted, so the refusals above are about the
  // label and not about the parser refusing everything.
  for (const SemanticClass value : aifc::all_builtin_classes()) {
    const std::string name(aifc::to_string(value));
    auto parsed = aifc::parse_semantic_class(name);
    AIFC_CHECK_MSG(parsed.ok(), "the canonical name [" << name << "] must parse: "
                                                      << aifc::render_status(parsed.status()));
    if (parsed) {
      AIFC_CHECK_MSG(parsed.value() == value, "the canonical name [" << name << "] parsed as "
                                                                     << aifc::to_string(parsed.value()));
    }
  }

  // A numeric code this build does not know decodes to UNKNOWN.  It must never decode to
  // a built-in class the peer did not name.
  for (std::uint32_t code = 12U; code < 4096U; ++code) {
    const auto decoded = aifc::decode_semantic_class(static_cast<std::uint16_t>(code));
    AIFC_CHECK_MSG(decoded.ok(), "code " << code << " must decode: "
                                        << aifc::render_status(decoded.status()));
    if (!decoded) continue;
    AIFC_CHECK_MSG(decoded.value() == SemanticClass::UNKNOWN,
                   "unknown numeric class code " << code << " decoded to "
                                                 << aifc::to_string(decoded.value())
                                                 << " instead of UNKNOWN");
  }
  const std::uint16_t high_codes[] = {0x1000U, 0x7FFFU, 0x8000U, 0xFFFEU, 0xFFFFU};
  for (const std::uint16_t code : high_codes) {
    const auto decoded = aifc::decode_semantic_class(code);
    AIFC_CHECK_MSG(decoded.ok() && decoded.value() == SemanticClass::UNKNOWN,
                   "unknown numeric class code " << code << " decoded to something other than "
                                                    "UNKNOWN");
  }
}

AIFC_TEST("label privilege: a hostile class code submitted through the real path cannot decide") {
  aifc_test::Harness harness;
  const aifc_test::Harness::Peer peer =
      harness.add_peer(0U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc::WorkloadRecord workload = harness.declare_workload(peer, 0U);
  const aifc::WorkloadContract contract =
      harness.activate_contract(peer, workload, 0U, SemanticClass::COLLECTIVE);
  (void)contract;
  const aifc::FlowRecord flow = harness.register_flow(peer, 0U);

  // Legitimate, admissible evidence: this is the only class any case below may report.
  harness.publish(peer, flow, SemanticClass::TRAINING_SYNC, aifc::EvidenceGeneration{1},
                  EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.1", 0, &workload);
  {
    const ClassificationResult baseline = harness.classify(flow.key, flow.generation, true);
    expect_class_is_admissible(baseline, {SemanticClass::TRAINING_SYNC}, "baseline classification");
    AIFC_CHECK_MSG(baseline.classification.semantic == SemanticClass::TRAINING_SYNC,
                   "the legitimate declaration must decide the flow: " << describe(baseline));
  }

  const std::uint64_t evidence_before = harness.classifier().stats().evidence.records;

  // The attack: a numeric class code this build does not know, taken through the wire
  // codec exactly as a peer would send it and then submitted through the real path.
  const std::uint16_t hostile_codes[] = {12U, 13U, 17U, 255U, 256U, 257U, 1000U, 0x8000U, 0xFFFFU};
  for (const std::uint16_t code : hostile_codes) {
    aifc::PublishEvidenceRequest request;
    request.payload = payload_for(flow, static_cast<SemanticClass>(code),
                                  aifc::EvidenceGeneration{static_cast<std::uint64_t>(code) + 10U},
                                  EvidenceSource::DECLARED_AUTHENTICATED,
                                  "adversarial.topic.code." + std::to_string(code));
    request.payload.workload = workload.id;
    request.payload.workload_generation = workload.generation;
    ByteBuffer wire;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(request, wire));
    auto decoded = aifc::decode_publish_evidence(wire, aifc::CodecLimits{});
    AIFC_CHECK_MSG(decoded.ok(), "the wire form of class code " << code
                                                               << " must decode: "
                                                               << aifc::render_status(decoded.status()));
    if (!decoded) continue;
    AIFC_CHECK_MSG(decoded.value().payload.semantic == SemanticClass::UNKNOWN,
                   "class code " << code << " decoded to "
                                 << aifc::to_string(decoded.value().payload.semantic)
                                 << " instead of UNKNOWN");

    const auto submitted = harness.classifier().submit_evidence(peer.envelope, decoded.value().payload);
    if (submitted) {
      AIFC_FAIL("a payload whose class decoded from unknown code "
                << code << " was accepted as evidence of class "
                << aifc::to_string(submitted.value().record.semantic)
                << "; UNKNOWN is not a declaration and must be refused");
      continue;
    }
    AIFC_CHECK_MSG(submitted.code() == ErrorCode::INVALID_ARGUMENT,
                   "a payload whose class decoded from unknown code " << code
                                                                     << " was refused with "
                                                                     << aifc::to_string(submitted.code())
                                                                     << " rather than INVALID_ARGUMENT");
  }

  // A payload that declares UNKNOWN directly is refused for the same reason.
  {
    const auto submitted = harness.classifier().submit_evidence(
        peer.envelope, payload_for(flow, SemanticClass::UNKNOWN, aifc::EvidenceGeneration{500U},
                                   EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.unknown"));
    AIFC_CHECK_MSG(!submitted.ok(), "declaring UNKNOWN as evidence must be refused");
    if (!submitted) {
      AIFC_CHECK_MSG(submitted.code() == ErrorCode::INVALID_ARGUMENT,
                     "declaring UNKNOWN as evidence was refused with "
                         << aifc::to_string(submitted.code()) << " rather than INVALID_ARGUMENT");
    }
  }

  AIFC_CHECK_EQ(harness.classifier().stats().evidence.records, evidence_before);
  const ClassificationResult after = harness.classify(flow.key, flow.generation, true);
  expect_class_is_admissible(after, {SemanticClass::TRAINING_SYNC, SemanticClass::COLLECTIVE},
                             "after nine hostile class codes");
  AIFC_CHECK_MSG(after.classification.semantic == SemanticClass::TRAINING_SYNC,
                 "the hostile submissions must not have disturbed the legitimate decision: "
                     << describe(after));
}

AIFC_TEST("label privilege: a claimed source above the session ceiling is reduced, never granted") {
  aifc_test::Harness harness(heuristic_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U, EvidenceSource::HEURISTIC);
  const aifc::FlowRecord flow = harness.register_flow(peer, 0U);

  // The peer claims the strongest source there is.  The ceiling its session was admitted
  // at is HEURISTIC, and nothing in the payload can raise it.
  const aifc::EvidencePayload payload =
      payload_for(flow, SemanticClass::INFERENCE_REQUEST, aifc::EvidenceGeneration{1},
                  EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.ceiling");
  const auto submitted = harness.classifier().submit_evidence(peer.envelope, payload);
  AIFC_CHECK_MSG(submitted.ok(), "heuristic evidence is admissible under this policy: "
                                     << aifc::render_status(submitted.status()));
  if (!submitted) return;

  AIFC_CHECK_MSG(submitted.value().effective_source == EvidenceSource::HEURISTIC,
                 "the effective source is "
                     << aifc::to_string(submitted.value().effective_source)
                     << " but the session ceiling is HEURISTIC; a peer must never be able to raise "
                        "its own source");
  AIFC_CHECK_MSG(aifc::source_rank(submitted.value().record.source) <=
                     aifc::source_rank(EvidenceSource::HEURISTIC),
                 "the stored record carries rank "
                     << static_cast<unsigned>(aifc::source_rank(submitted.value().record.source))
                     << ", above the HEURISTIC ceiling");
  bool noted_reduction = false;
  for (const std::string& note : submitted.value().notes) {
    if (note.find("DECLARED_AUTHENTICATED") != std::string::npos &&
        note.find("HEURISTIC") != std::string::npos) {
      noted_reduction = true;
    }
  }
  AIFC_CHECK_MSG(noted_reduction,
                 "the reduction of the claimed source must be reported to the caller; notes="
                     << submitted.value().notes.size());

  const ClassificationResult result = harness.classify(flow.key, flow.generation, true);
  AIFC_CHECK_MSG(result.classification.selected_source != EvidenceSource::DECLARED_AUTHENTICATED,
                 "a HEURISTIC session produced a DECLARED_AUTHENTICATED decision: "
                     << describe(result));
  for (const aifc::EvidenceCitation& citation : result.classification.citations) {
    if (citation.publisher != peer.publisher) continue;
    AIFC_CHECK_MSG(citation.source == EvidenceSource::HEURISTIC,
                   "a citation of the HEURISTIC session reports source "
                       << aifc::to_string(citation.source));
    AIFC_CHECK_MSG(citation.disposition == aifc::EvidenceDisposition::SUBORDINATE,
                   "a heuristic citation is reported as "
                       << aifc::to_string(citation.disposition)
                       << "; heuristic evidence is never decisive");
  }
  AIFC_CHECK_MSG(!reports_current_class(result),
                 "heuristic evidence alone must not produce a current class: " << describe(result));
  expect_class_is_admissible(result, {}, "heuristic only");
  AIFC_CHECK_MSG(result.classification.semantic == SemanticClass::UNKNOWN,
                 "heuristic evidence alone reports " << aifc::to_string(result.classification.semantic)
                                                     << " instead of UNKNOWN; a guess is not truth");
  AIFC_CHECK_MSG(result.explanation.find("DECLARED_AUTHENTICATED") == std::string::npos,
                 "the explanation of a heuristic-only decision mentions "
                 "DECLARED_AUTHENTICATED, which the session was never entitled to: "
                     << result.explanation);
}

AIFC_TEST("label privilege: a session admitted as HEURISTIC can never cause a "
          "DECLARED_AUTHENTICATED citation") {
  aifc_test::Harness harness(heuristic_policy());
  const aifc_test::Harness::Peer guesser = harness.add_peer(0U, EvidenceSource::HEURISTIC);
  const aifc_test::Harness::Peer declarer =
      harness.add_peer(1U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc::WorkloadRecord workload = harness.declare_workload(declarer, 1U);
  const aifc::FlowRecord flow = harness.register_flow(declarer, 1U);

  // The guesser asserts a class, claiming the strongest possible source.  Its class is
  // deliberately different from the declaration that follows, so that a promotion would
  // be visible as a class change and not only as a source change.
  const auto guessed = harness.classifier().submit_evidence(
      guesser.envelope,
      payload_for(flow, SemanticClass::INFERENCE_REQUEST, aifc::EvidenceGeneration{1},
                  EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.guess"));
  AIFC_CHECK_MSG(guessed.ok(), "the heuristic submission must be recorded, not dropped: "
                                   << aifc::render_status(guessed.status()));
  if (!guessed) return;
  AIFC_CHECK_MSG(guessed.value().record.source == EvidenceSource::HEURISTIC,
                 "the guesser's record carries source "
                     << aifc::to_string(guessed.value().record.source));

  {
    const ClassificationResult only_guess = harness.classify(flow.key, flow.generation, true);
    AIFC_CHECK_MSG(only_guess.classification.selected_source != EvidenceSource::DECLARED_AUTHENTICATED,
                   "a HEURISTIC session caused a DECLARED_AUTHENTICATED citation: "
                       << describe(only_guess));
    expect_class_is_admissible(only_guess, {}, "the guesser alone");
    AIFC_CHECK_MSG(only_guess.classification.semantic == SemanticClass::UNKNOWN,
                   "the guess alone reports " << aifc::to_string(only_guess.classification.semantic)
                                              << " instead of UNKNOWN: " << describe(only_guess));
  }

  // Now the authenticated declaration arrives.  It must win, and the guess must be
  // reported as subordinate -- not as corroboration and not as a contradiction, because a
  // guess disagreeing with a declaration is not a contradiction, it is a guess that lost.
  harness.publish(declarer, flow, SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                  EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.declaration", 0,
                  &workload);
  const ClassificationResult both = harness.classify(flow.key, flow.generation, true);
  AIFC_CHECK_MSG(both.classification.semantic == SemanticClass::COLLECTIVE,
                 "the authenticated declaration must win: " << describe(both));
  AIFC_CHECK_MSG(both.classification.selected_source == EvidenceSource::DECLARED_AUTHENTICATED,
                 "the authenticated declaration must be the selected source: " << describe(both));
  AIFC_CHECK_MSG(both.classification.contradictions.empty(),
                 "a heuristic guess was recorded as a contradiction: " << describe(both));
  bool saw_guesser = false;
  for (const aifc::EvidenceCitation& citation : both.classification.citations) {
    if (citation.publisher != guesser.publisher) continue;
    saw_guesser = true;
    AIFC_CHECK_MSG(citation.source == EvidenceSource::HEURISTIC,
                   "the guesser's citation reports source " << aifc::to_string(citation.source));
    AIFC_CHECK_MSG(citation.disposition == aifc::EvidenceDisposition::SUBORDINATE,
                   "the guesser's citation is reported as "
                       << aifc::to_string(citation.disposition) << " rather than SUBORDINATE");
  }
  AIFC_CHECK_MSG(saw_guesser, "the guess must still be cited, so that the decision is "
                              "explicable: "
                                  << describe(both));
  expect_class_is_admissible(both, {SemanticClass::COLLECTIVE}, "declaration plus guess");
}

AIFC_TEST("label privilege: a label the session is not entitled to cannot attach to a flow") {
  aifc_test::Harness harness;
  const aifc_test::Harness::Peer owner = harness.add_peer(0U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc_test::Harness::Peer stranger =
      harness.add_peer(1U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc::WorkloadRecord owned = harness.declare_workload(owner, 0U);
  const aifc::WorkloadContract contract =
      harness.activate_contract(owner, owned, 0U, SemanticClass::CHECKPOINT);
  const aifc::FlowRecord flow = harness.register_flow(owner, 0U);

  const std::uint64_t evidence_before = harness.classifier().stats().evidence.records;

  // The stranger tries to borrow the owner's workload, the owner's contract, and an
  // undeclared workload.  Each attempt names a class the stranger would like to attach to
  // the flow; none of them may attach.
  {
    aifc::EvidencePayload payload =
        payload_for(flow, SemanticClass::STORAGE_DATA, aifc::EvidenceGeneration{1},
                    EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.borrow.workload");
    payload.workload = owned.id;
    payload.workload_generation = owned.generation;
    const auto submitted = harness.classifier().submit_evidence(stranger.envelope, payload);
    AIFC_CHECK_MSG(!submitted.ok(),
                   "a stranger's evidence naming another publisher's workload was accepted");
    if (!submitted) {
      AIFC_CHECK_MSG(submitted.code() == ErrorCode::UNAUTHORIZED,
                     "borrowing a workload was refused with " << aifc::to_string(submitted.code())
                                                              << " rather than UNAUTHORIZED");
    }
  }
  {
    aifc::EvidencePayload payload =
        payload_for(flow, SemanticClass::STORAGE_DATA, aifc::EvidenceGeneration{2},
                    EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.borrow.contract");
    payload.contract = contract.id;
    const auto submitted = harness.classifier().submit_evidence(stranger.envelope, payload);
    AIFC_CHECK_MSG(!submitted.ok(),
                   "a stranger's evidence citing another publisher's contract was accepted");
    if (!submitted) {
      AIFC_CHECK_MSG(submitted.code() == ErrorCode::UNAUTHORIZED,
                     "citing a foreign contract was refused with "
                         << aifc::to_string(submitted.code()) << " rather than UNAUTHORIZED");
    }
  }
  {
    aifc::EvidencePayload payload =
        payload_for(flow, SemanticClass::STORAGE_DATA, aifc::EvidenceGeneration{3},
                    EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.borrow.nothing");
    payload.workload = aifc_test::synthetic_workload(99U);
    payload.workload_generation = aifc::WorkloadGeneration{1};
    const auto submitted = harness.classifier().submit_evidence(stranger.envelope, payload);
    AIFC_CHECK_MSG(!submitted.ok(), "evidence naming an undeclared workload was accepted");
    if (!submitted) {
      AIFC_CHECK_MSG(submitted.code() == ErrorCode::UNKNOWN_WORKLOAD,
                     "naming an undeclared workload was refused with "
                         << aifc::to_string(submitted.code()) << " rather than UNKNOWN_WORKLOAD");
    }
  }
  // Generation fencing applies to the owner as well: a workload generation that is not the
  // current one is not a statement about anything.  (The stranger's version of this attempt
  // is refused earlier, on ownership, which is why it is asserted with the owner's own
  // envelope.)
  {
    aifc::EvidencePayload payload =
        payload_for(flow, SemanticClass::STORAGE_DATA, aifc::EvidenceGeneration{4},
                    EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.borrow.generation");
    payload.workload = owned.id;
    payload.workload_generation = aifc::WorkloadGeneration{7};
    const auto submitted = harness.classifier().submit_evidence(owner.envelope, payload);
    AIFC_CHECK_MSG(!submitted.ok(),
                   "evidence naming a workload generation that is not current was accepted");
    if (!submitted) {
      AIFC_CHECK_MSG(submitted.code() == ErrorCode::STALE_GENERATION,
                     "a workload generation mismatch was refused with "
                         << aifc::to_string(submitted.code()) << " rather than STALE_GENERATION");
    }
  }
  // The same attempt from the stranger is an ownership failure, not a generation failure:
  // the runtime reports the first reason that applies.
  {
    aifc::EvidencePayload payload =
        payload_for(flow, SemanticClass::STORAGE_DATA, aifc::EvidenceGeneration{5},
                    EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.borrow.generation2");
    payload.workload = owned.id;
    payload.workload_generation = aifc::WorkloadGeneration{7};
    const auto submitted = harness.classifier().submit_evidence(stranger.envelope, payload);
    AIFC_CHECK_MSG(!submitted.ok(),
                   "a stranger naming another publisher's workload generation was accepted");
    if (!submitted) {
      AIFC_CHECK_MSG(submitted.code() == ErrorCode::UNAUTHORIZED,
                     "a stranger naming a foreign workload was refused with "
                         << aifc::to_string(submitted.code()) << " rather than UNAUTHORIZED");
    }
  }

  AIFC_CHECK_EQ(harness.classifier().stats().evidence.records, evidence_before);
  const ClassificationResult result = harness.classify(flow.key, flow.generation, true);
  // The only admissible statement about this flow is the owner's active contract, which
  // declares CHECKPOINT.  STORAGE_DATA was never legitimately declared by anything.
  expect_class_is_admissible(result, {SemanticClass::CHECKPOINT}, "borrowed labels");
  AIFC_CHECK_MSG(result.classification.semantic != SemanticClass::STORAGE_DATA,
                 "a label the session was not entitled to was reported: " << describe(result));
}

AIFC_TEST("label privilege: hostile payload text cannot reach the classifier at all") {
  aifc_test::Harness harness;
  const aifc_test::Harness::Peer peer = harness.add_peer(0U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc::FlowRecord flow = harness.register_flow(peer, 0U);
  const std::uint64_t evidence_before = harness.classifier().stats().evidence.records;

  // A control character in a publisher supplied reason: refused by the wire codec, so the
  // classifier never sees it.  The point of asserting the count is that "never reached the
  // classifier" is checked rather than assumed.
  {
    aifc::PublishEvidenceRequest request;
    request.payload = payload_for(flow, SemanticClass::CHECKPOINT, aifc::EvidenceGeneration{1},
                                 EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.control");
    request.payload.metadata.reason = std::string("line one\nline two");
    ByteBuffer wire;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(request, wire));
    AIFC_CHECK_ERR(aifc::decode_publish_evidence(wire, aifc::CodecLimits{}),
                   ErrorCode::MALFORMED_RECORD);
  }

  // An over-long topic: the codec bound refuses it before any record is built.
  {
    aifc::PublishEvidenceRequest request;
    request.payload = payload_for(flow, SemanticClass::CHECKPOINT, aifc::EvidenceGeneration{2},
                                 EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.long");
    request.payload.metadata.topic = std::string(aifc::kMaxStringBytes + 1U, 'T');
    ByteBuffer wire;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(request, wire));
    AIFC_CHECK_ERR(aifc::decode_publish_evidence(wire, aifc::CodecLimits{}),
                   ErrorCode::CAPACITY_EXCEEDED);
  }

  AIFC_CHECK_EQ(harness.classifier().stats().evidence.records, evidence_before);
  const ClassificationResult result = harness.classify(flow.key, flow.generation, true);
  AIFC_CHECK_MSG(result.classification.semantic == SemanticClass::UNKNOWN,
                 "no admissible evidence exists for this flow, so the answer must be UNKNOWN but "
                 "was " << describe(result));
  AIFC_CHECK_MSG(!reports_current_class(result),
                 "a flow with no admissible evidence reported a current class: " << describe(result));
}

AIFC_TEST("label privilege: two authenticated declarations cannot produce a third class") {
  aifc_test::Harness harness;
  const aifc_test::Harness::Peer left = harness.add_peer(0U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc_test::Harness::Peer right = harness.add_peer(1U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc::FlowRecord flow = harness.register_flow(left, 0U);

  harness.publish(left, flow, SemanticClass::TRAINING_SYNC, aifc::EvidenceGeneration{1},
                  EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.left");
  harness.publish(right, flow, SemanticClass::SHUFFLE, aifc::EvidenceGeneration{1},
                  EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.right");

  const ClassificationResult result = harness.classify(flow.key, flow.generation, true);
  expect_class_is_admissible(result, {SemanticClass::TRAINING_SYNC, SemanticClass::SHUFFLE},
                             "two authenticated declarations");
  AIFC_CHECK_MSG(result.classification.state == aifc::ClassificationState::CONTRADICTED,
                 "two disagreeing authenticated declarations must be reported as a contradiction: "
                     << describe(result));
  AIFC_CHECK_MSG(result.classification.contradictions.size() == 1U,
                 "expected exactly one contradiction, got "
                     << result.classification.contradictions.size() << ": " << describe(result));
  AIFC_CHECK_MSG(result.classification.applied_penalty_basis_points != 0U,
                 "the contradiction penalty must be reported: " << describe(result));
}

AIFC_TEST("label privilege: an authenticated session cannot declare a class above its ceiling") {
  // The class content of a declaration is the peer's to choose; what the ceiling bounds is
  // the *source*, and therefore whether the class can be reported as current.  This case
  // asserts both halves: the source is clamped, and a clamped source can never be cited as
  // the strongest one.
  aifc_test::Harness harness;
  const aifc_test::Harness::Peer peer =
      harness.add_peer(0U, EvidenceSource::TOPOLOGY_CORRELATED);
  const aifc::FlowRecord flow = harness.register_flow(peer, 0U);

  const auto submitted = harness.classifier().submit_evidence(
      peer.envelope,
      payload_for(flow, SemanticClass::MODEL_STATE_TRANSFER, aifc::EvidenceGeneration{1},
                  EvidenceSource::DECLARED_AUTHENTICATED, "adversarial.topic.topology"));
  AIFC_CHECK_MSG(submitted.ok(), "the submission must be admitted at the ceiling: "
                                     << aifc::render_status(submitted.status()));
  if (!submitted) return;
  AIFC_CHECK_MSG(submitted.value().effective_source == EvidenceSource::TOPOLOGY_CORRELATED,
                 "the effective source is "
                     << aifc::to_string(submitted.value().effective_source)
                     << " but the session ceiling is TOPOLOGY_CORRELATED");
  AIFC_CHECK_MSG(aifc::source_rank(submitted.value().record.source) <=
                     aifc::source_rank(EvidenceSource::TOPOLOGY_CORRELATED),
                 "the record's source rank is "
                     << static_cast<unsigned>(aifc::source_rank(submitted.value().record.source))
                     << ", above the ceiling rank");

  const ClassificationResult result = harness.classify(flow.key, flow.generation, true);
  AIFC_CHECK_MSG(result.classification.selected_source == EvidenceSource::TOPOLOGY_CORRELATED,
                 "the decision must be attributed to the ceiling source: " << describe(result));
  AIFC_CHECK_MSG(result.classification.selected_source != EvidenceSource::DECLARED_AUTHENTICATED,
                 "a TOPOLOGY_CORRELATED session produced a DECLARED_AUTHENTICATED decision: "
                     << describe(result));
  for (const aifc::EvidenceCitation& citation : result.classification.citations) {
    AIFC_CHECK_MSG(aifc::source_rank(citation.source) <=
                       aifc::source_rank(EvidenceSource::TOPOLOGY_CORRELATED),
                   "a citation reports source " << aifc::to_string(citation.source)
                                                << ", above the session ceiling");
  }
  expect_class_is_admissible(result, {SemanticClass::MODEL_STATE_TRANSFER}, "ceiling clamp");
}
