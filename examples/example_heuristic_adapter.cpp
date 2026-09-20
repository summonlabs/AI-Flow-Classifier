// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Example: a heuristic adapter, and the three gates in front of it.
//
// A heuristic is a guess derived from observable metadata -- here, a destination port.  It is useful,
// and it is dangerous, because a port number is not a declaration.  This example shows the four things
// that must all be true before a guess can influence an answer:
//
//   1. the policy must permit heuristic evidence at all;
//   2. at least one adapter must be enabled by name in that policy;
//   3. the submission must cite a declared port hint, and that hint must name the enabled adapter;
//   4. the session must be admitted at or below the HEURISTIC ceiling.
//
// and it shows the fifth, most important thing: even when all four hold, a guess is subordinate.  It can
// never outrank a current authenticated declaration, and a guess that disagrees with a declaration is
// not a contradiction -- it is a guess that lost.

#include <ai_flow_classifier/ai_flow_classifier.hpp>

#include <cstdio>
#include <string>

namespace {

aifc::FlowKey example_flow(std::uint16_t remote_port) {
  aifc::FlowKey key;
  key.local_address = aifc::IpAddress::from_v4(0x0A000014U);   // 10.0.0.20
  key.remote_address = aifc::IpAddress::from_v4(0x0A000015U);  // 10.0.0.21
  key.local_port = 41000;
  key.remote_port = remote_port;
  key.transport = aifc::TransportProtocol::TCP;
  return key;
}

int report(const aifc::Status& status, const char* what) {
  std::fprintf(stderr, "%s failed: %s\n", what, aifc::render_status(status).c_str());
  return 1;
}

}  // namespace

int main() {
  // --- gate 1 and 2: a policy that explicitly permits one named adapter --------------
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.allow_heuristic_evidence = true;
  policy.heuristic_adapters.push_back(aifc::HeuristicAdapterPolicy{"port-hint", true, 2000, 1});
  policy.port_hints.push_back(aifc::PortHint{aifc::TransportProtocol::TCP, 29500,
                                             aifc::SemanticClass::INFERENCE_REQUEST, 1500,
                                             "port-hint"});
  auto canonical = aifc::ClassifierPolicy::canonicalize(std::move(policy));
  if (!canonical) return report(canonical.status(), "canonicalize policy");

  aifc::Classifier classifier(
      aifc::ClassifierOptions{canonical.value(), aifc::Logger{}, aifc::CoordinatorEpoch{1},
                              aifc::CoordinatorBootId{1}});

  // A policy that enables an adapter while heuristics are globally off is refused rather
  // than silently neutralised, because a policy that says two different things is a defect
  // the operator needs to see.  Show that here.
  {
    aifc::ClassifierPolicy contradictory = aifc::ClassifierPolicy::initial();
    contradictory.heuristic_adapters.push_back(
        aifc::HeuristicAdapterPolicy{"port-hint", true, 2000, 1});
    auto refused = aifc::ClassifierPolicy::canonicalize(std::move(contradictory));
    if (refused) {
      std::fprintf(stderr, "a contradictory policy was accepted; that is a defect\n");
      return 2;
    }
    std::printf("contradictory policy refused: %s\n", aifc::render_status(refused.status()).c_str());
  }

  // --- gate 3: the observer session is admitted at the HEURISTIC ceiling -------------
  const aifc::PublisherId observer = aifc::make_publisher_id("metadata-observer");
  auto registration = classifier.register_publisher(observer, aifc::PublisherBootId{1},
                                                    aifc::EvidenceSource::HEURISTIC,
                                                    aifc::SessionId("session-observer"),
                                                    "heuristic observer");
  if (!registration) return report(registration.status(), "register_publisher observer");
  const aifc::SessionEnvelope observer_envelope = aifc::make_session_envelope(registration.value(), 0);

  const aifc::FlowKey key = example_flow(29500);
  auto flow = classifier.register_flow(key, aifc::FlowGeneration{0}, aifc::SessionId("example"));
  if (!flow) return report(flow.status(), "register_flow");

  aifc::EvidencePayload guess;
  guess.flow_key = key;
  guess.flow_generation = flow.value().record.generation;
  guess.evidence_generation = aifc::EvidenceGeneration{1};
  guess.semantic = aifc::SemanticClass::INFERENCE_REQUEST;
  // The observer asks for the strongest source it can name.  The session ceiling reduces it,
  // and the reduction is reported rather than applied quietly.
  guess.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  guess.metadata.topic = "port.hint";
  guess.metadata.reason = "destination port 29500 resembles an inference service";
  // The submission cites the declared hint it is claiming to have observed.  Without this the
  // coordinator refuses it: a submission that names no hint is indistinguishable from a peer asking to
  // be believed on its own word, which is the one thing this runtime never does.
  guess.metadata.binding =
      aifc::ClassifierPolicy::hint_binding_of(aifc::TransportProtocol::TCP, 29500U);
  auto submitted = classifier.submit_evidence(observer_envelope, guess);
  if (!submitted) return report(submitted.status(), "submit_evidence heuristic");
  std::printf("effective source %s\n",
              std::string(aifc::to_string(submitted.value().effective_source)).c_str());
  for (const std::string& note : submitted.value().notes) {
    std::printf("note: %s\n", note.c_str());
  }
  if (submitted.value().effective_source != aifc::EvidenceSource::HEURISTIC) {
    std::fprintf(stderr, "the session ceiling did not reduce the claimed source\n");
    return 2;
  }

  // A guess alone is not enough to publish a class.  This is the behaviour that keeps
  // "UNKNOWN" honest: weak data does not promote a flow.
  {
    aifc::ClassificationQuery query;
    query.flow_key = key;
    query.explain = true;
    auto classified = classifier.classify(query);
    if (!classified) return report(classified.status(), "classify heuristic only");
    std::printf("%s\n", classified.value().explanation.c_str());
    if (classified.value().classification.semantic != aifc::SemanticClass::UNKNOWN) {
      std::fprintf(stderr, "a heuristic alone produced a published class; that is a defect\n");
      return 2;
    }
  }

  // --- the declaration arrives and outranks the guess --------------------------------
  const aifc::PublisherId owner = aifc::make_publisher_id("serving-node-1");
  auto owner_registration = classifier.register_publisher(
      owner, aifc::PublisherBootId{1}, aifc::EvidenceSource::DECLARED_AUTHENTICATED,
      aifc::SessionId("session-serving-node-1"), "serving node");
  if (!owner_registration) return report(owner_registration.status(), "register_publisher owner");
  const aifc::SessionEnvelope owner_envelope =
      aifc::make_session_envelope(owner_registration.value(), 0);

  aifc::EvidencePayload declaration;
  declaration.flow_key = key;
  declaration.flow_generation = flow.value().record.generation;
  declaration.evidence_generation = aifc::EvidenceGeneration{1};
  // Deliberately a different class from the guess, so the example proves which one wins.
  declaration.semantic = aifc::SemanticClass::PREFILL_DECODE_HANDOFF;
  declaration.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  declaration.metadata.topic = "rank.declaration";
  declaration.metadata.reason = "the prefiller opened this flow to hand off to the decoder";
  auto declared = classifier.submit_evidence(owner_envelope, declaration);
  if (!declared) return report(declared.status(), "submit_evidence declaration");

  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.explain = true;
  auto classified = classifier.classify(query);
  if (!classified) return report(classified.status(), "classify with declaration");
  std::printf("%s\n", classified.value().explanation.c_str());

  const aifc::Classification& result = classified.value().classification;
  if (result.semantic != aifc::SemanticClass::PREFILL_DECODE_HANDOFF) {
    std::fprintf(stderr, "the authenticated declaration did not win: got %s\n",
                 std::string(aifc::to_string(result.semantic)).c_str());
    return 2;
  }
  if (!result.contradictions.empty()) {
    std::fprintf(stderr,
                 "a heuristic disagreement was reported as a contradiction; a guess that "
                 "loses is not a contradiction\n");
    return 2;
  }
  std::printf("example_heuristic_adapter: OK\n");
  return 0;
}
