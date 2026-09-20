// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Example: two authenticated publishers disagree, and the runtime says so.
//
// The point of this example is what the runtime does *not* do.  It does not average the
// two declarations into a third class, it does not drop the weaker one, and it does not
// pretend the disagreement is not there.  It reports the class of the precedence winner,
// cites both records, lists the contradiction, and applies the configured, reported
// penalty.  An operator who sees CONTRADICTED knows the fabric is telling two different
// stories and can go and look.

#include <ai_flow_classifier/ai_flow_classifier.hpp>

#include <cstdio>
#include <string>

namespace {

aifc::FlowKey example_flow() {
  aifc::FlowKey key;
  key.local_address = aifc::IpAddress::from_v4(0x0A00000AU);   // 10.0.0.10
  key.remote_address = aifc::IpAddress::from_v4(0x0A00000BU);  // 10.0.0.11
  key.local_port = 40100;
  key.remote_port = 29600;
  key.transport = aifc::TransportProtocol::TCP;
  return key;
}

int report(const aifc::Status& status, const char* what) {
  std::fprintf(stderr, "%s failed: %s\n", what, aifc::render_status(status).c_str());
  return 1;
}

}  // namespace

int main() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  // The penalty is explicit configuration, not a hidden constant: an operator chooses how
  // much a live disagreement costs.
  policy.contradiction_penalty = 2500;
  aifc::Classifier classifier(aifc::ClassifierOptions{policy, aifc::Logger{},
                                                      aifc::CoordinatorEpoch{1},
                                                      aifc::CoordinatorBootId{1}});

  const aifc::FlowKey key = example_flow();

  struct Peer {
    aifc::SessionEnvelope envelope;
    aifc::SessionId session;
    std::string name;
  };

  Peer peers[2];
  const char* names[2] = {"rank-0-agent", "rank-9-agent"};
  aifc::SessionEnvelope envelopes[2];
  for (int i = 0; i < 2; ++i) {
    const aifc::PublisherId publisher = aifc::make_publisher_id(names[i]);
    const aifc::SessionId session(std::string("session-") + names[i]);
    auto registration = classifier.register_publisher(publisher, aifc::PublisherBootId{1},
                                                      aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                                      session, "example peer");
    if (!registration) return report(registration.status(), "register_publisher");
    envelopes[i] = aifc::make_session_envelope(registration.value(), 0);
  }

  auto flow = classifier.register_flow(key, aifc::FlowGeneration{0}, aifc::SessionId("example"));
  if (!flow) return report(flow.status(), "register_flow");

  const aifc::SemanticClass declared[2] = {aifc::SemanticClass::KV_STATE_TRANSFER,
                                           aifc::SemanticClass::PREFILL_DECODE_HANDOFF};
  for (int i = 0; i < 2; ++i) {
    aifc::EvidencePayload payload;
    payload.flow_key = key;
    payload.flow_generation = flow.value().record.generation;
    payload.evidence_generation = aifc::EvidenceGeneration{static_cast<std::uint64_t>(i + 1)};
    payload.semantic = declared[i];
    payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.topic = "disagreement.topic";
    payload.metadata.reason = std::string("declared by ") + names[i];
    auto outcome = classifier.submit_evidence(envelopes[i], payload);
    if (!outcome) return report(outcome.status(), "submit_evidence");
  }

  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.explain = true;
  auto classified = classifier.classify(query);
  if (!classified) return report(classified.status(), "classify");

  std::printf("%s\n", classified.value().explanation.c_str());

  const aifc::Classification& result = classified.value().classification;
  const bool contradiction_reported =
      result.state == aifc::ClassificationState::CONTRADICTED && !result.contradictions.empty();
  const bool penalty_applied = result.applied_penalty_basis_points == 2500;
  const bool not_a_synthesis = result.semantic == declared[0] || result.semantic == declared[1];
  std::printf("contradictions  %zu\n", result.contradictions.size());
  std::printf("penalty         %u basis points\n", result.applied_penalty_basis_points);
  std::printf("class           %s\n", std::string(aifc::to_string(result.semantic)).c_str());
  if (!contradiction_reported || !penalty_applied || !not_a_synthesis) {
    std::fprintf(stderr, "the contradiction was not reported as required\n");
    return 2;
  }
  std::printf("example_contradiction: OK\n");
  return 0;
}
