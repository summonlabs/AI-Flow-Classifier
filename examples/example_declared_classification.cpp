// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Example: an authenticated declaration decides a flow's semantic class.
//
// This is the supported, intended path: a publisher with a real session declares what its
// own flow is, and the runtime reports that class with the evidence and the policy that
// produced it.  Nothing here is synthetic; the flow metadata is supplied by the program,
// which stands in for a publisher process.
//
// Exit status is non-zero if the runtime's answer is not the expected one, so the example
// doubles as a smoke test of the installed library.

#include <ai_flow_classifier/ai_flow_classifier.hpp>

#include <cstdio>
#include <string>

namespace {

aifc::FlowKey example_flow() {
  aifc::FlowKey key;
  key.local_address = aifc::IpAddress::from_v4(0x0A000001U);   // 10.0.0.1
  key.remote_address = aifc::IpAddress::from_v4(0x0A000002U);  // 10.0.0.2
  key.local_port = 51234;
  key.remote_port = 29500;
  key.transport = aifc::TransportProtocol::TCP;
  return key;
}

int report(const aifc::Status& status, const char* what) {
  std::fprintf(stderr, "%s failed: %s\n", what, aifc::render_status(status).c_str());
  return 1;
}

}  // namespace

int main() {
  std::printf("%s\n", aifc::product_banner().c_str());

  aifc::ClassifierOptions options;
  options.policy = aifc::ClassifierPolicy::initial();
  aifc::Classifier classifier(options);

  const aifc::PublisherId publisher = aifc::make_publisher_id("trainer-node-7");
  const aifc::SessionId session("session-trainer-node-7");
  auto registration = classifier.register_publisher(publisher, aifc::PublisherBootId{1},
                                                    aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                                    session, "training node");
  if (!registration) return report(registration.status(), "register_publisher");
  const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

  auto workload = classifier.declare_workload(aifc::make_workload_id("llama-70b-pretrain"), publisher,
                                              aifc::WorkloadGeneration{1}, "70B pretraining job");
  if (!workload) return report(workload.status(), "declare_workload");

  const aifc::FlowKey key = example_flow();
  auto flow = classifier.register_flow(key, aifc::FlowGeneration{0}, session);
  if (!flow) return report(flow.status(), "register_flow");

  aifc::EvidencePayload payload;
  payload.workload = workload.value().id;
  payload.workload_generation = workload.value().generation;
  payload.flow_key = key;
  payload.flow_generation = flow.value().record.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};
  payload.semantic = aifc::SemanticClass::COLLECTIVE;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "rank0.collective";
  payload.metadata.reason = "all-reduce group 3 of 8";

  auto outcome = classifier.submit_evidence(envelope, payload);
  if (!outcome) return report(outcome.status(), "submit_evidence");

  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.explain = true;
  auto classified = classifier.classify(query);
  if (!classified) return report(classified.status(), "classify");

  std::printf("key         %s\n", key.to_string().c_str());
  std::printf("class       %s\n",
              std::string(aifc::to_string(classified.value().classification.semantic)).c_str());
  std::printf("state       %s\n",
              std::string(aifc::to_string(classified.value().classification.state)).c_str());
  std::printf("confidence  %s\n", classified.value().classification.confidence.to_decimal().c_str());
  std::printf("source      %s\n",
              std::string(aifc::to_string(classified.value().classification.selected_source)).c_str());
  std::printf("%s\n", classified.value().explanation.c_str());

  const bool ok =
      classified.value().classification.semantic == aifc::SemanticClass::COLLECTIVE &&
      classified.value().classification.state == aifc::ClassificationState::CURRENT &&
      classified.value().classification.selected_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  if (!ok) {
    std::fprintf(stderr, "unexpected classification result\n");
    return 2;
  }
  std::printf("example_declared_classification: OK\n");
  return 0;
}
