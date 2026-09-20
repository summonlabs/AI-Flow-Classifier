// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Downstream consumer.  Built by tests/downstream_consumer/CMakeLists.txt against an
// installed copy of the library, with no access to this repository's source tree.
//
// It exercises the public API end to end: create a classifier, bind a publisher,
// declare a workload and a contract, register a flow, publish authenticated evidence,
// classify, and print the explanation.  A consumer that can do this has everything it
// needs; if the packaging is broken, this program fails to build or fails at run time.

#include <ai_flow_classifier/ai_flow_classifier.hpp>

#include <cstdio>
#include <string>

namespace {

aifc::FlowKey make_key() {
  aifc::FlowKey key;
  key.local_address = aifc::IpAddress::from_v4(0x7F000001U);
  key.remote_address = aifc::IpAddress::from_v4(0x7F000002U);
  key.local_port = 41000;
  key.remote_port = 29500;
  key.transport = aifc::TransportProtocol::TCP;
  return key;
}

}  // namespace

int main() {
  aifc::ClassifierOptions options;
  options.policy = aifc::ClassifierPolicy::initial();
  aifc::Classifier classifier(options);

  const aifc::PublisherId publisher = aifc::make_publisher_id("consumer-publisher");
  const aifc::SessionId session("consumer-session");
  auto registration = classifier.register_publisher(publisher, aifc::PublisherBootId{1},
                                                    aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                                    session, "downstream consumer");
  if (!registration) {
    std::printf("register_publisher failed: %s\n", aifc::render_status(registration.status()).c_str());
    return 1;
  }

  auto workload = classifier.declare_workload(aifc::make_workload_id("consumer-workload"), publisher,
                                              aifc::WorkloadGeneration{1}, "consumer workload");
  if (!workload) {
    std::printf("declare_workload failed: %s\n", aifc::render_status(workload.status()).c_str());
    return 1;
  }

  aifc::WorkloadContract contract;
  contract.id = aifc::make_contract_id("consumer-contract");
  contract.workload = workload.value().id;
  contract.workload_generation = workload.value().generation;
  contract.owner = publisher;
  contract.declared_class = aifc::SemanticClass::INFERENCE_REQUEST;
  contract.match_any_remote_address = true;
  contract.transport = aifc::TransportProtocol::TCP;
  contract.remote_port = 29500;
  contract.description = "consumer contract";
  auto proposed = classifier.propose_contract(contract);
  if (!proposed) {
    std::printf("propose_contract failed: %s\n", aifc::render_status(proposed.status()).c_str());
    return 1;
  }
  auto activated = classifier.activate_contract(proposed.value().id, publisher);
  if (!activated) {
    std::printf("activate_contract failed: %s\n", aifc::render_status(activated.status()).c_str());
    return 1;
  }

  const aifc::FlowKey key = make_key();
  auto flow = classifier.register_flow(key, aifc::FlowGeneration{0}, session);
  if (!flow) {
    std::printf("register_flow failed: %s\n", aifc::render_status(flow.status()).c_str());
    return 1;
  }

  aifc::EvidencePayload payload;
  payload.workload = workload.value().id;
  payload.workload_generation = workload.value().generation;
  payload.contract = activated.value().id;
  payload.flow_key = key;
  payload.flow_generation = flow.value().record.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};
  payload.semantic = aifc::SemanticClass::INFERENCE_REQUEST;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "consumer.topic";
  payload.metadata.reason = "downstream consumer proof";

  auto outcome = classifier.submit_evidence(aifc::make_session_envelope(registration.value(), 0), payload);
  if (!outcome) {
    std::printf("submit_evidence failed: %s\n", aifc::render_status(outcome.status()).c_str());
    return 1;
  }

  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.explain = true;
  auto classified = classifier.classify(query);
  if (!classified) {
    std::printf("classify failed: %s\n", aifc::render_status(classified.status()).c_str());
    return 1;
  }

  std::printf("product=%s\n", aifc::product_version_string().c_str());
  std::printf("semantic_class=%s\n",
              std::string(aifc::to_string(classified.value().classification.semantic)).c_str());
  std::printf("state=%s\n",
              std::string(aifc::to_string(classified.value().classification.state)).c_str());
  std::printf("confidence=%s\n", classified.value().classification.confidence.to_decimal().c_str());
  std::printf("%s\n", classified.value().explanation.c_str());

  const bool ok = classified.value().classification.semantic == aifc::SemanticClass::INFERENCE_REQUEST &&
                  classified.value().classification.confidence.basis_points() != 0;
  return ok ? 0 : 2;
}
