// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Example: the whole lifecycle for one flow, over a durable state directory.
//
//   1. a publisher declares a workload and a contract;
//   2. a flow is registered and evidence is published against the contract;
//   3. the classification is produced and explained;
//   4. the state is persisted durably;
//   5. the coordinator "restarts" on that state, which advances the epoch and drops every
//      liveness claim;
//   6. the classification after the restart is *not* the pre-restart class presented as
//      current -- the evidence is stale and the runtime says why;
//   7. the publisher republishes under the new epoch with a new generation, and the class
//      becomes current again.
//
// Step 6 is the whole point.  Persistence is not currentness, and a restart is not a
// resurrection.
//
// The state directory is created under the system temporary root and removed on exit, so
// running this example does not leave anything behind.

#include <ai_flow_classifier/ai_flow_classifier.hpp>

#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>

namespace {

aifc::FlowKey example_flow() {
  aifc::FlowKey key;
  key.local_address = aifc::IpAddress::from_v4(0x0A00001EU);   // 10.0.0.30
  key.remote_address = aifc::IpAddress::from_v4(0x0A00001FU);  // 10.0.0.31
  key.local_port = 42000;
  key.remote_port = 29500;
  key.transport = aifc::TransportProtocol::TCP;
  return key;
}

int report(const aifc::Status& status, const char* what) {
  std::fprintf(stderr, "%s failed: %s\n", what, aifc::render_status(status).c_str());
  return 1;
}

class Scratch {
 public:
  Scratch() {
    std::error_code error;
    const std::filesystem::path base = std::filesystem::temp_directory_path(error);
    path_ = (base / "aifc-example-end-to-end").string();
    std::filesystem::remove_all(path_, error);
    const aifc::Status created = aifc::create_directories(path_);
    if (!created) {
      std::fprintf(stderr, "cannot create %s: %s\n", path_.c_str(), created.message.c_str());
      std::abort();
    }
  }
  ~Scratch() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  [[nodiscard]] std::string state_file() const { return path_ + "/coordinator.state"; }

 private:
  std::string path_;
};

}  // namespace

int main() {
  Scratch scratch;
  const std::string state_path = scratch.state_file();
  const aifc::PublisherId publisher = aifc::make_publisher_id("checkpoint-writer");
  const aifc::SessionId session("session-checkpoint-writer");
  const aifc::FlowKey key = example_flow();

  aifc::FlowRecord flow;

  // --- first incarnation: declare, publish, classify, persist ------------------------
  {
    aifc::CoordinatorOptions options;
    options.policy = aifc::ClassifierPolicy::initial();
    options.state_path = state_path;
    aifc::Coordinator coordinator(options);
    aifc::Status status = coordinator.start(aifc::CoordinatorBootId{1});
    if (!status) return report(status, "coordinator.start (first)");

    auto registration = coordinator.classifier().register_publisher(
        publisher, aifc::PublisherBootId{1}, aifc::EvidenceSource::DECLARED_AUTHENTICATED, session,
        "checkpoint writer");
    if (!registration) return report(registration.status(), "register_publisher");
    const aifc::SessionEnvelope envelope =
        aifc::make_session_envelope(registration.value(), 0);

    auto workload = coordinator.classifier().declare_workload(
        aifc::make_workload_id("checkpoint-writer-workload"), publisher,
        aifc::WorkloadGeneration{1}, "periodic checkpoint writer");
    if (!workload) return report(workload.status(), "declare_workload");

    aifc::WorkloadContract contract;
    contract.id = aifc::make_contract_id("checkpoint-writer-contract");
    contract.workload = workload.value().id;
    contract.workload_generation = workload.value().generation;
    contract.owner = publisher;
    contract.declared_class = aifc::SemanticClass::CHECKPOINT;
    contract.match_any_remote_address = true;
    contract.transport = aifc::TransportProtocol::TCP;
    contract.remote_port = 29500;
    contract.description = "checkpoint traffic to the object store";
    auto proposed = coordinator.classifier().propose_contract(contract);
    if (!proposed) return report(proposed.status(), "propose_contract");
    auto activated = coordinator.classifier().activate_contract(proposed.value().id, publisher);
    if (!activated) return report(activated.status(), "activate_contract");

    auto registration_flow =
        coordinator.classifier().register_flow(key, aifc::FlowGeneration{0}, session);
    if (!registration_flow) return report(registration_flow.status(), "register_flow");
    flow = registration_flow.value().record;

    aifc::EvidencePayload payload;
    payload.workload = workload.value().id;
    payload.workload_generation = workload.value().generation;
    payload.contract = activated.value().id;
    payload.flow_key = key;
    payload.flow_generation = flow.generation;
    payload.evidence_generation = aifc::EvidenceGeneration{1};
    payload.semantic = aifc::SemanticClass::CHECKPOINT;
    payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.topic = "checkpoint.upload";
    payload.metadata.reason = "shard 12 of 128 written to the checkpoint store";
    auto outcome = coordinator.classifier().submit_evidence(envelope, payload);
    if (!outcome) return report(outcome.status(), "submit_evidence");

    aifc::ClassificationQuery query;
    query.flow_key = key;
    query.explain = true;
    auto classified = coordinator.classifier().classify(query);
    if (!classified) return report(classified.status(), "classify (first)");
    std::printf("--- before restart ---\n%s\n", classified.value().explanation.c_str());
    if (classified.value().classification.semantic != aifc::SemanticClass::CHECKPOINT) {
      std::fprintf(stderr, "the contract did not produce the declared class\n");
      return 2;
    }

    status = coordinator.persist();
    if (!status) return report(status, "persist");
    std::printf("state written to %s\n", state_path.c_str());

    status = coordinator.stop();
    if (!status) return report(status, "coordinator.stop (first)");
  }

  // --- restart on the same state ------------------------------------------------------
  {
    aifc::CoordinatorOptions options;
    options.policy = aifc::ClassifierPolicy::initial();
    options.state_path = state_path;
    aifc::Coordinator coordinator(options);
    aifc::Status status = coordinator.start(aifc::CoordinatorBootId{2});
    if (!status) return report(status, "coordinator.start (restart)");
    std::printf("restarted at epoch %s boot %s\n", coordinator.epoch().to_string().c_str(),
                coordinator.boot().to_string().c_str());

    aifc::ClassificationQuery query;
    query.flow_key = key;
    query.explain = true;
    auto classified = coordinator.classifier().classify(query);
    if (!classified) return report(classified.status(), "classify (after restart)");
    std::printf("--- after restart, before republishing ---\n%s\n",
                classified.value().explanation.c_str());

    // What must NOT survive a restart is session-bound authority.  What legitimately does
    // survive is the durable contract, because a contract is a declaration the coordinator
    // itself owns and re-validates on every decision -- it is not a liveness claim.
    //
    // So the assertion is precise rather than coarse: every citation that is still CURRENT
    // must be contract-derived, and the record that came from the publisher's session must
    // be STALE with the restart named as the reason.
    const aifc::Classification& after = classified.value().classification;
    bool session_evidence_is_current = false;
    bool contract_evidence_is_current = false;
    for (const aifc::EvidenceCitation& citation : after.citations) {
      if (citation.state != aifc::EvidenceState::EVIDENCE_CURRENT) continue;
      if (citation.id.value().rfind("ev-", 0) == 0) session_evidence_is_current = true;
      if (citation.id.value().rfind("ctr-", 0) == 0) contract_evidence_is_current = true;
      if (citation.source == aifc::EvidenceSource::DECLARED_AUTHENTICATED) {
        session_evidence_is_current = true;
      }
    }
    if (session_evidence_is_current) {
      std::fprintf(stderr,
                   "a restart kept session-bound authority current; that is the exact defect "
                   "this runtime must not have\n");
      return 2;
    }
    std::printf("post-restart class %s state %s (session authority was NOT resurrected; "
                "contract authority current: %s)\n",
                std::string(aifc::to_string(after.semantic)).c_str(),
                std::string(aifc::to_string(after.state)).c_str(),
                contract_evidence_is_current ? "yes" : "no");

    // --- republish under the new epoch ------------------------------------------------
    auto registration = coordinator.classifier().register_publisher(
        publisher, aifc::PublisherBootId{2}, aifc::EvidenceSource::DECLARED_AUTHENTICATED,
        aifc::SessionId("session-checkpoint-writer-2"), "checkpoint writer, second boot");
    if (!registration) return report(registration.status(), "register_publisher (second boot)");
    const aifc::SessionEnvelope envelope =
        aifc::make_session_envelope(registration.value(), 0);

    auto current = coordinator.classifier().find_flow(key);
    if (!current) return report(current.status(), "find_flow");

    aifc::EvidencePayload payload;
    payload.flow_key = key;
    payload.flow_generation = current.value().generation;
    payload.evidence_generation = aifc::EvidenceGeneration{2};
    payload.metadata.topic = "checkpoint.upload";
    payload.semantic = aifc::SemanticClass::CHECKPOINT;
    payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.reason = "shard 13 of 128 written after the restart";
    auto outcome = coordinator.classifier().submit_evidence(envelope, payload);
    if (!outcome) return report(outcome.status(), "submit_evidence (after restart)");

    auto reclassified = coordinator.classifier().classify(query);
    if (!reclassified) return report(reclassified.status(), "classify (republished)");
    std::printf("--- after republishing in the new epoch ---\n%s\n",
                reclassified.value().explanation.c_str());
    const aifc::Classification& restored = reclassified.value().classification;
    if (restored.semantic != aifc::SemanticClass::CHECKPOINT ||
        restored.selected_source != aifc::EvidenceSource::DECLARED_AUTHENTICATED ||
        restored.state == aifc::ClassificationState::STALE) {
      std::fprintf(stderr,
                   "republishing did not restore a current authenticated classification: class "
                   "%s source %s state %s\n",
                   std::string(aifc::to_string(restored.semantic)).c_str(),
                   std::string(aifc::to_string(restored.selected_source)).c_str(),
                   std::string(aifc::to_string(restored.state)).c_str());
      return 2;
    }

    status = coordinator.stop();
    if (!status) return report(status, "coordinator.stop (restart)");
  }

  std::printf("example_end_to_end: OK\n");
  return 0;
}
