// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic synthetic inputs shared by the test surfaces.
//
// Everything here is SYNTHETIC by construction.  No test, example or document produced
// from this tree claims that these values were observed on real AI fabric hardware;
// what is REAL is the runtime behaviour they exercise.  See docs/proof-surfaces.md.

#ifndef AIFC_SYNTHETIC_HPP
#define AIFC_SYNTHETIC_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"

namespace aifc_test {

// A deterministic flow key derived from an index, so a failing case can be replayed by
// naming the index rather than by printing a five-tuple.
[[nodiscard]] aifc::FlowKey synthetic_flow_key(std::uint32_t index,
                                               aifc::TransportProtocol transport =
                                                   aifc::TransportProtocol::TCP);

[[nodiscard]] aifc::PublisherId synthetic_publisher(std::uint32_t index);
[[nodiscard]] aifc::WorkloadId synthetic_workload(std::uint32_t index);
[[nodiscard]] aifc::ContractId synthetic_contract(std::uint32_t index);
[[nodiscard]] aifc::SessionId synthetic_session(std::uint32_t index);
[[nodiscard]] aifc::IpAddress synthetic_address(std::uint32_t index);

// A running harness that owns a classifier and the sessions a test needs.  It exists so
// that every integration and property test builds the same preamble the same way; a
// divergence between two tests' setup would be a source of false failures.
class Harness {
 public:
  struct Peer {
    aifc::PublisherId publisher;
    aifc::PublisherBootId boot;
    aifc::SessionId session;
    aifc::SessionEnvelope envelope;
  };

  explicit Harness(aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial(),
                   aifc::CoordinatorEpoch epoch = aifc::CoordinatorEpoch{1},
                   aifc::CoordinatorBootId boot = aifc::CoordinatorBootId{1});

  // Binds a publisher with the given authority ceiling.
  Peer add_peer(std::uint32_t index, aifc::EvidenceSource ceiling = aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                aifc::PublisherBootId boot = aifc::PublisherBootId{1});

  // Restarts a peer at a strictly higher boot incarnation, which is what a publisher
  // process restart looks like from the coordinator's point of view.
  Peer restart_peer(std::uint32_t index, aifc::PublisherBootId boot);

  aifc::Classifier& classifier() noexcept { return classifier_; }

  // Declares a workload for a peer and returns the record.
  aifc::WorkloadRecord declare_workload(const Peer& peer, std::uint32_t index,
                                        aifc::WorkloadGeneration generation = aifc::WorkloadGeneration{1});

  // Proposes and activates a contract for a peer over a workload.
  aifc::WorkloadContract activate_contract(const Peer& peer, const aifc::WorkloadRecord& workload,
                                           std::uint32_t index, aifc::SemanticClass declared_class,
                                           std::uint16_t remote_port = 0,
                                           bool any_remote = true);

  // Registers a flow and returns its current incarnation.
  aifc::FlowRecord register_flow(const Peer& peer, std::uint32_t index,
                                 aifc::FlowGeneration generation = aifc::FlowGeneration{0});

  struct Published {
    aifc::EvidenceRecord record;
  };

  // Publishes authenticated evidence for a flow.
  aifc::EvidenceRecord publish(const Peer& peer, const aifc::FlowRecord& flow,
                               aifc::SemanticClass semantic, aifc::EvidenceGeneration generation,
                               aifc::EvidenceSource claimed = aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                               std::string topic = "synthetic.topic",
                               std::uint64_t freshness_window = 0,
                               const aifc::WorkloadRecord* workload = nullptr);

  // Classifies a flow and returns the result, failing the test if classification itself
  // fails.  Tests that expect a failure call the classifier directly.
  aifc::ClassificationResult classify(const aifc::FlowKey& key, aifc::FlowGeneration generation = {},
                                      bool explain = false);

 private:
  aifc::Classifier classifier_;
};

// A temporary directory that removes its own contents.  Used by the persistence and
// multiprocess surfaces so that a failed test does not leave state behind for the next
// run, which would make a failure non-reproducible.
class ScratchDirectory {
 public:
  explicit ScratchDirectory(const std::string& name);
  ~ScratchDirectory();
  ScratchDirectory(const ScratchDirectory&) = delete;
  ScratchDirectory& operator=(const ScratchDirectory&) = delete;

  [[nodiscard]] const std::string& path() const noexcept { return path_; }
  [[nodiscard]] std::string file(const std::string& name) const;

 private:
  std::string path_;
};

// Absolute path of the test executable, so that a multiprocess test can re-execute
// itself in a child role.  Returns an empty string when the platform cannot report it.
[[nodiscard]] std::string executable_path();

// Argument that puts a multiprocess test binary into its child role.
inline constexpr const char* kChildModeArgument = "--aifc-child";

}  // namespace aifc_test

#endif  // AIFC_SYNTHETIC_HPP
