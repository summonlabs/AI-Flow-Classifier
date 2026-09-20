// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "synthetic.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <thread>

#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/io/files.hpp"

#if defined(AIFC_PLATFORM_WINDOWS)
#include <windows.h>
#endif

namespace aifc_test {
namespace {

[[nodiscard]] std::string indexed(std::string_view prefix, std::uint32_t index) {
  return std::string(prefix) + "-" + std::to_string(index);
}

}  // namespace

aifc::IpAddress synthetic_address(std::uint32_t index) {
  // 127.x.y.z, so the address space used by the synthetic inputs is loopback and can
  // never be confused with a real fabric address.
  const std::uint32_t value = 0x7F000000U | (index & 0x00FFFFFFU);
  return aifc::IpAddress::from_v4(value == 0x7F000000U ? 0x7F000001U : value);
}

aifc::FlowKey synthetic_flow_key(std::uint32_t index, aifc::TransportProtocol transport) {
  aifc::FlowKey key;
  key.local_address = aifc::IpAddress::from_v4(0x7F000001U);
  key.remote_address = synthetic_address(index + 1);
  key.local_port = static_cast<std::uint16_t>(40000U + (index % 20000U));
  key.remote_port = static_cast<std::uint16_t>(20000U + (index % 40000U));
  key.transport = transport;
  return key;
}

aifc::PublisherId synthetic_publisher(std::uint32_t index) {
  return aifc::make_publisher_id(indexed("publisher", index));
}

aifc::WorkloadId synthetic_workload(std::uint32_t index) {
  return aifc::make_workload_id(indexed("workload", index));
}

aifc::ContractId synthetic_contract(std::uint32_t index) {
  return aifc::make_contract_id(indexed("contract", index));
}

aifc::SessionId synthetic_session(std::uint32_t index) { return aifc::SessionId(indexed("session", index)); }

Harness::Harness(aifc::ClassifierPolicy policy, aifc::CoordinatorEpoch epoch,
                 aifc::CoordinatorBootId boot)
    : classifier_(aifc::ClassifierOptions{std::move(policy), aifc::Logger{}, epoch, boot}) {}

Harness::Peer Harness::add_peer(std::uint32_t index, aifc::EvidenceSource ceiling,
                                aifc::PublisherBootId boot) {
  Peer peer;
  peer.publisher = synthetic_publisher(index);
  peer.boot = boot;
  peer.session = synthetic_session(index);
  const auto registration = classifier_.register_publisher(peer.publisher, peer.boot, ceiling,
                                                           peer.session, "synthetic peer");
  if (!registration) {
    std::fprintf(stderr, "harness: register_publisher failed: %s\n",
                 aifc::render_status(registration.status()).c_str());
    std::abort();
  }
  peer.envelope = aifc::make_session_envelope(registration.value(), 0);
  return peer;
}

Harness::Peer Harness::restart_peer(std::uint32_t index, aifc::PublisherBootId boot) {
  return add_peer(index, aifc::EvidenceSource::DECLARED_AUTHENTICATED, boot);
}

aifc::WorkloadRecord Harness::declare_workload(const Peer& peer, std::uint32_t index,
                                               aifc::WorkloadGeneration generation) {
  const auto record = classifier_.declare_workload(synthetic_workload(index), peer.publisher,
                                                   generation, "synthetic workload");
  if (!record) {
    std::fprintf(stderr, "harness: declare_workload failed: %s\n",
                 aifc::render_status(record.status()).c_str());
    std::abort();
  }
  return record.value();
}

aifc::WorkloadContract Harness::activate_contract(const Peer& peer, const aifc::WorkloadRecord& workload,
                                                  std::uint32_t index,
                                                  aifc::SemanticClass declared_class,
                                                  std::uint16_t remote_port, bool any_remote) {
  aifc::WorkloadContract contract;
  contract.id = synthetic_contract(index);
  contract.workload = workload.id;
  contract.workload_generation = workload.generation;
  contract.owner = peer.publisher;
  contract.declared_class = declared_class;
  contract.match_any_remote_address = any_remote;
  contract.transport = aifc::TransportProtocol::TCP;
  contract.remote_port = remote_port;
  contract.description = "synthetic contract";
  const auto proposed = classifier_.propose_contract(contract);
  if (!proposed) {
    std::fprintf(stderr, "harness: propose_contract failed: %s\n",
                 aifc::render_status(proposed.status()).c_str());
    std::abort();
  }
  const auto activated = classifier_.activate_contract(proposed.value().id, peer.publisher);
  if (!activated) {
    std::fprintf(stderr, "harness: activate_contract failed: %s\n",
                 aifc::render_status(activated.status()).c_str());
    std::abort();
  }
  return activated.value();
}

aifc::FlowRecord Harness::register_flow(const Peer& peer, std::uint32_t index,
                                        aifc::FlowGeneration generation) {
  const auto registration =
      classifier_.register_flow(synthetic_flow_key(index), generation, peer.session);
  if (!registration) {
    std::fprintf(stderr, "harness: register_flow failed: %s\n",
                 aifc::render_status(registration.status()).c_str());
    std::abort();
  }
  return registration.value().record;
}

aifc::EvidenceRecord Harness::publish(const Peer& peer, const aifc::FlowRecord& flow,
                                      aifc::SemanticClass semantic,
                                      aifc::EvidenceGeneration generation,
                                      aifc::EvidenceSource claimed, std::string topic,
                                      std::uint64_t freshness_window,
                                      const aifc::WorkloadRecord* workload) {
  aifc::EvidencePayload payload;
  payload.flow_key = flow.key;
  payload.flow_generation = flow.generation;
  payload.evidence_generation = generation;
  payload.semantic = semantic;
  payload.claimed_source = claimed;
  payload.freshness_window = freshness_window;
  payload.metadata.topic = std::move(topic);
  payload.metadata.reason = "synthetic evidence";
  if (workload != nullptr) {
    payload.workload = workload->id;
    payload.workload_generation = workload->generation;
  }
  const auto outcome = classifier_.submit_evidence(peer.envelope, payload);
  if (!outcome) {
    std::fprintf(stderr, "harness: submit_evidence failed: %s\n",
                 aifc::render_status(outcome.status()).c_str());
    std::abort();
  }
  return outcome.value().record;
}

aifc::ClassificationResult Harness::classify(const aifc::FlowKey& key,
                                             aifc::FlowGeneration generation, bool explain) {
  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.flow_generation = generation;
  query.explain = explain;
  query.accept_current_generation = generation.value == 0;
  const auto result = classifier_.classify(query);
  if (!result) {
    std::fprintf(stderr, "harness: classify failed: %s\n",
                 aifc::render_status(result.status()).c_str());
    std::abort();
  }
  return result.value();
}

ScratchDirectory::ScratchDirectory(const std::string& name) {
  std::error_code error;
  const std::filesystem::path base = std::filesystem::temp_directory_path(error);
  if (error) {
    std::fprintf(stderr, "harness: no temporary directory available: %s\n", error.message().c_str());
    std::abort();
  }
  const std::uint64_t nonce = aifc::wall_clock_unix_millis();
  path_ = (base / ("aifc-" + name + "-" + std::to_string(nonce))).string();
  const aifc::Status created = aifc::create_directories(path_);
  if (!created) {
    std::fprintf(stderr, "harness: cannot create scratch directory %s: %s\n", path_.c_str(),
                 created.message.c_str());
    std::abort();
  }
}

ScratchDirectory::~ScratchDirectory() {
  // Removal is retried.  A process that has just been terminated can still hold its inherited
  // handles open for a moment, and a single attempt would leave the directory behind on a machine
  // that is under load -- which then makes the *next* run behave differently from this one.  A test
  // harness must not be the reason a result is not reproducible.
  for (int attempt = 0; attempt < 40; ++attempt) {
    std::error_code error;
    std::filesystem::remove_all(std::filesystem::path(path_), error);
    if (!error) return;
    if (attempt == 39) {
      // Reported, never fatal: the directory is under the system temporary root and its name carries
      // a nonce, so a leftover cannot collide with a later run.
      std::fprintf(stderr, "harness: could not remove scratch directory %s: %s\n", path_.c_str(),
                   error.message().c_str());
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
}

std::string ScratchDirectory::file(const std::string& name) const {
  return (std::filesystem::path(path_) / name).string();
}

std::string executable_path() {
#if defined(AIFC_PLATFORM_WINDOWS)
  char buffer[4096] = {};
  const DWORD length = ::GetModuleFileNameA(nullptr, buffer, sizeof(buffer));
  if (length == 0 || length >= sizeof(buffer)) return std::string();
  return std::string(buffer, length);
#else
  std::error_code error;
  const std::filesystem::path path = std::filesystem::read_symlink("/proc/self/exe", error);
  if (error) return std::string();
  return path.string();
#endif
}

}  // namespace aifc_test
