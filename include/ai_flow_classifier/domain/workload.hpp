// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Workloads and workload contracts.
//
// A workload is a named unit of AI work owned by a publisher.  A contract is the
// durable declaration of what that workload's flows mean.  Contracts are the only
// route by which a peer can influence classification without sending per-flow
// evidence, and they are therefore versioned, fenced by generation and immutable
// once active: changing a contract means retiring the old one and activating a new
// generation, which stales every classification derived from the old one.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_WORKLOAD_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_WORKLOAD_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/semantic_class.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

enum class WorkloadState : std::uint8_t {
  DECLARED = 0,
  ACTIVE = 1,
  RETIRED = 2,
};

[[nodiscard]] std::string_view to_string(WorkloadState value) noexcept;
[[nodiscard]] Result<WorkloadState> parse_workload_state(std::string_view text);

struct WorkloadRecord {
  WorkloadId id;
  PublisherId owner;
  WorkloadGeneration generation;
  WorkloadState state = WorkloadState::DECLARED;
  ContractId active_contract;
  Tick declared_tick = kTickNone;
  Tick activated_tick = kTickNone;
  Tick retired_tick = kTickNone;
  std::string description;
};

enum class ContractState : std::uint8_t {
  // Proposed, not yet validated.  Contributes nothing to classification: a
  // proposal is not authority.
  PENDING = 0,
  ACTIVE = 1,
  RETIRED = 2,
};

[[nodiscard]] std::string_view to_string(ContractState value) noexcept;
[[nodiscard]] Result<ContractState> parse_contract_state(std::string_view text);

struct WorkloadContract {
  ContractId id;
  WorkloadId workload;
  WorkloadGeneration workload_generation;
  PublisherId owner;
  ContractState state = ContractState::PENDING;

  // The class that flows matching this contract are declared to carry.  This is a
  // declaration, not an observation.
  SemanticClass declared_class = SemanticClass::UNKNOWN;

  // Endpoint scope.  A contract applies to flows whose remote endpoint is in the
  // declared set.  An empty set means "any peer"; a contract with an empty set and
  // no port scope is refused as too broad to be meaningful.
  std::vector<IpAddress> remote_scope;
  std::vector<std::uint16_t> local_port_scope;
  std::uint16_t remote_port = 0;
  TransportProtocol transport = TransportProtocol::UNKNOWN;
  bool match_any_remote_address = false;

  // Effective authority ceiling for evidence derived from this contract.  The
  // coordinator chooses this; a peer cannot raise it by asking.
  EvidenceSource derived_source = EvidenceSource::CONTRACT_DERIVED;

  // Content digest of the contract definition.  Any mutation of an ACTIVE
  // contract is refused: a changed contract is a new contract id.
  Digest256 definition_digest;

  Tick created_tick = kTickNone;
  Tick activated_tick = kTickNone;
  Tick retired_tick = kTickNone;
  std::string description;
};

// Computes the definition digest over every field that affects meaning.  State and
// lifecycle ticks are excluded, because they describe the contract's position
// rather than its content.
[[nodiscard]] Digest256 compute_contract_digest(const WorkloadContract& contract);

// True when the contract's scope covers the key.  Scope matching is necessary but
// not sufficient: the caller must also check the workload generation and state.
[[nodiscard]] bool contract_covers(const WorkloadContract& contract, const FlowKey& key) noexcept;

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_WORKLOAD_HPP
