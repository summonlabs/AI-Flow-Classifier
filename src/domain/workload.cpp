// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/domain/workload.hpp"

#include <array>
#include <string>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

struct WorkloadStateEntry {
  WorkloadState value;
  std::string_view name;
};

constexpr std::array<WorkloadStateEntry, 3> kWorkloadStates = {{
    {WorkloadState::DECLARED, "DECLARED"},
    {WorkloadState::ACTIVE, "ACTIVE"},
    {WorkloadState::RETIRED, "RETIRED"},
}};

struct ContractStateEntry {
  ContractState value;
  std::string_view name;
};

constexpr std::array<ContractStateEntry, 3> kContractStates = {{
    {ContractState::PENDING, "PENDING"},
    {ContractState::ACTIVE, "ACTIVE"},
    {ContractState::RETIRED, "RETIRED"},
}};

}  // namespace

std::string_view to_string(WorkloadState value) noexcept {
  for (const WorkloadStateEntry& entry : kWorkloadStates) {
    if (entry.value == value) return entry.name;
  }
  return "UNRECOGNIZED_WORKLOAD_STATE";
}

Result<WorkloadState> parse_workload_state(std::string_view text) {
  for (const WorkloadStateEntry& entry : kWorkloadStates) {
    if (entry.name == text) return entry.value;
  }
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised workload state: " + std::string(text));
}

std::string_view to_string(ContractState value) noexcept {
  for (const ContractStateEntry& entry : kContractStates) {
    if (entry.value == value) return entry.name;
  }
  return "UNRECOGNIZED_CONTRACT_STATE";
}

Result<ContractState> parse_contract_state(std::string_view text) {
  for (const ContractStateEntry& entry : kContractStates) {
    if (entry.name == text) return entry.value;
  }
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised contract state: " + std::string(text));
}

Digest256 compute_contract_digest(const WorkloadContract& contract) {
  BufferWriter writer(kMaxBlobBytes);
  Status status = writer.put_u8(1U);  // digest schema version
  if (status) status = writer.put_string(contract.id.value());
  if (status) status = writer.put_string(contract.workload.value());
  if (status) status = writer.put_u64(contract.workload_generation.value);
  if (status) status = writer.put_string(contract.owner.value());
  if (status) status = writer.put_u16(static_cast<std::uint16_t>(contract.declared_class));
  if (status) status = writer.put_bool(contract.match_any_remote_address);
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(contract.remote_scope.size()));
  for (const IpAddress& address : contract.remote_scope) {
    if (!status) break;
    status = writer.put_blob(address.bytes.data(), address.bytes.size());
  }
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(contract.local_port_scope.size()));
  for (std::uint16_t port : contract.local_port_scope) {
    if (!status) break;
    status = writer.put_u16(port);
  }
  if (status) status = writer.put_u16(contract.remote_port);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(contract.transport));
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(contract.derived_source));
  if (status) status = writer.put_string(contract.description);

  Digest256 digest;
  if (!status) return digest;
  Sha256 hasher;
  hasher.update(writer.bytes());
  hasher.finish(digest.bytes);
  return digest;
}

bool contract_covers(const WorkloadContract& contract, const FlowKey& key) noexcept {
  if (contract.transport != TransportProtocol::UNKNOWN && contract.transport != key.transport) {
    return false;
  }
  if (contract.remote_port != 0 && contract.remote_port != key.remote_port) {
    return false;
  }
  if (!contract.match_any_remote_address) {
    bool found = false;
    for (const IpAddress& address : contract.remote_scope) {
      if (address == key.remote_address) {
        found = true;
        break;
      }
    }
    if (!found) return false;
  }
  if (!contract.local_port_scope.empty()) {
    bool found = false;
    for (std::uint16_t port : contract.local_port_scope) {
      if (port == key.local_port) {
        found = true;
        break;
      }
    }
    if (!found) return false;
  }
  return true;
}

}  // namespace aifc
