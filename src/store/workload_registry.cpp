// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/store/workload_registry.hpp"

#include <algorithm>
#include <string>

namespace aifc {
namespace {

[[nodiscard]] std::string key_of(const WorkloadId& id) { return id.value(); }
[[nodiscard]] std::string key_of(const ContractId& id) { return id.value(); }

}  // namespace

Result<WorkloadRecord> WorkloadRegistry::declare_workload(
    const WorkloadId& id, const PublisherId& owner, WorkloadGeneration generation, Tick tick,
    std::string description, std::vector<WorkloadContract>* retired_contracts) {
  if (id.empty()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "workload identity is empty");
  }
  if (!generation.valid()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "workload generation must be greater than zero");
  }

  auto entry = workloads_.find(key_of(id));
  if (entry == workloads_.end()) {
    if (workloads_.size() >= static_cast<std::size_t>(max_workloads_)) {
      stats_.capacity_rejections += 1;
      return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                             "workload registry is full at " + std::to_string(max_workloads_));
    }
    WorkloadRecord record;
    record.id = id;
    record.owner = owner;
    record.generation = generation;
    record.state = WorkloadState::ACTIVE;
    record.declared_tick = tick;
    record.activated_tick = tick;
    record.description = std::move(description);
    workloads_.emplace(key_of(id), record);
    stats_.workloads_declared += 1;
    stats_.workloads = workloads_.size();
    return record;
  }

  WorkloadRecord& record = entry->second;
  if (owner != record.owner) {
    // Ownership is not transferable.  A different publisher claiming an existing
    // workload identity is either a mistake or an attack, and both are refused.
    stats_.contract_owner_rejections += 1;
    return Status::failure(ErrorCode::UNAUTHORIZED,
                           "workload " + id.value() + " is owned by " + record.owner.value());
  }
  if (generation < record.generation) {
    return Status::failure(ErrorCode::STALE_GENERATION,
                           "workload " + id.value() + " is at generation " +
                               record.generation.to_string() + "; generation " +
                               generation.to_string() + " was refused");
  }
  if (generation == record.generation) {
    if (!description.empty()) record.description = std::move(description);
    if (record.state == WorkloadState::RETIRED) {
      return Status::failure(ErrorCode::STALE_GENERATION,
                             "workload " + id.value() + " is retired at generation " +
                                 generation.to_string());
    }
    return record;
  }

  // A generation advance retires every contract bound to a lower generation.  Those
  // contracts are returned rather than silently dropped, because the caller must
  // report exactly which derived classifications became stale.
  std::vector<WorkloadContract> retired;
  for (auto& contract_entry : contracts_) {
    WorkloadContract& contract = contract_entry.second;
    if (contract.workload == id && contract.workload_generation < generation &&
        contract.state == ContractState::ACTIVE) {
      contract.state = ContractState::RETIRED;
      contract.retired_tick = tick;
      retired.push_back(contract);
      stats_.contracts_retired += 1;
    }
  }
  record.generation = generation;
  record.state = WorkloadState::ACTIVE;
  record.active_contract = ContractId{};
  record.activated_tick = tick;
  if (!description.empty()) record.description = std::move(description);
  stats_.workload_generation_advances += 1;
  if (retired_contracts != nullptr) {
    *retired_contracts = std::move(retired);
  }
  return record;
}

Result<WorkloadRecord> WorkloadRegistry::find_workload(const WorkloadId& id) const {
  auto entry = workloads_.find(key_of(id));
  if (entry == workloads_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_WORKLOAD, "no workload " + id.value() + " declared");
  }
  return entry->second;
}

Status WorkloadRegistry::retire_workload(const WorkloadId& id, WorkloadGeneration generation,
                                         Tick tick) {
  auto entry = workloads_.find(key_of(id));
  if (entry == workloads_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_WORKLOAD, "no workload " + id.value() + " declared");
  }
  if (generation != entry->second.generation) {
    return Status::failure(ErrorCode::STALE_GENERATION,
                           "workload retirement named generation " + generation.to_string() +
                               " but the current generation is " +
                               entry->second.generation.to_string());
  }
  entry->second.state = WorkloadState::RETIRED;
  entry->second.retired_tick = tick;
  for (auto& contract_entry : contracts_) {
    WorkloadContract& contract = contract_entry.second;
    if (contract.workload == id && contract.state == ContractState::ACTIVE) {
      contract.state = ContractState::RETIRED;
      contract.retired_tick = tick;
      stats_.contracts_retired += 1;
    }
  }
  return Status::success();
}

Result<WorkloadContract> WorkloadRegistry::propose_contract(WorkloadContract contract, Tick tick) {
  if (contract.id.empty()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "contract identity is empty");
  }
  if (!contract.workload_generation.valid()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "contract workload generation must be greater than zero");
  }
  if (contract.declared_class == SemanticClass::UNKNOWN) {
    // A contract that declares UNKNOWN is meaningless: UNKNOWN means "no class was
    // established", and a declaration cannot establish the absence of a class.
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "a contract may not declare the UNKNOWN semantic class");
  }
  if (!contract.match_any_remote_address && contract.remote_scope.empty() &&
      contract.local_port_scope.empty() && contract.remote_port == 0) {
    return Status::failure(
        ErrorCode::INVALID_ARGUMENT,
        "a contract must declare at least one scope; an unscoped contract would apply to every flow");
  }
  if (contracts_.find(key_of(contract.id)) != contracts_.end()) {
    return Status::failure(ErrorCode::ALREADY_EXISTS,
                           "contract " + contract.id.value() + " already exists");
  }
  auto workload_entry = workloads_.find(key_of(contract.workload));
  if (workload_entry == workloads_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_WORKLOAD,
                           "contract names undeclared workload " + contract.workload.value());
  }
  if (workload_entry->second.owner != contract.owner) {
    stats_.contract_owner_rejections += 1;
    return Status::failure(ErrorCode::UNAUTHORIZED,
                           "publisher " + contract.owner.value() + " does not own workload " +
                               contract.workload.value());
  }
  if (workload_entry->second.generation != contract.workload_generation) {
    return Status::failure(ErrorCode::STALE_GENERATION,
                           "contract names workload generation " +
                               contract.workload_generation.to_string() +
                               " but the current generation is " +
                               workload_entry->second.generation.to_string());
  }

  const std::size_t pending = static_cast<std::size_t>(std::count_if(
      contracts_.begin(), contracts_.end(), [](const auto& entry) {
        return entry.second.state == ContractState::PENDING;
      }));
  if (pending >= static_cast<std::size_t>(max_pending_contracts_)) {
    stats_.capacity_rejections += 1;
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "pending contract limit of " + std::to_string(max_pending_contracts_) +
                               " reached");
  }
  if (contracts_.size() >= static_cast<std::size_t>(max_contracts_)) {
    stats_.capacity_rejections += 1;
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "contract registry is full at " + std::to_string(max_contracts_));
  }

  contract.state = ContractState::PENDING;
  contract.created_tick = tick;
  contract.activated_tick = kTickNone;
  contract.retired_tick = kTickNone;
  // The digest is computed here so a caller cannot supply a digest that does not
  // match the content it is claiming.
  contract.definition_digest = compute_contract_digest(contract);
  contracts_.emplace(key_of(contract.id), contract);
  stats_.contracts_proposed += 1;
  stats_.contracts = contracts_.size();
  return contract;
}

Result<WorkloadContract> WorkloadRegistry::activate_contract(const ContractId& id,
                                                             const PublisherId& caller, Tick tick,
                                                             WorkloadContract* retired) {
  auto entry = contracts_.find(key_of(id));
  if (entry == contracts_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_CONTRACT, "no contract " + id.value());
  }
  WorkloadContract& contract = entry->second;
  if (contract.owner != caller) {
    stats_.contract_owner_rejections += 1;
    return Status::failure(ErrorCode::UNAUTHORIZED,
                           "publisher " + caller.value() + " does not own contract " + id.value());
  }
  if (contract.state == ContractState::RETIRED) {
    return Status::failure(ErrorCode::CONTRACT_RETIRED,
                           "contract " + id.value() + " has been retired");
  }
  auto workload_entry = workloads_.find(key_of(contract.workload));
  if (workload_entry == workloads_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_WORKLOAD,
                           "contract names undeclared workload " + contract.workload.value());
  }
  if (workload_entry->second.generation != contract.workload_generation) {
    return Status::failure(ErrorCode::STALE_GENERATION,
                           "contract " + id.value() + " is bound to workload generation " +
                               contract.workload_generation.to_string() +
                               " but the workload is at " +
                               workload_entry->second.generation.to_string());
  }
  if (workload_entry->second.state == WorkloadState::RETIRED) {
    return Status::failure(ErrorCode::CONTRACT_RETIRED,
                           "workload " + contract.workload.value() + " is retired");
  }

  if (contract.state == ContractState::ACTIVE) {
    // Re-activating the active contract is idempotent rather than an error.
    return contract;
  }

  for (auto& other_entry : contracts_) {
    WorkloadContract& other = other_entry.second;
    if (other.id == contract.id) continue;
    if (other.workload == contract.workload && other.state == ContractState::ACTIVE) {
      other.state = ContractState::RETIRED;
      other.retired_tick = tick;
      stats_.contracts_retired += 1;
      if (retired != nullptr) {
        *retired = other;
      }
    }
  }

  contract.state = ContractState::ACTIVE;
  contract.activated_tick = tick;
  contract.retired_tick = kTickNone;
  workload_entry->second.active_contract = contract.id;
  workload_entry->second.state = WorkloadState::ACTIVE;
  workload_entry->second.activated_tick = tick;
  stats_.contracts_activated += 1;
  stats_.active_contracts = static_cast<std::size_t>(
      std::count_if(contracts_.begin(), contracts_.end(), [](const auto& other) {
        return other.second.state == ContractState::ACTIVE;
      }));
  return contract;
}

Status WorkloadRegistry::retire_contract(const ContractId& id, const PublisherId& caller,
                                         Tick tick) {
  auto entry = contracts_.find(key_of(id));
  if (entry == contracts_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_CONTRACT, "no contract " + id.value());
  }
  if (entry->second.owner != caller) {
    stats_.contract_owner_rejections += 1;
    return Status::failure(ErrorCode::UNAUTHORIZED,
                           "publisher " + caller.value() + " does not own contract " + id.value());
  }
  entry->second.state = ContractState::RETIRED;
  entry->second.retired_tick = tick;
  stats_.contracts_retired += 1;
  auto workload_entry = workloads_.find(key_of(entry->second.workload));
  if (workload_entry != workloads_.end() && workload_entry->second.active_contract == id) {
    workload_entry->second.active_contract = ContractId{};
  }
  return Status::success();
}

Result<WorkloadContract> WorkloadRegistry::find_contract(const ContractId& id) const {
  auto entry = contracts_.find(key_of(id));
  if (entry == contracts_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_CONTRACT, "no contract " + id.value());
  }
  return entry->second;
}

Result<WorkloadContract> WorkloadRegistry::find_active_contract(
    const WorkloadId& workload, WorkloadGeneration generation) const {
  for (const auto& entry : contracts_) {
    const WorkloadContract& contract = entry.second;
    if (contract.workload == workload && contract.workload_generation == generation &&
        contract.state == ContractState::ACTIVE) {
      return contract;
    }
  }
  return Status::failure(ErrorCode::UNKNOWN_CONTRACT,
                         "workload " + workload.value() + " has no active contract at generation " +
                             generation.to_string());
}

std::vector<WorkloadContract> WorkloadRegistry::active_contracts() const {
  std::vector<WorkloadContract> out;
  for (const auto& entry : contracts_) {
    if (entry.second.state == ContractState::ACTIVE) out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(),
            [](const WorkloadContract& a, const WorkloadContract& b) { return a.id < b.id; });
  return out;
}

std::vector<WorkloadRecord> WorkloadRegistry::snapshot_workloads() const {
  std::vector<WorkloadRecord> out;
  out.reserve(workloads_.size());
  for (const auto& entry : workloads_) out.push_back(entry.second);
  std::sort(out.begin(), out.end(),
            [](const WorkloadRecord& a, const WorkloadRecord& b) { return a.id < b.id; });
  return out;
}

std::vector<WorkloadContract> WorkloadRegistry::snapshot_contracts() const {
  std::vector<WorkloadContract> out;
  out.reserve(contracts_.size());
  for (const auto& entry : contracts_) out.push_back(entry.second);
  std::sort(out.begin(), out.end(),
            [](const WorkloadContract& a, const WorkloadContract& b) { return a.id < b.id; });
  return out;
}

Status WorkloadRegistry::restore_workload(const WorkloadRecord& record) {
  if (workloads_.find(key_of(record.id)) == workloads_.end() &&
      workloads_.size() >= static_cast<std::size_t>(max_workloads_)) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "workload registry is full while restoring persisted state");
  }
  workloads_[key_of(record.id)] = record;
  return Status::success();
}

Status WorkloadRegistry::restore_contract(const WorkloadContract& contract) {
  if (contracts_.find(key_of(contract.id)) == contracts_.end() &&
      contracts_.size() >= static_cast<std::size_t>(max_contracts_)) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "contract registry is full while restoring persisted state");
  }
  WorkloadContract restored = contract;
  const Digest256 recomputed = compute_contract_digest(restored);
  if (!restored.definition_digest.is_zero() && restored.definition_digest != recomputed) {
    return Status::failure(ErrorCode::CORRUPT_STATE,
                           "persisted contract " + restored.id.value() +
                               " content does not match its recorded digest");
  }
  restored.definition_digest = recomputed;
  contracts_[key_of(restored.id)] = restored;
  return Status::success();
}

void WorkloadRegistry::clear() {
  workloads_.clear();
  contracts_.clear();
  stats_ = WorkloadRegistryStats{};
}

}  // namespace aifc
