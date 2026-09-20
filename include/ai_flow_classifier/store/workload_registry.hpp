// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Workload and contract registry.
//
// A contract is the only durable route by which a peer influences classification
// for many flows at once.  Two rules keep that influence honest:
//
//   * a contract must be explicitly activated before it contributes anything: a
//     PENDING proposal is visible but has no authority;
//   * an ACTIVE contract is immutable.  Mutating one is refused, because a changed
//     contract is a different contract and every classification derived from the
//     old one must be stale.

#ifndef AI_FLOW_CLASSIFIER_STORE_WORKLOAD_REGISTRY_HPP
#define AI_FLOW_CLASSIFIER_STORE_WORKLOAD_REGISTRY_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

struct WorkloadRegistryStats {
  std::uint64_t workloads_declared = 0;
  std::uint64_t workload_generation_advances = 0;
  std::uint64_t contracts_proposed = 0;
  std::uint64_t contracts_activated = 0;
  std::uint64_t contracts_retired = 0;
  std::uint64_t contract_mutation_rejections = 0;
  std::uint64_t contract_owner_rejections = 0;
  std::uint64_t capacity_rejections = 0;
  std::size_t workloads = 0;
  std::size_t contracts = 0;
  std::size_t active_contracts = 0;
};

class WorkloadRegistry {
 public:
  WorkloadRegistry(std::uint32_t max_workloads, std::uint32_t max_contracts,
                   std::uint32_t max_pending_contracts)
      : max_workloads_(max_workloads),
        max_contracts_(max_contracts),
        max_pending_contracts_(max_pending_contracts) {}

  // Declares or advances a workload.  A strictly larger generation retires every
  // contract bound to a lower generation and returns them so the caller can report
  // exactly which derived classifications were invalidated.
  Result<WorkloadRecord> declare_workload(const WorkloadId& id, const PublisherId& owner,
                                          WorkloadGeneration generation, Tick tick,
                                          std::string description,
                                          std::vector<WorkloadContract>* retired_contracts);

  [[nodiscard]] Result<WorkloadRecord> find_workload(const WorkloadId& id) const;
  Status retire_workload(const WorkloadId& id, WorkloadGeneration generation, Tick tick);

  // Proposes a contract as PENDING.  The definition digest is computed here, so a
  // caller cannot claim a digest that does not match the content.
  Result<WorkloadContract> propose_contract(WorkloadContract contract, Tick tick);

  // Activates a pending contract.  Activation is the point at which a contract
  // starts to mean something; before it, the contract contributes nothing.
  //
  // Activating a contract for a workload generation retires the previously active
  // contract for that workload and returns it, so that the caller can mark the
  // derived classifications stale.
  Result<WorkloadContract> activate_contract(const ContractId& id, const PublisherId& caller,
                                             Tick tick, WorkloadContract* retired);

  Status retire_contract(const ContractId& id, const PublisherId& caller, Tick tick);

  [[nodiscard]] Result<WorkloadContract> find_contract(const ContractId& id) const;

  // The active contract for a workload at exactly this generation, if any.  This is
  // the lookup that fences derived classification: a contract for another
  // generation is not returned.
  [[nodiscard]] Result<WorkloadContract> find_active_contract(const WorkloadId& workload,
                                                              WorkloadGeneration generation) const;

  // Every active contract, in canonical (contract id) order.  Used by the decision
  // engine, which applies its own scope matching.
  [[nodiscard]] std::vector<WorkloadContract> active_contracts() const;

  [[nodiscard]] std::vector<WorkloadRecord> snapshot_workloads() const;
  [[nodiscard]] std::vector<WorkloadContract> snapshot_contracts() const;
  Status restore_workload(const WorkloadRecord& record);
  Status restore_contract(const WorkloadContract& contract);

  void clear();
  [[nodiscard]] std::size_t workload_count() const noexcept { return workloads_.size(); }
  [[nodiscard]] std::size_t contract_count() const noexcept { return contracts_.size(); }
  [[nodiscard]] std::uint32_t workload_capacity() const noexcept { return max_workloads_; }
  [[nodiscard]] std::uint32_t contract_capacity() const noexcept { return max_contracts_; }
  [[nodiscard]] const WorkloadRegistryStats& stats() const noexcept { return stats_; }

 private:
  std::unordered_map<std::string, WorkloadRecord> workloads_;
  std::unordered_map<std::string, WorkloadContract> contracts_;
  std::uint32_t max_workloads_ = 0;
  std::uint32_t max_contracts_ = 0;
  std::uint32_t max_pending_contracts_ = 0;
  WorkloadRegistryStats stats_{};
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_STORE_WORKLOAD_REGISTRY_HPP
