// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Flow registry: keys to incarnations, and incarnations to keys.
//
// Both directions are indexed, so neither "what is this generation of this flow"
// nor "which flow does this identity belong to" is a linear scan.  The registry is
// bounded, and a full registry refuses an insert with CAPACITY_EXCEEDED rather than
// evicting a live flow.  Silent eviction of live state would be a correctness bug,
// not a resource policy.

#ifndef AI_FLOW_CLASSIFIER_STORE_FLOW_REGISTRY_HPP
#define AI_FLOW_CLASSIFIER_STORE_FLOW_REGISTRY_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

enum class FlowRegistryOutcome : std::uint8_t {
  CREATED = 0,
  // An identical (key, generation) registration was already present.  Idempotent.
  REPEATED = 1,
  // A strictly larger generation replaced the previous incarnation of this key.
  GENERATION_ADVANCED = 2,
};

[[nodiscard]] std::string_view to_string(FlowRegistryOutcome outcome) noexcept;

struct FlowRegistryStats {
  std::uint64_t registrations = 0;
  std::uint64_t repeats = 0;
  std::uint64_t generation_advances = 0;
  std::uint64_t capacity_rejections = 0;
  std::uint64_t lookups = 0;
  std::size_t size = 0;
};

class FlowRegistry {
 public:
  // The highest generation a caller may name.  The value is peer-supplied, so it is bounded here
  // rather than trusted: a peer that could register generation 2^64-1 would make "the next
  // generation" unrepresentable and pin the key permanently, for every publisher.
  static constexpr std::uint64_t kMaxAcceptableGeneration = (1ULL << 62U);

  explicit FlowRegistry(std::uint32_t max_flows) : max_flows_(max_flows) {}

  // Registers or renews a flow incarnation.
  //
  //   * A key that has never been seen creates generation 1 when requested with
  //     generation 0, or the requested generation when it is 1 or more.
  //   * The same key with the same generation is an idempotent repeat: it renews
  //     last_activity_tick and does not disturb anything derived from the key.
  //   * The same key with a strictly larger generation fences the previous
  //     incarnation.  The caller is told, so that derived classifications for the
  //     previous generation can be marked stale rather than silently inherited.
  //   * The same key with a strictly smaller generation is STALE_GENERATION.
  Result<FlowRegistration> register_flow(const FlowKey& key, FlowGeneration requested_generation,
                                         const SessionId& session, Tick tick);

  // Looks up the current incarnation for a key.  UNKNOWN_FLOW when absent.
  [[nodiscard]] Result<FlowRecord> find_by_key(const FlowKey& key) const;

  // Looks up an incarnation by identity.  UNKNOWN_FLOW when absent.
  [[nodiscard]] Result<FlowRecord> find_by_id(const FlowId& id) const;

  // Looks up a specific (identity, generation) pair.  This is the only form that
  // proves currentness, because an identity alone says nothing about generation.
  [[nodiscard]] Result<FlowRecord> find_generation(const FlowId& id,
                                                   FlowGeneration generation) const;

  // True when the record is the current incarnation of its key at the given
  // generation.  A matching identity with a non-matching generation is not current.
  [[nodiscard]] bool is_current(const FlowRecord& record) const;

  // Marks the incarnation as retired by removing it from the current map while
  // keeping its history record available to the caller.
  Status retire_flow(const FlowId& id, FlowGeneration generation, Tick tick);

  [[nodiscard]] std::vector<FlowRecord> snapshot_flows() const;
  Status restore_flow(const FlowRecord& record);

  void clear();
  [[nodiscard]] std::size_t size() const noexcept { return current_.size(); }
  [[nodiscard]] std::uint32_t capacity() const noexcept { return max_flows_; }
  [[nodiscard]] const FlowRegistryStats& stats() const noexcept { return stats_; }

 private:
  std::unordered_map<FlowKey, FlowRecord, detail::FlowKeyHash> current_;
  std::unordered_map<Id128, std::vector<FlowRecord>> history_;
  std::uint32_t max_flows_ = 0;
  // The lookup counter is instrumentation for a read-only operation, so it is mutable
  // and updated under the caller's synchronisation.
  mutable FlowRegistryStats stats_{};
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_STORE_FLOW_REGISTRY_HPP
