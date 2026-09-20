// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/domain/policy.hpp"

#include <algorithm>
#include <string>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

ClassifierPolicy ClassifierPolicy::initial() {
  ClassifierPolicy policy;
  policy.generation = ClassifierPolicyGeneration{1};
  policy.allow_heuristic_evidence = false;
  policy.limits = ResourceLimits{};
  policy.default_freshness_window = policy.limits.default_freshness_window;
  return policy;
}

Result<ClassifierPolicy> ClassifierPolicy::canonicalize(ClassifierPolicy policy) {
  policy.limits = policy.limits.effective();

  if (policy.default_freshness_window == 0) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "default_freshness_window must be greater than zero");
  }
  if (policy.minimum_publishable_confidence > Confidence::kScale) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "minimum_publishable_confidence exceeds 1.0");
  }
  if (policy.contradiction_penalty > Confidence::kScale) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "contradiction_penalty exceeds 1.0");
  }
  if (policy.max_evidence_considered == 0) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "max_evidence_considered must be greater than zero");
  }
  if (policy.heuristic_adapters.size() > kMaxCollectionCount) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED, "too many heuristic adapters declared");
  }
  if (policy.port_hints.size() > kMaxCollectionCount) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED, "too many port hints declared");
  }

  // A canonical policy is the same policy regardless of declaration order.  This
  // is what allows two independently built policies with equal content to have
  // equal digests, and therefore to produce equal decisions.
  std::sort(policy.heuristic_adapters.begin(), policy.heuristic_adapters.end(),
            [](const HeuristicAdapterPolicy& a, const HeuristicAdapterPolicy& b) {
              return a.name < b.name;
            });
  for (const HeuristicAdapterPolicy& adapter : policy.heuristic_adapters) {
    if (!is_canonical_identity(adapter.name)) {
      return Status::failure(ErrorCode::MALFORMED_INPUT,
                             "heuristic adapter name is not a canonical identity: " + adapter.name);
    }
    if (adapter.max_basis_points > Confidence::kScale) {
      return Status::failure(ErrorCode::INVALID_ARGUMENT,
                             "heuristic adapter " + adapter.name +
                                 " declares a confidence above 1.0");
    }
  }
  for (std::size_t i = 1; i < policy.heuristic_adapters.size(); ++i) {
    if (policy.heuristic_adapters[i - 1].name == policy.heuristic_adapters[i].name) {
      return Status::failure(ErrorCode::DUPLICATE_IDENTITY,
                             "heuristic adapter declared twice: " +
                                 policy.heuristic_adapters[i].name);
    }
  }

  std::sort(policy.port_hints.begin(), policy.port_hints.end(),
            [](const PortHint& a, const PortHint& b) {
              if (a.transport != b.transport) return a.transport < b.transport;
              if (a.port != b.port) return a.port < b.port;
              return a.semantic < b.semantic;
            });
  // Structural facts about a single hint are checked before hint uniqueness and before the hint's
  // relationship to an adapter, so that the error an operator sees names the thing they got wrong
  // rather than the first thing that happens to be checked.
  for (const PortHint& hint : policy.port_hints) {
    if (hint.basis_points > Confidence::kScale) {
      return Status::failure(ErrorCode::INVALID_ARGUMENT,
                             "port hint for port " + std::to_string(hint.port) +
                                 " declares a confidence above 1.0");
    }
  }
  for (std::size_t i = 1; i < policy.port_hints.size(); ++i) {
    const PortHint& previous = policy.port_hints[i - 1];
    const PortHint& current = policy.port_hints[i];
    if (previous.transport == current.transport && previous.port == current.port &&
        previous.semantic == current.semantic) {
      return Status::failure(ErrorCode::DUPLICATE_IDENTITY,
                             "port hint declared twice for the same transport, port and class");
    }
  }

  // A hint attached to an adapter the policy never declares would be permanently unusable while
  // looking like configuration.  Refusing it turns a silent no-op into a visible error, and it keeps
  // the adapter gate from being bypassed by declaring a dangling hint.
  for (const PortHint& hint : policy.port_hints) {
    bool declares_adapter = false;
    for (const HeuristicAdapterPolicy& adapter : policy.heuristic_adapters) {
      if (adapter.name == hint.adapter) declares_adapter = true;
    }
    if (!declares_adapter) {
      return Status::failure(ErrorCode::INVALID_ARGUMENT,
                             "port hint for port " + std::to_string(hint.port) +
                                 " names adapter '" + hint.adapter +
                                 "', which the policy does not declare");
    }
  }

  // Heuristics are only reachable when both switches agree.  A policy that
  // enables adapters while the global switch is off is refused rather than
  // silently neutralised, because a policy that says two different things is a
  // defect the operator needs to see.
  if (!policy.allow_heuristic_evidence) {
    for (const HeuristicAdapterPolicy& adapter : policy.heuristic_adapters) {
      if (adapter.enabled) {
        return Status::failure(
            ErrorCode::INVALID_ARGUMENT,
            "heuristic adapter " + adapter.name +
                " is enabled while allow_heuristic_evidence is false; the policy is contradictory");
      }
    }
    if (!policy.port_hints.empty()) {
      return Status::failure(
          ErrorCode::INVALID_ARGUMENT,
          "port hints are declared while allow_heuristic_evidence is false; the policy is "
          "contradictory");
    }
  }
  return policy;
}

bool ClassifierPolicy::heuristic_enabled(std::string_view adapter_name) const noexcept {
  if (!allow_heuristic_evidence) return false;
  for (const HeuristicAdapterPolicy& adapter : heuristic_adapters) {
    if (adapter.name == adapter_name) return adapter.enabled;
  }
  return false;
}

ClassifierPolicy::HeuristicClaim ClassifierPolicy::claim_of(std::uint64_t binding) noexcept {
  HeuristicClaim claim;
  claim.port = static_cast<std::uint16_t>(binding & 0xFFFFULL);
  claim.transport = static_cast<TransportProtocol>((binding >> 16U) & 0xFFULL);
  return claim;
}

std::uint64_t ClassifierPolicy::hint_binding_of(TransportProtocol transport,
                                               std::uint16_t port) noexcept {
  return (static_cast<std::uint64_t>(transport) << 16U) | static_cast<std::uint64_t>(port);
}

const PortHint* ClassifierPolicy::find_port_hint(TransportProtocol transport,
                                                std::uint16_t port) const noexcept {
  if (!allow_heuristic_evidence) return nullptr;
  for (const PortHint& hint : port_hints) {
    if (hint.transport == transport && hint.port == port && heuristic_enabled(hint.adapter)) {
      return &hint;
    }
  }
  return nullptr;
}

Digest256 compute_policy_digest(const ClassifierPolicy& policy) {
  BufferWriter writer(kMaxBlobBytes);
  Status status = writer.put_u8(2U);  // digest schema version
  // The generation is deliberately excluded: the digest exists to detect content
  // that changed while the generation did not.
  if (status) status = writer.put_bool(policy.allow_heuristic_evidence);
  if (status) status = writer.put_u64(policy.default_freshness_window);
  if (status) status = writer.put_u32(policy.contradiction_penalty);
  if (status) status = writer.put_u32(policy.minimum_publishable_confidence);
  if (status) status = writer.put_u32(policy.max_evidence_considered);

  // Limits participate in decisions (they bound what is considered), so they are
  // part of the policy fingerprint.
  const ResourceLimits& limits = policy.limits;
  const std::uint64_t limit_fields[] = {limits.max_flows,
                                        limits.max_publishers,
                                        limits.max_workloads,
                                        limits.max_contracts,
                                        limits.max_pending_contracts,
                                        limits.max_sessions,
                                        limits.max_config_overrides,
                                        limits.max_evidence_per_flow,
                                        limits.max_evidence_records,
                                        limits.max_decisions_per_flow,
                                        limits.max_contradictions_per_flow,
                                        limits.max_contradictions,
                                        limits.max_supersessions,
                                        limits.max_revocations,
                                        limits.max_flow_key_index,
                                        limits.max_frame_payload,
                                        limits.max_string_bytes,
                                        limits.max_blob_bytes,
                                        limits.max_collection_count,
                                        limits.max_batch_keys,
                                        limits.max_workers,
                                        limits.max_queue_depth,
                                        limits.max_inflight_requests,
                                        limits.max_retry_attempts,
                                        limits.default_freshness_window,
                                        limits.max_session_idle_ticks};
  for (std::uint64_t value : limit_fields) {
    if (!status) break;
    status = writer.put_u64(value);
  }

  if (status) status = writer.put_u32(static_cast<std::uint32_t>(policy.heuristic_adapters.size()));
  for (const HeuristicAdapterPolicy& adapter : policy.heuristic_adapters) {
    if (!status) break;
    status = writer.put_string(adapter.name);
    if (status) status = writer.put_bool(adapter.enabled);
    if (status) status = writer.put_u32(adapter.max_basis_points);
    if (status) status = writer.put_u32(adapter.priority);
  }
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(policy.port_hints.size()));
  for (const PortHint& hint : policy.port_hints) {
    if (!status) break;
    status = writer.put_u8(static_cast<std::uint8_t>(hint.transport));
    if (status) status = writer.put_u16(hint.port);
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(hint.semantic));
    if (status) status = writer.put_u32(hint.basis_points);
    if (status) status = writer.put_string(hint.adapter);
  }

  Digest256 digest;
  if (!status) return digest;
  Sha256 hasher;
  hasher.update(writer.bytes());
  hasher.finish(digest.bytes);
  return digest;
}

}  // namespace aifc
