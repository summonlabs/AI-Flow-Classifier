// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/config.hpp"

#include <string>

namespace aifc {
namespace {

[[nodiscard]] std::string decimal(std::uint32_t value) { return std::to_string(value); }

template <typename T>
void clamp_to(T& value, T lower, T upper) noexcept {
  if (value < lower) {
    value = lower;
  } else if (value > upper) {
    value = upper;
  }
}

}  // namespace

std::string product_version_string() {
  return decimal(kProductVersionMajor) + "." + decimal(kProductVersionMinor) + "." +
         decimal(kProductVersionPatch);
}

std::string product_banner() {
  return "AI Flow Classifier " + product_version_string() + " (protocol " +
         decimal(kProtocolVersion) + ", persistence " + decimal(kPersistenceGeneration) +
         ", trace digest)";
}

ResourceLimits ResourceLimits::effective() const noexcept {
  ResourceLimits out = *this;

  // Hard structural bounds.  A configured value can only reduce these.
  clamp_to<std::uint32_t>(out.max_frame_payload, 64U, kMaxFramePayload);
  clamp_to<std::uint32_t>(out.max_string_bytes, 1U, kMaxStringBytes);
  clamp_to<std::uint32_t>(out.max_blob_bytes, 1U, kMaxBlobBytes);
  clamp_to<std::uint32_t>(out.max_collection_count, 1U, kMaxCollectionCount);
  clamp_to<std::uint32_t>(out.max_batch_keys, 1U, kMaxBatchKeys);

  // Registry and history bounds.  Zero is honoured as zero, never as unbounded:
  // a zero bound means the corresponding structure refuses every insert.
  clamp_to<std::uint32_t>(out.max_flows, 0U, 1U << 22);
  clamp_to<std::uint32_t>(out.max_publishers, 0U, 1U << 20);
  clamp_to<std::uint32_t>(out.max_workloads, 0U, 1U << 20);
  clamp_to<std::uint32_t>(out.max_contracts, 0U, 1U << 20);
  clamp_to<std::uint32_t>(out.max_pending_contracts, 0U, 1U << 20);
  clamp_to<std::uint32_t>(out.max_sessions, 0U, 1U << 16);
  clamp_to<std::uint32_t>(out.max_config_overrides, 0U, 1U << 16);

  clamp_to<std::uint32_t>(out.max_evidence_per_flow, 0U, 4096U);
  clamp_to<std::uint32_t>(out.max_evidence_records, 0U, 1U << 24);
  clamp_to<std::uint32_t>(out.max_decisions_per_flow, 0U, 1024U);
  clamp_to<std::uint32_t>(out.max_contradictions_per_flow, 0U, 4096U);
  clamp_to<std::uint32_t>(out.max_contradictions, 0U, 1U << 24);
  clamp_to<std::uint32_t>(out.max_supersessions, 0U, 1U << 24);
  clamp_to<std::uint32_t>(out.max_revocations, 0U, 1U << 24);
  clamp_to<std::uint32_t>(out.max_flow_key_index, 0U, 1U << 24);

  clamp_to<std::uint32_t>(out.max_workers, 0U, 256U);
  clamp_to<std::uint32_t>(out.max_queue_depth, 0U, 1U << 20);
  clamp_to<std::uint32_t>(out.max_inflight_requests, 0U, 1U << 20);
  clamp_to<std::uint32_t>(out.max_retry_attempts, 0U, 64U);

  if (out.default_freshness_window == 0) {
    out.default_freshness_window = 1;
  }
  if (out.max_session_idle_ticks == 0) {
    out.max_session_idle_ticks = 1;
  }
  return out;
}

bool limits_are_structurally_valid(const ResourceLimits& limits) noexcept {
  const ResourceLimits clamped = limits.effective();
  return clamped.max_frame_payload <= kMaxFramePayload &&
         clamped.max_string_bytes <= kMaxStringBytes && clamped.max_blob_bytes <= kMaxBlobBytes &&
         clamped.max_collection_count <= kMaxCollectionCount &&
         clamped.max_batch_keys <= kMaxBatchKeys;
}

}  // namespace aifc
