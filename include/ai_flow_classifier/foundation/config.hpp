// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Compile time constants: product identity, wire/persistence compatibility
// generations, hard resource bounds and the effective resource limits structure.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_CONFIG_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_CONFIG_HPP

#include <ostream>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace aifc {

// ---------------------------------------------------------------------------
// Product identity
// ---------------------------------------------------------------------------

inline constexpr std::uint32_t kProductVersionMajor = 1;
inline constexpr std::uint32_t kProductVersionMinor = 0;
inline constexpr std::uint32_t kProductVersionPatch = 0;

// Wire compatibility generation.  A peer whose protocol version is outside
// [kProtocolVersionMin, kProtocolVersion] is refused deterministically; the product version never
// implies wire compatibility and vice versa.
//
// Version 2 gave each response body its own message kind.  Version 1 reused one kind for five
// different bodies, so a peer that decoded by kind -- the only sound way to decode -- could not tell
// a contract response from a statistics response.
inline constexpr std::uint16_t kProtocolVersion = 2;
inline constexpr std::uint16_t kProtocolVersionMin = 2;

// On-disk format generation.  A file written by a different generation is
// rejected as UNSUPPORTED_FORMAT_VERSION and is never partially applied.
inline constexpr std::uint16_t kPersistenceGeneration = 1;

// Returned verbatim by the CLI and by PROTOCOL_VERSION negotiation.
[[nodiscard]] std::string product_version_string();
[[nodiscard]] std::string product_banner();

// ---------------------------------------------------------------------------
// Hard structural bounds
//
// These are compile time and can never be raised by configuration or by input.
// They exist so that no externally supplied length can reach an allocation
// unchecked.
// ---------------------------------------------------------------------------

// Largest frame payload the runtime will ever accept or emit.
inline constexpr std::uint32_t kMaxFramePayload = 4U * 1024U * 1024U;

// Largest canonical record blob (workload contract, evidence metadata, ...).
inline constexpr std::uint32_t kMaxBlobBytes = 64U * 1024U;

// Largest single canonical string (identifier, label, topic, reason, ...).
inline constexpr std::uint32_t kMaxStringBytes = 512U;

// Largest decoded collection count in a single canonical record.
inline constexpr std::uint32_t kMaxCollectionCount = 4096U;

// Largest number of distinct flow keys that may appear in one batch request.
inline constexpr std::uint32_t kMaxBatchKeys = 4096U;

// Largest number of evidence records that may be cited by one explanation.
inline constexpr std::uint32_t kMaxExplanationEvidence = 64U;

// ---------------------------------------------------------------------------
// Effective resource limits
// ---------------------------------------------------------------------------

struct ResourceLimits {
  // Registry sizes.  Each is enforced on insert with ErrorCode::CAPACITY_EXCEEDED.
  std::uint32_t max_flows = 65536U;
  std::uint32_t max_publishers = 1024U;
  std::uint32_t max_workloads = 4096U;
  std::uint32_t max_contracts = 4096U;
  std::uint32_t max_pending_contracts = 1024U;
  std::uint32_t max_sessions = 64U;
  std::uint32_t max_config_overrides = 256U;

  // Retained history.  Oldest-first eviction, never silent: evictions are counted
  // and reported through stats().
  std::uint32_t max_evidence_per_flow = 32U;
  std::uint32_t max_evidence_records = 262144U;
  std::uint32_t max_decisions_per_flow = 8U;
  std::uint32_t max_contradictions_per_flow = 16U;
  std::uint32_t max_contradictions = 65536U;
  std::uint32_t max_supersessions = 65536U;
  std::uint32_t max_revocations = 65536U;
  std::uint32_t max_flow_key_index = 131072U;

  // Per-input bounds.  Payload and collection sizes are clamped to the hard
  // structural bounds above by effective().
  std::uint32_t max_frame_payload = kMaxFramePayload;
  std::uint32_t max_string_bytes = kMaxStringBytes;
  std::uint32_t max_blob_bytes = kMaxBlobBytes;
  std::uint32_t max_collection_count = kMaxCollectionCount;
  std::uint32_t max_batch_keys = kMaxBatchKeys;

  // Concurrency and queues.
  std::uint32_t max_workers = 8U;
  std::uint32_t max_queue_depth = 1024U;
  std::uint32_t max_inflight_requests = 256U;
  std::uint32_t max_retry_attempts = 3U;

  // Freshness.  An evidence record whose fresh_until_seq is in the past is stale
  // and loses to any authoritative current declaration, but it is still shown in
  // explanations as stale rather than erased.
  std::uint64_t default_freshness_window = 4096ULL;
  std::uint64_t max_session_idle_ticks = 65536ULL;

  // Note: there is deliberately no heuristic switch here.  ClassifierPolicy owns that decision, and
  // an earlier version of this structure carried a second copy which nothing ever read: it was
  // serialised into the snapshot, so two policies could differ on disk while hashing identically.
  // A setting that decides nothing is worse than no setting at all.

  // Returns a copy clamped to the hard structural bounds.  Any value larger than
  // a hard bound is reduced to it; a value of zero means "zero", never
  // "unbounded".
  [[nodiscard]] ResourceLimits effective() const noexcept;
};

[[nodiscard]] bool limits_are_structurally_valid(const ResourceLimits& limits) noexcept;

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_CONFIG_HPP
