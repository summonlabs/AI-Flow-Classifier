// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/domain/evidence.hpp"

#include <array>
#include <string>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

struct SourceEntry {
  EvidenceSource value;
  std::string_view name;
  std::uint8_t rank;
  std::uint32_t basis_points;
};

// Rank and confidence are properties of the *source*, not of the payload.  The
// gaps between ranks are deliberate: nothing computed at run time may promote one
// source into another's band.
constexpr std::array<SourceEntry, kEvidenceSourceCount> kSources = {{
    {EvidenceSource::UNKNOWN, "UNKNOWN", 0U, 0U},
    {EvidenceSource::HEURISTIC, "HEURISTIC", 1U, 2000U},
    {EvidenceSource::TOPOLOGY_CORRELATED, "TOPOLOGY_CORRELATED", 2U, 5000U},
    {EvidenceSource::COORDINATOR_CORRELATED, "COORDINATOR_CORRELATED", 3U, 7000U},
    {EvidenceSource::CONTRACT_DERIVED, "CONTRACT_DERIVED", 4U, 8000U},
    {EvidenceSource::DECLARED_AUTHENTICATED, "DECLARED_AUTHENTICATED", 5U, 9000U},
}};

[[nodiscard]] const SourceEntry* find_source(EvidenceSource value) noexcept {
  for (const SourceEntry& entry : kSources) {
    if (entry.value == value) return &entry;
  }
  return nullptr;
}

struct StateEntry {
  EvidenceState value;
  std::string_view name;
};

constexpr std::array<StateEntry, 7> kStates = {{
    {EvidenceState::EVIDENCE_NONE, "NONE"},
    {EvidenceState::EVIDENCE_CURRENT, "CURRENT"},
    {EvidenceState::EVIDENCE_STALE, "STALE"},
    {EvidenceState::EVIDENCE_SUPERSEDED, "SUPERSEDED"},
    {EvidenceState::EVIDENCE_REVOKED, "REVOKED"},
    {EvidenceState::EVIDENCE_INSUFFICIENT, "INSUFFICIENT"},
    {EvidenceState::EVIDENCE_REJECTED, "REJECTED"},
}};

}  // namespace

std::string_view to_string(EvidenceSource value) noexcept {
  const SourceEntry* entry = find_source(value);
  return entry != nullptr ? entry->name : "UNRECOGNIZED_SOURCE";
}

Result<EvidenceSource> parse_evidence_source(std::string_view text) {
  for (const SourceEntry& entry : kSources) {
    if (entry.name == text) return entry.value;
  }
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised evidence source: " + std::string(text));
}

Result<EvidenceSource> decode_evidence_source(std::uint32_t code) noexcept {
  for (const SourceEntry& entry : kSources) {
    if (static_cast<std::uint32_t>(entry.value) == code) return entry.value;
  }
  // An unknown source code is the weakest possible source, never a stronger one.
  // This is the decode-side half of "a malformed label cannot produce a privileged
  // semantic class".
  return EvidenceSource::UNKNOWN;
}

std::uint8_t source_rank(EvidenceSource source) noexcept {
  const SourceEntry* entry = find_source(source);
  return entry != nullptr ? entry->rank : 0U;
}

Confidence source_confidence(EvidenceSource source) noexcept {
  const SourceEntry* entry = find_source(source);
  const std::uint32_t basis_points = entry != nullptr ? entry->basis_points : 0U;
  return Confidence::from_basis_points(basis_points);
}

bool source_is_authoritative(EvidenceSource source) noexcept {
  // Authoritative means "may participate in a contradiction".  Heuristic evidence is never
  // authoritative: a guess disagreeing with a declaration is not a contradiction, it is a
  // guess that lost.
  return source_rank(source) >= source_rank(EvidenceSource::CONTRACT_DERIVED);
}

bool source_requires_live_session(EvidenceSource source) noexcept {
  switch (source) {
    case EvidenceSource::DECLARED_AUTHENTICATED:
    case EvidenceSource::COORDINATOR_CORRELATED:
    case EvidenceSource::TOPOLOGY_CORRELATED:
      return true;
    case EvidenceSource::CONTRACT_DERIVED:
    case EvidenceSource::HEURISTIC:
    case EvidenceSource::UNKNOWN:
      return false;
  }
  return true;
}

bool source_is_heuristic(EvidenceSource source) noexcept {
  return source == EvidenceSource::HEURISTIC;
}

std::string_view to_string(EvidenceState value) noexcept {
  for (const StateEntry& entry : kStates) {
    if (entry.value == value) return entry.name;
  }
  return "UNRECOGNIZED_STATE";
}

Result<EvidenceState> parse_evidence_state(std::string_view text) {
  for (const StateEntry& entry : kStates) {
    if (entry.name == text) return entry.value;
  }
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised evidence state: " + std::string(text));
}

Digest256 compute_evidence_digest(const EvidenceRecord& record) {
  BufferWriter writer(kMaxBlobBytes);
  Status status = writer.put_u8(1U);  // digest schema version
  if (status) status = writer.put_string(record.id.value());
  if (status) status = writer.put_string(record.publisher.value());
  if (status) status = writer.put_u64(record.publisher_boot.value);
  if (status) status = writer.put_string(record.workload.value());
  if (status) status = writer.put_u64(record.workload_generation.value);
  if (status) status = writer.put_string(record.contract.value());
  if (status) status = writer.put_u64(record.flow_id.hi);
  if (status) status = writer.put_u64(record.flow_id.lo);
  if (status) status = writer.put_u64(record.flow_generation.value);
  if (status) status = writer.put_u64(record.generation.value);
  if (status) status = writer.put_u16(static_cast<std::uint16_t>(record.semantic));
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(record.source));
  if (status) status = writer.put_u32(record.confidence.basis_points());
  if (status) status = writer.put_string(record.metadata.topic);
  if (status) status = writer.put_u64(record.metadata.binding);
  if (status) status = writer.put_string(record.metadata.reason);
  if (status) status = writer.put_string(record.metadata.contract.value());
  if (status) status = writer.put_u64(record.fresh_until);

  Digest256 digest;
  if (!status) {
    // The encoder bound is a hard structural limit and the record fields are all
    // individually bounded, so exhausting it would be an internal defect rather
    // than bad input.  A zero digest is a deterministic, detectable sentinel.
    return digest;
  }
  Sha256 hasher;
  hasher.update(writer.bytes());
  hasher.finish(digest.bytes);
  return digest;
}

}  // namespace aifc
