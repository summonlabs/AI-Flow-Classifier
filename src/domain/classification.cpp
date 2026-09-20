// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/domain/classification.hpp"

#include <algorithm>
#include <array>
#include <string>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

struct StateEntry {
  ClassificationState value;
  std::string_view name;
};

constexpr std::array<StateEntry, 7> kStates = {{
    {ClassificationState::UNKNOWN, "UNKNOWN"},
    {ClassificationState::CURRENT, "CURRENT"},
    {ClassificationState::CORROBORATED, "CORROBORATED"},
    {ClassificationState::CONTRADICTED, "CONTRADICTED"},
    {ClassificationState::STALE, "STALE"},
    {ClassificationState::INSUFFICIENT, "INSUFFICIENT"},
    {ClassificationState::REVOKED, "REVOKED"},
}};

struct DispositionEntry {
  EvidenceDisposition value;
  std::string_view name;
};

constexpr std::array<DispositionEntry, 10> kDispositions = {{
    {EvidenceDisposition::SELECTED, "SELECTED"},
    {EvidenceDisposition::CORROBORATING, "CORROBORATING"},
    {EvidenceDisposition::CONTRADICTING, "CONTRADICTING"},
    {EvidenceDisposition::SUBORDINATE, "SUBORDINATE"},
    {EvidenceDisposition::STALE, "STALE"},
    {EvidenceDisposition::WITHDRAWN, "WITHDRAWN"},
    {EvidenceDisposition::REVOKED, "REVOKED"},
    {EvidenceDisposition::REJECTED, "REJECTED"},
    {EvidenceDisposition::EXCLUDED_BY_LIMIT, "EXCLUDED_BY_LIMIT"},
    {EvidenceDisposition::BELOW_THRESHOLD, "BELOW_THRESHOLD"},
}};

}  // namespace

std::string_view to_string(ClassificationState value) noexcept {
  for (const StateEntry& entry : kStates) {
    if (entry.value == value) return entry.name;
  }
  return "UNRECOGNIZED_CLASSIFICATION_STATE";
}

Result<ClassificationState> parse_classification_state(std::string_view text) {
  for (const StateEntry& entry : kStates) {
    if (entry.name == text) return entry.value;
  }
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised classification state: " + std::string(text));
}

std::string_view to_string(EvidenceDisposition value) noexcept {
  for (const DispositionEntry& entry : kDispositions) {
    if (entry.value == value) return entry.name;
  }
  return "UNRECOGNIZED_DISPOSITION";
}

Digest256 compute_classification_digest(const Classification& classification) {
  // Only content participates.  Everything that describes *when* or *by which
  // process* the decision was made (tick, epoch, boot) is excluded, which is what
  // makes the digest reproducible across a coordinator restart and across two
  // independent processes fed the same canonical evidence set.
  BufferWriter writer(kMaxBlobBytes);
  Status status = writer.put_u8(2U);  // digest schema version
  if (status) status = writer.put_u64(classification.flow_id.hi);
  if (status) status = writer.put_u64(classification.flow_id.lo);
  if (status) status = writer.put_u64(classification.flow_generation.value);
  if (status) status = writer.put_u16(static_cast<std::uint16_t>(classification.semantic));
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(classification.state));
  if (status) status = writer.put_u32(classification.confidence.basis_points());
  if (status) status = writer.put_string(classification.selected_evidence.value());
  if (status) status =
      writer.put_u8(static_cast<std::uint8_t>(classification.selected_source));
  if (status) status = writer.put_u32(classification.corroboration_count);
  if (status) status = writer.put_u32(classification.applied_penalty_basis_points);
  if (status) status = writer.put_u64(classification.policy_generation.value);
  if (status) status = writer.put_blob(classification.policy_digest.bytes,
                                       Digest256::kBytes);

  // Citations are sorted by evidence id so that the digest does not depend on the
  // order in which records happened to be considered.
  std::vector<const EvidenceCitation*> citations;
  citations.reserve(classification.citations.size());
  for (const EvidenceCitation& citation : classification.citations) {
    citations.push_back(&citation);
  }
  std::sort(citations.begin(), citations.end(),
            [](const EvidenceCitation* a, const EvidenceCitation* b) { return a->id < b->id; });

  if (status) status = writer.put_u32(static_cast<std::uint32_t>(citations.size()));
  for (const EvidenceCitation* citation : citations) {
    if (!status) break;
    status = writer.put_string(citation->id.value());
    if (status) status = writer.put_string(citation->publisher.value());
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(citation->source));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(citation->state));
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(citation->semantic));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(citation->disposition));
    if (status) status = writer.put_u32(citation->confidence.basis_points());
    if (status) status = writer.put_u64(citation->generation.value);
  }

  const std::size_t contradiction_count = classification.contradictions.size();
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(contradiction_count));
  for (const ClassificationContradiction& contradiction : classification.contradictions) {
    if (!status) break;
    status = writer.put_string(contradiction.left_id.value());
    if (status) status = writer.put_string(contradiction.right_id.value());
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(contradiction.left_class));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(contradiction.left_source));
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(contradiction.right_class));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(contradiction.right_source));
    if (status) status = writer.put_string(contradiction.resolved_by);
  }

  Digest256 digest;
  if (!status) return digest;
  Sha256 hasher;
  hasher.update(writer.bytes());
  hasher.finish(digest.bytes);
  return digest;
}

}  // namespace aifc
