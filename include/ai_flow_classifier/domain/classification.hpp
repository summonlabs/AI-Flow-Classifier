// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Classifications, contradictions, revocations and explanations.
//
// A Classification is the answer to the product question.  It is bound to a flow
// generation and to a policy generation, it cites the exact evidence that produced
// it, and it carries a digest that is reproducible from that evidence.  It is
// never a bare label.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_CLASSIFICATION_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_CLASSIFICATION_HPP

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"
#include "ai_flow_classifier/foundation/math.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/semantic_class.hpp"

namespace aifc {

// The final evidence-state verdict reported alongside a class.  It summarises the
// state of the winning evidence, not of every record considered.
enum class ClassificationState : std::uint8_t {
  UNKNOWN = 0,
  // One current, authoritative evidence source selected the class outright.
  CURRENT = 1,
  // Current authoritative sources agree on the class, one of them leading.
  CORROBORATED = 2,
  // Current authoritative sources disagree on the class.  The class is still
  // reported (the precedence winner) but the disagreement is explicit and the
  // confidence carries the reported penalty.
  CONTRADICTED = 3,
  // The best available evidence is not current.  A class may be reported as a
  // historical statement, never as a current one.
  STALE = 4,
  // Nothing publishable was available.  The class is UNKNOWN with confidence zero.
  INSUFFICIENT = 5,
  // The previous classification for this flow generation was explicitly revoked.
  REVOKED = 6,
};

[[nodiscard]] std::string_view to_string(ClassificationState value) noexcept;
[[nodiscard]] Result<ClassificationState> parse_classification_state(std::string_view text);

// Why a particular evidence record did or did not count.  Every considered record
// produces exactly one disposition, so an explanation is exhaustive over what the
// engine looked at.
enum class EvidenceDisposition : std::uint8_t {
  // Selected as the leading support for the reported class.
  SELECTED = 0,
  // Current and authoritative, agrees with the reported class.
  CORROBORATING = 1,
  // Current and authoritative, disagrees with the reported class.
  CONTRADICTING = 2,
  // Current, but not authoritative (heuristic): noted, never decisive, never a
  // contradiction.
  SUBORDINATE = 3,
  // Was current, no longer is (liveness, freshness, generation or epoch).
  STALE = 4,
  // Explicitly withdrawn by its publisher.
  WITHDRAWN = 5,
  // Explicitly revoked.
  REVOKED = 6,
  // Rejected by policy before it could count.
  REJECTED = 7,
  // Considered but excluded by the policy's consideration cap.  Reported so that
  // the cap is visible rather than silent.
  EXCLUDED_BY_LIMIT = 8,
  // Confident enough to matter but below the publishable threshold, so it did not
  // promote the reported class.
  BELOW_THRESHOLD = 9,
};

[[nodiscard]] std::string_view to_string(EvidenceDisposition value) noexcept;

inline std::ostream& operator<<(std::ostream& stream, ClassificationState value) {
  return stream << to_string(value);
}

inline std::ostream& operator<<(std::ostream& stream, EvidenceDisposition value) {
  return stream << to_string(value);
}

struct EvidenceCitation {
  EvidenceId id;
  PublisherId publisher;
  EvidenceSource source = EvidenceSource::UNKNOWN;
  EvidenceState state = EvidenceState::EVIDENCE_NONE;
  SemanticClass semantic = SemanticClass::UNKNOWN;
  EvidenceDisposition disposition = EvidenceDisposition::SELECTED;
  Confidence confidence;
  EvidenceGeneration generation;
  Seq accepted_seq = 0;
  Tick accepted_tick = kTickNone;
  Tick fresh_until = kTickNone;
  std::string detail;
};

struct ClassificationContradiction {
  EvidenceId left_id;
  EvidenceId right_id;
  SemanticClass left_class = SemanticClass::UNKNOWN;
  EvidenceSource left_source = EvidenceSource::UNKNOWN;
  SemanticClass right_class = SemanticClass::UNKNOWN;
  EvidenceSource right_source = EvidenceSource::UNKNOWN;
  // Deterministic ordering: left always outranks right, or, at equal rank, left
  // always has the smaller evidence id.
  std::string resolved_by;
};

struct Classification {
  FlowId flow_id;
  FlowGeneration flow_generation;
  SemanticClass semantic = SemanticClass::UNKNOWN;
  ClassificationState state = ClassificationState::UNKNOWN;
  Confidence confidence;

  // The evidence that selected the class.  Empty when state is INSUFFICIENT or
  // REVOKED.
  EvidenceId selected_evidence;
  EvidenceSource selected_source = EvidenceSource::UNKNOWN;

  // Every evidence record that was considered, in canonical order.
  std::vector<EvidenceCitation> citations;
  std::vector<ClassificationContradiction> contradictions;

  // Number of current, authoritative records that agree with the reported class.
  std::uint32_t corroboration_count = 0;
  // Explicit penalty applied for contradictions, exactly as configured.
  std::uint32_t applied_penalty_basis_points = 0;

  ClassifierPolicyGeneration policy_generation;
  Digest256 policy_digest;
  CoordinatorEpoch coordinator_epoch;
  CoordinatorBootId coordinator_boot;
  Tick decided_tick = kTickNone;

  // Reproducible digest over the decision content.  Excludes every field that
  // describes when or by which process the decision was made, so two runs over
  // the same evidence set agree exactly.
  Digest256 digest;

  [[nodiscard]] bool is_unknown() const noexcept { return semantic == SemanticClass::UNKNOWN; }

  // Two classifications are equal when they are the same decision: same flow generation, same
  // class, same confidence, same policy and the same reproducible content digest.  Equality is
  // defined in terms of the digest on purpose, so that "these two runs agree" is exactly the
  // property the determinism tests assert, rather than a field-by-field comparison that could
  // drift out of step with the digest.
  friend bool operator==(const Classification& a, const Classification& b) noexcept {
    return a.flow_id == b.flow_id && a.flow_generation == b.flow_generation &&
           a.semantic == b.semantic && a.state == b.state &&
           a.confidence.basis_points() == b.confidence.basis_points() &&
           a.policy_generation == b.policy_generation && a.digest == b.digest;
  }
  friend bool operator!=(const Classification& a, const Classification& b) noexcept {
    return !(a == b);
  }
};

// Computes the digest described above.  Callers must populate every content field
// before calling; the function is a pure function of those fields.
[[nodiscard]] Digest256 compute_classification_digest(const Classification& classification);

struct RevocationRecord {
  FlowId flow_id;
  FlowGeneration flow_generation;
  EvidenceId evidence_id;
  // Session that issued the revocation, and the publisher it was authenticated as.
  SessionId revoked_by_session;
  PublisherId revoked_by_publisher;
  CoordinatorEpoch epoch;
  Seq seq = 0;
  Tick revoked_tick = kTickNone;
  std::string reason;
};

// A supersession is recorded whenever a strictly newer generation of the same
// evidence topic from the same publisher displaces an older one.
struct SupersessionRecord {
  EvidenceId previous_id;
  EvidenceId replacement_id;
  EvidenceGeneration previous_generation;
  EvidenceGeneration replacement_generation;
  PublisherId publisher;
  Seq seq = 0;
  Tick recorded_tick = kTickNone;
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_CLASSIFICATION_HPP
