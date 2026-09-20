// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Evidence quality, state and records.
//
// The central rule of this runtime is that the *quality* of evidence is separate
// from its *content*.  Evidence source quality can never be raised by anything a
// peer says about itself: only the authenticated session envelope, the durable
// contract, or the coordinator's own correlation may assign an authoritative
// source.  Heuristic evidence is a lower rank by construction and can never
// outrank a current authenticated declaration.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_EVIDENCE_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_EVIDENCE_HPP

#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "ai_flow_classifier/domain/flow_key.hpp"
#include "ai_flow_classifier/domain/semantic_class.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"
#include "ai_flow_classifier/foundation/math.hpp"

namespace aifc {

// ---------------------------------------------------------------------------
// Evidence source quality
// ---------------------------------------------------------------------------

enum class EvidenceSource : std::uint8_t {
  UNKNOWN = 0,
  // A signed/authenticated declaration from a registered publisher, bound to the
  // session envelope.  The only source that may claim DECLARED_AUTHENTICATED.
  DECLARED_AUTHENTICATED = 1,
  // Derived by the coordinator from a durable workload contract that the
  // publisher registered and the coordinator validated.
  CONTRACT_DERIVED = 2,
  // Correlated by the coordinator across two or more authenticated sessions.
  COORDINATOR_CORRELATED = 3,
  // Derived from endpoint/process/session topology that the runtime observed.
  TOPOLOGY_CORRELATED = 4,
  // Produced by an optional adapter from observable metadata only.  Always lower
  // rank, always labelled, never silent truth.
  HEURISTIC = 5,
};

inline constexpr std::size_t kEvidenceSourceCount = 6U;

[[nodiscard]] std::string_view to_string(EvidenceSource value) noexcept;
[[nodiscard]] Result<EvidenceSource> parse_evidence_source(std::string_view text);
[[nodiscard]] Result<EvidenceSource> decode_evidence_source(std::uint32_t code) noexcept;

// Authority rank.  Strictly higher wins; there are no ties among sources, which
// is what makes precedence deterministic.
[[nodiscard]] std::uint8_t source_rank(EvidenceSource source) noexcept;

// The confidence a source can ever justify, before any explicit penalty.  These
// are constants of the policy, not measurements.
[[nodiscard]] Confidence source_confidence(EvidenceSource source) noexcept;

// True for sources that carry sufficient authority that a conflicting pair of them must
// be reported as a contradiction rather than silently resolved.
[[nodiscard]] bool source_is_authoritative(EvidenceSource source) noexcept;

// True when a record from this source stands or falls with the liveness of the publisher
// session that published it.
//
// DECLARED_AUTHENTICATED, COORDINATOR_CORRELATED and TOPOLOGY_CORRELATED are observations
// *by* a session, so they lose currentness when that session ends.  HEURISTIC is exempt
// because it never had authority to lose.  CONTRACT_DERIVED is exempt because it is not an
// observation at all: it is a statement the coordinator derives from a durable contract,
// and its currentness is governed by the contract being ACTIVE at the current workload
// generation.  Requiring a live publisher session for it would make a restart discard a
// declaration that is still perfectly current.
[[nodiscard]] bool source_requires_live_session(EvidenceSource source) noexcept;

// True only for HEURISTIC.
[[nodiscard]] bool source_is_heuristic(EvidenceSource source) noexcept;

inline std::ostream& operator<<(std::ostream& stream, EvidenceSource value) {
  return stream << to_string(value);
}

// ---------------------------------------------------------------------------
// Evidence state
// ---------------------------------------------------------------------------

// The enumerators are prefixed because EvidenceState is used in expressions that also
// name the sentinel classes of other enums, and an unprefixed CURRENT would be ambiguous
// at a glance in an explanation.  The prefix also means the name of a state can never be
// confused with the name of a semantic class.
enum class EvidenceState : std::uint8_t {
  // Unused or not applicable.
  EVIDENCE_NONE = 0,
  // Carries current authority: the publisher is live in the current coordinator epoch,
  // the generations match, and the freshness window has not elapsed.
  EVIDENCE_CURRENT = 1,
  // Retained for explanation but no longer authoritative.  Liveness, freshness, epoch or
  // generation was lost.  A stale record is still cited, so an operator can see what
  // used to be believed and why it stopped counting.
  EVIDENCE_STALE = 2,
  // Explicitly withdrawn by its publisher, or replaced by a strictly newer generation of
  // the same evidence topic from the same publisher.
  EVIDENCE_SUPERSEDED = 3,
  // Explicitly revoked, or withdrawn because its authority was shown to be invalid.
  EVIDENCE_REVOKED = 4,
  // Present but insufficient to establish anything on its own.
  EVIDENCE_INSUFFICIENT = 5,
  // Rejected: the record was refused and is retained only as a denial record.
  EVIDENCE_REJECTED = 6,
};

[[nodiscard]] std::string_view to_string(EvidenceState value) noexcept;
[[nodiscard]] Result<EvidenceState> parse_evidence_state(std::string_view text);

inline std::ostream& operator<<(std::ostream& stream, EvidenceState value) {
  return stream << to_string(value);
}

// Only CURRENT evidence can carry authority.
[[nodiscard]] inline bool state_carries_authority(EvidenceState state) noexcept {
  return state == EvidenceState::EVIDENCE_CURRENT;
}

// ---------------------------------------------------------------------------
// Evidence payload
// ---------------------------------------------------------------------------

// Publisher supplied metadata.  Every field here is untrusted input that has been
// length/character validated and canonicalised; nothing here is authority.
struct EvidenceMetadata {
  // Free-form topic used for generation ordering within a publisher, for example
  // "workload.rank.7.collective".  Canonical identity rules apply.
  std::string topic;
  // Opaque binding token chosen by the publisher.  Never interpreted.
  std::uint64_t binding = 0;
  // Optional declared reason, surfaced verbatim in explanations.  Bounded and
  // sanitised for control characters; never parsed as authority.
  std::string reason;
  // Optional contract this evidence claims to be derived from.  The coordinator
  // verifies the claim; the claim itself grants nothing.
  ContractId contract;
};

struct EvidenceRecord {
  EvidenceId id;
  // The authenticated publisher that submitted this record.  Assigned by the
  // receiving session envelope, never taken from the payload.
  PublisherId publisher;
  PublisherBootId publisher_boot;
  SessionId session;
  // Epoch of the coordinator incarnation that accepted the record.
  CoordinatorEpoch accepted_epoch;
  // The coordinator incarnation that accepted the record.
  CoordinatorBootId accepted_boot;

  WorkloadId workload;
  WorkloadGeneration workload_generation;
  ContractId contract;
  FlowId flow_id;
  FlowGeneration flow_generation;

  EvidenceGeneration generation;
  // Monotonic per-coordinator acceptance sequence.  Ordering by this value is the
  // canonical total order among records accepted in one epoch.
  Seq accepted_seq;
  // Tick after which the record is stale: accepted_tick + freshness window.
  Tick accepted_tick = kTickNone;
  Tick fresh_until = kTickNone;

  SemanticClass semantic = SemanticClass::UNKNOWN;
  EvidenceSource source = EvidenceSource::UNKNOWN;
  EvidenceState state = EvidenceState::EVIDENCE_CURRENT;
  // Confidence justified by the source alone.  The decision engine never raises a
  // record's confidence; it may only apply an explicit, reported penalty.
  Confidence confidence;

  EvidenceMetadata metadata;

  // Content digest over every authority-relevant field above.  Two records with
  // the same digest are the same record, which makes replay detection exact.
  Digest256 content_digest;

  // Reason a record is not CURRENT, rendered in explanations.  Bounded text.
  std::string state_reason;

  [[nodiscard]] bool carries_authority() const noexcept {
    return state_carries_authority(state);
  }
  // A record is live only when it carries authority and the decision tick has not
  // passed its freshness deadline.
  [[nodiscard]] bool is_live_at(Tick tick) const noexcept {
    return carries_authority() && fresh_until != kTickNone && tick <= fresh_until;
  }
};

// Computes the canonical content digest.  The digest covers identity, binding,
// class, source, generation and the metadata that affects meaning.  It does not
// cover acceptance bookkeeping (accepted_seq, accepted_tick, state) because those
// describe where the record sits, not what it says.
[[nodiscard]] Digest256 compute_evidence_digest(const EvidenceRecord& record);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_EVIDENCE_HPP
