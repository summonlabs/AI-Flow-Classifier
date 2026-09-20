// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Publishers: authenticated metadata sources.
//
// A publisher is a process that has established an authenticated session with the
// coordinator.  Its authority is bound to three independent values:
//
//   PublisherId        stable identity, chosen by the publisher
//   PublisherBootId    incarnation of the publisher process
//   CoordinatorEpoch   incarnation of the coordinator that accepted the session
//
// All three must be current for evidence to carry authority.  A restart of the
// publisher advances the boot id and every record bound to the previous boot id
// becomes stale.  A restart of the coordinator advances the epoch and every
// session, and therefore every liveness claim, is gone.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_PUBLISHER_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_PUBLISHER_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"

namespace aifc {

enum class PublisherState : std::uint8_t {
  // Registered, no session has ever been bound to this boot.
  REGISTERED = 0,
  // A session is bound in the current epoch and the publisher has been seen
  // within the idle window.  Only this state supports authoritative evidence.
  LIVE = 1,
  // A session was bound in the current epoch but the publisher has not been seen
  // within the idle window.  Liveness is not inferred; it expires.
  IDLE = 2,
  // The bound session ended, or the publisher was explicitly retired.
  DEAD = 3,
};

[[nodiscard]] std::string_view to_string(PublisherState value) noexcept;
[[nodiscard]] Result<PublisherState> parse_publisher_state(std::string_view text);

// The strongest evidence source a publisher's session is permitted to assert.
// This is a coordinator-side decision recorded at registration time; it is never
// requested by the peer.  A session admitted as HEURISTIC cannot declare truth
// even if its payload claims DECLARED_AUTHENTICATED.
struct PublisherRegistration {
  PublisherId id;
  PublisherBootId boot;
  CoordinatorEpoch registered_epoch;
  CoordinatorBootId registered_boot;
  SessionId session;
  PublisherState state = PublisherState::REGISTERED;
  EvidenceSource max_source = EvidenceSource::HEURISTIC;
  // Every session currently bound to this incarnation, including `session` itself.
  //
  // A publisher incarnation may hold more than one session: a reconnect while the previous
  // connection is still open is legal and does not supersede it.  Keeping the set is what makes
  // that safe.  Without it, a peer that knows a publisher identity and boot could bind a second
  // session and then disconnect, staling the first session's evidence -- de-authorising a live
  // publisher by connecting and hanging up.
  std::vector<SessionId> live_sessions;
  Tick registered_tick = kTickNone;
  Tick last_seen_tick = kTickNone;
  // Highest evidence generation this publisher has used.  A publication must use a
  // strictly larger value; a repeat or a lower value is REPLAY_DETECTED.
  EvidenceGeneration highest_generation;
  std::uint64_t evidence_accepted = 0;
  std::uint64_t evidence_rejected = 0;
  std::uint64_t sessions_opened = 0;
  std::string description;
};

// A durable publisher descriptor.  This is the part of publisher state that is
// persisted and that survives a coordinator restart: identity, the highest
// observed boot id and generation, and the permitted source ceiling.
//
// Liveness is deliberately not part of this record.  A restart cannot resurrect
// liveness, so there is nothing to resurrect.
struct PublisherRecord {
  PublisherId id;
  PublisherBootId highest_boot;
  EvidenceGeneration highest_generation;
  EvidenceSource max_source = EvidenceSource::HEURISTIC;
  Tick first_seen_tick = kTickNone;
  std::uint64_t last_seen_wall_millis = 0;
  std::uint64_t total_evidence_accepted = 0;
  std::string description;
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_PUBLISHER_HPP
