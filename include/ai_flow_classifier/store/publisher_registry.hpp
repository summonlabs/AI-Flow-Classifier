// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Publisher registry: durable descriptors plus in-memory liveness.
//
// The split between PublisherRecord (durable) and PublisherRegistration (volatile)
// is the mechanism that makes a coordinator restart safe.  A restart reloads the
// durable half and deliberately does not reload liveness: a restarted coordinator
// has no sessions, so every publisher starts out not live, and evidence bound to
// the previous epoch is stale by construction rather than by a check that someone
// could forget.

#ifndef AI_FLOW_CLASSIFIER_STORE_PUBLISHER_REGISTRY_HPP
#define AI_FLOW_CLASSIFIER_STORE_PUBLISHER_REGISTRY_HPP

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "ai_flow_classifier/domain/publisher.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

struct PublisherRegistryStats {
  std::uint64_t registrations = 0;
  std::uint64_t boot_advances = 0;
  std::uint64_t sessions_opened = 0;
  std::uint64_t sessions_closed = 0;
  std::uint64_t liveness_expirations = 0;
  std::uint64_t capacity_rejections = 0;
  std::uint64_t replay_rejections = 0;
  std::size_t publishers = 0;
  std::size_t live = 0;
};

class PublisherRegistry {
 public:
  PublisherRegistry(std::uint32_t max_publishers, std::uint64_t idle_ticks)
      : max_publishers_(max_publishers), idle_ticks_(idle_ticks == 0 ? 1 : idle_ticks) {}

  // Binds an authenticated session to a publisher identity.
  //
  // The boot id is supplied by the caller from the *authenticated envelope*, not
  // from anything the peer said about itself.  A boot id lower than the highest
  // observed boot id is STALE_BOOT_ID; an equal boot id opens a second session for
  // the same incarnation, which is legal (a publisher may reconnect) but is
  // reported so that the caller can decide whether to fence the old session.
  Result<PublisherRegistration> bind_session(const PublisherId& id, PublisherBootId boot,
                                             CoordinatorEpoch epoch, CoordinatorBootId coordinator_boot,
                                             EvidenceSource max_source, const SessionId& session,
                                             Tick tick, std::string description);

  // Marks a session as no longer present.  This is not an inference: it is what
  // happens when the transport reports the connection gone, or when a coordinator
  // epoch advances.
  Status end_session(const PublisherId& id, PublisherBootId boot, Tick tick);

  // Closes one named session of an incarnation.  The incarnation stays live while another of its
  // sessions remains, which is what keeps a reconnect from taking over authority it does not own.
  // An empty session identity means "close every session of this incarnation".
  Status end_specific_session(const PublisherId& id, PublisherBootId boot, const SessionId& session,
                              Tick tick);

  // Recomputes liveness from last_seen_tick.  Liveness is never assumed and never
  // inferred from the fact that a publisher was seen recently in another epoch.
  // Returns the number of publishers that transitioned LIVE or IDLE to a weaker
  // state as a result of this sweep.
  std::uint32_t expire_liveness(Tick tick);

  Status touch(const PublisherId& id, PublisherBootId boot, Tick tick);

  // Binds a session to a different boot without any durability claim, used by the
  // revalidation path after a coordinator restart.
  Status require_revalidation(const PublisherId& id);

  [[nodiscard]] Result<PublisherRegistration> find(const PublisherId& id) const;

  // True only when the publisher is LIVE at this exact boot.  This is the check the
  // evidence admission path uses.
  [[nodiscard]] bool is_live(const PublisherId& id, PublisherBootId boot) const;

  // Records that a publisher has used an evidence generation.  A repeat or a lower
  // value is REPLAY_DETECTED, which is what makes replay of a previously accepted
  // publication harmless.
  Status observe_evidence_generation(const PublisherId& id, PublisherBootId boot,
                                     EvidenceGeneration generation);

  // Durable descriptors, for persistence.  Liveness is intentionally absent.
  [[nodiscard]] std::vector<PublisherRecord> snapshot_records() const;

  // Volatile registrations, sorted by publisher identity.  Used to build the
  // authority context a decision is evaluated against.
  [[nodiscard]] std::vector<PublisherRegistration> registrations() const;
  Status restore_records(const std::vector<PublisherRecord>& records, Tick tick);

  // Drops all volatile sessions and returns the publishers to a not-live state.
  // Called on coordinator restart after restoring durable records.
  void clear_sessions();

  void clear();
  [[nodiscard]] std::size_t size() const noexcept { return publishers_.size(); }
  [[nodiscard]] std::uint32_t capacity() const noexcept { return max_publishers_; }
  [[nodiscard]] const PublisherRegistryStats& stats() const noexcept { return stats_; }

 private:
  std::unordered_map<std::string, PublisherRegistration> publishers_;
  std::unordered_map<std::string, PublisherRecord> records_;
  std::uint32_t max_publishers_ = 0;
  std::uint64_t idle_ticks_ = 1;
  PublisherRegistryStats stats_{};
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_STORE_PUBLISHER_REGISTRY_HPP
