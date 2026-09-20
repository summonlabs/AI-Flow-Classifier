// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/store/publisher_registry.hpp"

#include <algorithm>
#include <string>

namespace aifc {
namespace {

[[nodiscard]] std::string key_of(const PublisherId& id) { return id.value(); }

}  // namespace

Result<PublisherRegistration> PublisherRegistry::bind_session(
    const PublisherId& id, PublisherBootId boot, CoordinatorEpoch epoch,
    CoordinatorBootId coordinator_boot, EvidenceSource max_source, const SessionId& session,
    Tick tick, std::string description) {
  if (!id.empty() && id.value().empty()) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "publisher identity is empty");
  }
  if (!boot.valid()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "publisher boot id must be greater than zero");
  }
  if (boot.value == 0) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "publisher boot id must be greater than zero");
  }

  auto record_entry = records_.find(key_of(id));
  if (record_entry == records_.end()) {
    if (records_.size() >= static_cast<std::size_t>(max_publishers_)) {
      stats_.capacity_rejections += 1;
      return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                             "publisher registry is full at " + std::to_string(max_publishers_));
    }
    PublisherRecord record;
    record.id = id;
    record.highest_boot = boot;
    record.highest_generation = EvidenceGeneration{};
    record.max_source = max_source;
    record.first_seen_tick = tick;
    record.last_seen_wall_millis = wall_clock_unix_millis();
    record.description = description;
    record_entry = records_.emplace(key_of(id), record).first;
  } else {
    if (boot < record_entry->second.highest_boot) {
      // A lower boot id means the peer is presenting an incarnation that has
      // already been superseded.  Accepting it would resurrect authority that was
      // retired, so it is refused before any state is touched.
      stats_.replay_rejections += 1;
      return Status::failure(ErrorCode::STALE_BOOT_ID,
                             "publisher " + id.value() + " presented boot " + boot.to_string() +
                                 " but boot " + record_entry->second.highest_boot.to_string() +
                                 " has already been observed");
    }
    if (boot > record_entry->second.highest_boot) {
      record_entry->second.highest_boot = boot;
      // A new incarnation has never used any evidence generation, so the observed
      // high-water mark restarts.  Keeping the old value would let the new
      // incarnation be fenced by a generation it never issued.
      record_entry->second.highest_generation = EvidenceGeneration{};
      stats_.boot_advances += 1;
    }
    record_entry->second.last_seen_wall_millis = wall_clock_unix_millis();
    if (record_entry->second.description.empty()) {
      record_entry->second.description = description;
    }
    // The authority ceiling is a coordinator decision and never decreases as a
    // result of a peer reconnecting.
    if (source_rank(max_source) > source_rank(record_entry->second.max_source)) {
      record_entry->second.max_source = max_source;
    }
  }

  auto entry = publishers_.find(key_of(id));
  if (entry == publishers_.end()) {
    if (publishers_.size() >= static_cast<std::size_t>(max_publishers_)) {
      stats_.capacity_rejections += 1;
      return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                             "publisher registry is full at " + std::to_string(max_publishers_));
    }
    PublisherRegistration registration;
    registration.id = id;
    registration.boot = boot;
    registration.registered_epoch = epoch;
    registration.registered_boot = coordinator_boot;
    registration.session = session;
    // A newly bound incarnation is live *because* it has a session.  is_live() answers from
    // live_sessions, so leaving this out makes every first publication from a fresh publisher
    // fail with PUBLISHER_DEAD while the registration itself says LIVE.
    registration.live_sessions.push_back(session);
    registration.state = PublisherState::LIVE;
    registration.max_source = max_source;
    registration.registered_tick = tick;
    registration.last_seen_tick = tick;
    registration.sessions_opened = 1;
    registration.description = description;
    entry = publishers_.emplace(key_of(id), registration).first;
    stats_.registrations += 1;
    stats_.sessions_opened += 1;
  } else {
    PublisherRegistration& registration = entry->second;
    if (boot < registration.boot) {
      stats_.replay_rejections += 1;
      return Status::failure(ErrorCode::STALE_BOOT_ID,
                             "publisher " + id.value() + " session is bound to boot " +
                                 registration.boot.to_string() + "; boot " + boot.to_string() +
                                 " is older");
    }
    if (boot > registration.boot) {
      // A new incarnation starts with no sessions and its own evidence-generation history.
      registration.boot = boot;
      registration.highest_generation = EvidenceGeneration{};
      registration.live_sessions.clear();
    }
    // The connection being bound becomes the current session, and every session bound to this
    // incarnation stays live.  A reconnect therefore does not silently take over the incarnation.
    registration.session = session;
    if (std::find(registration.live_sessions.begin(), registration.live_sessions.end(), session) ==
        registration.live_sessions.end()) {
      registration.live_sessions.push_back(session);
    }
    registration.registered_epoch = epoch;
    registration.registered_boot = coordinator_boot;
    registration.state = PublisherState::LIVE;
    registration.last_seen_tick = tick;
    registration.sessions_opened += 1;
    stats_.sessions_opened += 1;
  }

  stats_.publishers = publishers_.size();
  return entry->second;
}

Status PublisherRegistry::end_session(const PublisherId& id, PublisherBootId boot, Tick tick) {
  return end_specific_session(id, boot, SessionId{}, tick);
}

Status PublisherRegistry::end_specific_session(const PublisherId& id, PublisherBootId boot,
                                               const SessionId& session, Tick tick) {
  auto entry = publishers_.find(key_of(id));
  if (entry == publishers_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_PUBLISHER,
                           "no session for publisher " + id.value());
  }
  if (entry->second.boot != boot) {
    return Status::failure(ErrorCode::STALE_BOOT_ID,
                           "session being closed is not the current incarnation");
  }
  PublisherRegistration& registration = entry->second;
  if (!session.empty()) {
    // Closing one named session leaves the incarnation live as long as another session remains.
    // This is the mechanism that stops a second connection from de-authorising the first.
    registration.live_sessions.erase(
        std::remove(registration.live_sessions.begin(), registration.live_sessions.end(), session),
        registration.live_sessions.end());
    if (registration.session == session) {
      registration.session =
          registration.live_sessions.empty() ? SessionId{} : registration.live_sessions.back();
    }
  } else {
    registration.live_sessions.clear();
    registration.session = SessionId{};
  }

  if (registration.live_sessions.empty()) {
    // The last session for this incarnation is gone, so the incarnation is no longer live and every
    // record it published stops being current.
    registration.state = PublisherState::DEAD;
    registration.last_seen_tick = tick;
  }
  stats_.sessions_closed += 1;
  return Status::success();
}

std::uint32_t PublisherRegistry::expire_liveness(Tick tick) {
  std::uint32_t changed = 0;
  std::size_t live = 0;
  for (auto& entry : publishers_) {
    PublisherRegistration& registration = entry.second;
    if (registration.state == PublisherState::LIVE) {
      if (tick > registration.last_seen_tick &&
          (tick - registration.last_seen_tick) > idle_ticks_) {
        registration.state = PublisherState::IDLE;
        stats_.liveness_expirations += 1;
        ++changed;
      }
    }
    if (registration.state == PublisherState::LIVE) ++live;
  }
  stats_.live = live;
  return changed;
}

Status PublisherRegistry::touch(const PublisherId& id, PublisherBootId boot, Tick tick) {
  auto entry = publishers_.find(key_of(id));
  if (entry == publishers_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_PUBLISHER,
                           "no session for publisher " + id.value());
  }
  if (entry->second.boot != boot) {
    return Status::failure(ErrorCode::STALE_BOOT_ID,
                           "touch presented boot " + boot.to_string() + " but the session is at " +
                               entry->second.boot.to_string());
  }
  entry->second.last_seen_tick = tick;
  if (entry->second.state == PublisherState::IDLE) {
    // Returning from IDLE to LIVE is not a resurrection of authority: the session
    // in the current epoch is still bound, so the publisher never lost the ability
    // to be current.  It did lose its freshness window, and every record it
    // published while idle is stale by its own deadline rather than by this call.
    entry->second.state = PublisherState::LIVE;
  }
  if (entry->second.state != PublisherState::DEAD) {
    entry->second.state = PublisherState::LIVE;
  }
  auto record_entry = records_.find(key_of(id));
  if (record_entry != records_.end()) {
    record_entry->second.last_seen_wall_millis = wall_clock_unix_millis();
  }
  return Status::success();
}

Status PublisherRegistry::require_revalidation(const PublisherId& id) {
  auto entry = publishers_.find(key_of(id));
  if (entry == publishers_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_PUBLISHER,
                           "no publisher " + id.value() + " registered");
  }
  entry->second.state = PublisherState::IDLE;
  entry->second.session = SessionId{};
  return Status::success();
}

Result<PublisherRegistration> PublisherRegistry::find(const PublisherId& id) const {
  auto entry = publishers_.find(key_of(id));
  if (entry == publishers_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_PUBLISHER,
                           "no publisher " + id.value() + " registered");
  }
  return entry->second;
}

bool PublisherRegistry::is_live(const PublisherId& id, PublisherBootId boot) const {
  auto entry = publishers_.find(key_of(id));
  if (entry == publishers_.end()) return false;
  if (entry->second.state != PublisherState::LIVE || entry->second.boot != boot) return false;
  // An incarnation with no session is not live, whatever the state field says: liveness is contact,
  // and contact is a session.
  return !entry->second.live_sessions.empty();
}

Status PublisherRegistry::observe_evidence_generation(const PublisherId& id, PublisherBootId boot,
                                                      EvidenceGeneration generation) {
  auto entry = publishers_.find(key_of(id));
  if (entry == publishers_.end()) {
    return Status::failure(ErrorCode::UNKNOWN_PUBLISHER,
                           "no session for publisher " + id.value());
  }
  if (entry->second.boot != boot) {
    return Status::failure(ErrorCode::STALE_BOOT_ID,
                           "evidence presented boot " + boot.to_string() +
                               " but the session is at " + entry->second.boot.to_string());
  }
  if (!generation.valid()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "evidence generation must be greater than zero");
  }
  if (generation < entry->second.highest_generation) {
    stats_.replay_rejections += 1;
    return Status::failure(ErrorCode::REPLAY_DETECTED,
                           "evidence generation " + generation.to_string() +
                               " is lower than the observed high-water mark " +
                               entry->second.highest_generation.to_string());
  }
  if (generation == entry->second.highest_generation) {
    stats_.replay_rejections += 1;
    return Status::failure(ErrorCode::REPLAY_DETECTED,
                           "evidence generation " + generation.to_string() +
                               " has already been accepted for this publisher incarnation");
  }
  entry->second.highest_generation = generation;
  auto record_entry = records_.find(key_of(id));
  if (record_entry != records_.end()) {
    record_entry->second.highest_generation = generation;
  }
  return Status::success();
}

std::vector<PublisherRecord> PublisherRegistry::snapshot_records() const {
  std::vector<PublisherRecord> out;
  out.reserve(records_.size());
  for (const auto& entry : records_) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(),
            [](const PublisherRecord& a, const PublisherRecord& b) { return a.id < b.id; });
  return out;
}

std::vector<PublisherRegistration> PublisherRegistry::registrations() const {
  std::vector<PublisherRegistration> out;
  out.reserve(publishers_.size());
  for (const auto& entry : publishers_) {
    out.push_back(entry.second);
  }
  std::sort(out.begin(), out.end(),
            [](const PublisherRegistration& a, const PublisherRegistration& b) {
              if (a.id != b.id) return a.id < b.id;
              return a.boot < b.boot;
            });
  return out;
}

Status PublisherRegistry::restore_records(const std::vector<PublisherRecord>& records, Tick tick) {
  for (const PublisherRecord& record : records) {
    if (records_.size() >= static_cast<std::size_t>(max_publishers_) &&
        records_.find(key_of(record.id)) == records_.end()) {
      return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                             "publisher registry is full while restoring persisted records");
    }
    PublisherRecord stored = record;
    if (stored.first_seen_tick == kTickNone) {
      stored.first_seen_tick = tick;
    }
    records_[key_of(stored.id)] = stored;
    // A restored record deliberately yields no live session.  This is the whole
    // point of the durability/liveness split: persistence is not currentness.
    PublisherRegistration registration;
    registration.id = stored.id;
    registration.boot = stored.highest_boot;
    registration.state = PublisherState::IDLE;
    registration.max_source = stored.max_source;
    registration.registered_tick = tick;
    registration.last_seen_tick = kTickNone;
    registration.highest_generation = stored.highest_generation;
    registration.description = stored.description;
    publishers_[key_of(stored.id)] = registration;
  }
  stats_.publishers = publishers_.size();
  return Status::success();
}

void PublisherRegistry::clear_sessions() {
  for (auto& entry : publishers_) {
    entry.second.state = PublisherState::IDLE;
    entry.second.session = SessionId{};
    entry.second.last_seen_tick = kTickNone;
  }
  stats_.live = 0;
}

void PublisherRegistry::clear() {
  publishers_.clear();
  records_.clear();
  stats_ = PublisherRegistryStats{};
}

}  // namespace aifc
