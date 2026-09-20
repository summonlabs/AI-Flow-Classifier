// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/classify/classifier.hpp"

#include <algorithm>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/foundation/math.hpp"

namespace aifc {
namespace {

// The default time source.  Function-local static storage, so that a Classifier constructed
// without an explicit clock has a stable, process-lifetime monotonic source rather than a
// dangling reference.
[[nodiscard]] const TickSource& default_clock() {
  static const SteadyTickSource source;
  return source;
}

// The evidence band a session may assert.  A peer's claim is clamped down to the
// ceiling the session was admitted at; it is never raised.
[[nodiscard]] EvidenceSource clamp_source(EvidenceSource claimed, EvidenceSource ceiling) noexcept {
  return source_rank(claimed) <= source_rank(ceiling) ? claimed : ceiling;
}

[[nodiscard]] Status stale_epoch_status(const SessionEnvelope& envelope,
                                       CoordinatorEpoch current) {
  return Status::failure(ErrorCode::STALE_EPOCH,
                         "session is bound to coordinator epoch " + envelope.epoch.to_string() +
                             " but the coordinator is at epoch " + current.to_string() +
                             "; authority must be re-established");
}

}  // namespace

SessionEnvelope make_session_envelope(const PublisherRegistration& registration, Tick tick) {
  SessionEnvelope envelope;
  envelope.publisher = registration.id;
  envelope.publisher_boot = registration.boot;
  envelope.session = registration.session;
  envelope.epoch = registration.registered_epoch;
  envelope.coordinator_boot = registration.registered_boot;
  envelope.max_source = registration.max_source;
  envelope.received_tick = tick;
  return envelope;
}

Classifier::Classifier(ClassifierOptions options)
    : policy_(std::move(options.policy)),
      logger_(std::move(options.logger)),
      flows_(policy_.limits.effective().max_flows),
      publishers_(policy_.limits.effective().max_publishers,
                  policy_.limits.effective().max_session_idle_ticks),
      workloads_(policy_.limits.effective().max_workloads, policy_.limits.effective().max_contracts,
                 policy_.limits.effective().max_pending_contracts),
      evidence_(policy_.limits.effective().max_evidence_records,
                policy_.limits.effective().max_evidence_per_flow,
                policy_.limits.effective().max_flow_key_index),
      decisions_(policy_.limits.effective().max_decisions_per_flow,
                 policy_.limits.effective().max_flow_key_index,
                 policy_.limits.effective().max_contradictions_per_flow,
                 policy_.limits.effective().max_supersessions,
                 policy_.limits.effective().max_revocations),
      epoch_(options.epoch),
      coordinator_boot_(options.coordinator_boot),
      clock_(options.clock != nullptr ? options.clock : &default_clock()) {
  policy_.limits = policy_.limits.effective();
  policy_ = ClassifierPolicy::canonicalize(policy_).value();
  policy_digest_ = compute_policy_digest(policy_);
  logger_.set_component("classifier");
}

// --- lifecycle -------------------------------------------------------------

Result<CoordinatorEpoch> Classifier::advance_epoch(CoordinatorBootId boot) {
  std::lock_guard<std::mutex> guard(mutex_);
  std::uint64_t next = 0;
  Status status = sequence_.next(next);
  if (!status) return status;

  std::uint64_t epoch_value = 0;
  Counter epoch_counter(epoch_.value);
  status = epoch_counter.next(epoch_value);
  if (!status) return status;
  epoch_ = CoordinatorEpoch{epoch_value};
  coordinator_boot_ = boot;

  // Authority does not survive an incarnation change.  Every session is dropped, every
  // liveness claim is dropped, and every record accepted under the previous epoch is
  // marked stale with an explicit reason.  Note what this does *not* do: it does not
  // delete evidence.  The records stay visible in explanations, marked stale, which is
  // what lets an operator see what used to be believed.
  publishers_.clear_sessions();
  const std::uint32_t staled = evidence_.mark_epoch_stale(epoch_, now());
  ++authority_sequence_;
  logger_.info("coordinator epoch advanced to " + epoch_.to_string() + "; " +
                   std::to_string(staled) + " evidence records marked stale",
               {}, "STALE_EPOCH");
  return epoch_;
}

CoordinatorEpoch Classifier::epoch() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return epoch_;
}

CoordinatorBootId Classifier::coordinator_boot() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return coordinator_boot_;
}

// --- policy ----------------------------------------------------------------

ClassifierPolicy Classifier::policy() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return policy_;
}

std::vector<PublisherRegistration> Classifier::publisher_registrations() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return publishers_.registrations();
}

Result<Classification> Classifier::recorded_decision(const FlowId& flow,
                                                     FlowGeneration generation) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return decisions_.latest(flow, generation);
}

Classifier::DurableState Classifier::durable_state() const {
  // One acquisition, one consistent image.  Every vector below is copied while the lock is held, so
  // a concurrent admission, classification or session change cannot produce a torn image and cannot
  // invalidate an iterator underneath the copy.
  std::lock_guard<std::mutex> guard(mutex_);
  DurableState state;
  state.policy = policy_;
  state.epoch = epoch_;
  state.coordinator_boot = coordinator_boot_;
  state.sequence_high_water = sequence_.value();
  state.publishers = publishers_.snapshot_records();
  state.workloads = workloads_.snapshot_workloads();
  state.contracts = workloads_.snapshot_contracts();
  state.flows = flows_.snapshot_flows();
  state.evidence = evidence_.snapshot_records();
  state.classifications = decisions_.snapshot_classifications();
  state.revocations = decisions_.revocations();
  state.supersessions = decisions_.supersessions();
  return state;
}

Digest256 Classifier::policy_digest() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return policy_digest_;
}

Result<ClassifierPolicyGeneration> Classifier::set_policy(ClassifierPolicy policy) {
  Result<ClassifierPolicy> canonical = ClassifierPolicy::canonicalize(std::move(policy));
  if (!canonical) return canonical.status();
  std::lock_guard<std::mutex> guard(mutex_);
  ClassifierPolicy next = std::move(canonical).value();
  const Digest256 next_digest = compute_policy_digest(next);
  if (next_digest == policy_digest_ && policy_.generation.valid()) {
    // The content is identical, so this is not a policy change.  Advancing the generation
    // here would renumber the policy without changing it, which would invalidate decisions
    // that are still correct -- the opposite of what a generation is for.
    return policy_.generation;
  }
  std::uint64_t generation = 0;
  {
    Counter counter(policy_.generation.value);
    Status status = counter.next(generation);
    if (!status) return status;
  }
  next.generation = ClassifierPolicyGeneration{generation};
  policy_ = std::move(next);
  policy_digest_ = compute_policy_digest(policy_);
  counters_.policy_updates += 1;
  // The decision memo is keyed by policy generation, so it does not need clearing to
  // be correct.  It is cleared anyway because the old entries can no longer be hit and
  // holding them would be dead weight against a bounded budget.
  decisions_.clear();
  logger_.info("classifier policy generation advanced to " + policy_.generation.to_string());
  return policy_.generation;
}

// --- publishers ------------------------------------------------------------

Result<PublisherRegistration> Classifier::register_publisher(const PublisherId& id,
                                                             PublisherBootId boot,
                                                             EvidenceSource max_source,
                                                             const SessionId& session,
                                                             std::string description) {
  std::lock_guard<std::mutex> guard(mutex_);
  Result<PublisherRegistration> registration = publishers_.bind_session(id, boot, epoch_, coordinator_boot_, max_source, session,
                                 now(), std::move(description));
  if (!registration) return registration.status();
  // A new live incarnation is a change to a volatile authority fact.
  ++authority_sequence_;
  return registration;
}

Status Classifier::end_publisher_session(const PublisherId& id, PublisherBootId boot,
                                         const SessionId& session) {
  std::lock_guard<std::mutex> guard(mutex_);
  const Status status = publishers_.end_specific_session(id, boot, session, now());
  if (!status) return status;

  // Whether the evidence stops being current depends on whether the *incarnation* is still live,
  // not on whether this particular connection closed.  A publisher that holds two sessions and
  // closes one is still live, and its records must stay current; if it closed the last one, every
  // record it published stops being current immediately.
  const Result<PublisherRegistration> registration = publishers_.find(id);
  const bool incarnation_live = registration && !registration.value().live_sessions.empty();
  std::uint32_t changed = 0;
  if (!incarnation_live) {
    const std::string prefix = id.value() + "@" + boot.to_string();
    changed = evidence_.mark_stale_by_predicate(
        [&](const EvidenceRecord& record) {
          return AuthorityContext::boot_key(record.publisher, record.publisher_boot) == prefix;
        },
        "publisher " + id.value() + " boot " + boot.to_string() +
            " has no remaining session; evidence published by that incarnation is no longer current",
        now());
  } else if (!session.empty()) {
    // Only the records published through the session that ended lose their authority.  Records
    // published through a still-open session of the same incarnation are untouched.
    //
    // A record with no recorded session is treated as belonging to this session rather than to nobody:
    // an empty session identity would otherwise match every sessionless record and stale an
    // incarnation's whole history when one of its connections went away.
    changed = evidence_.mark_stale_by_predicate(
        [&](const EvidenceRecord& record) {
          if (record.publisher != id || record.publisher_boot != boot) return false;
          return record.session.empty() || record.session == session;
        },
        "session " + session.value() + " of publisher " + id.value() + " boot " + boot.to_string() +
            " ended; evidence published through that session is no longer current",
        now());
  }
  ++authority_sequence_;
  logger_.info("publisher " + id.value() + " boot " + boot.to_string() +
                   " session ended; incarnation live=" + (incarnation_live ? "yes" : "no") + "; " +
                   std::to_string(changed) + " evidence records marked stale",
               id.value(), "PUBLISHER_DEAD");
  return Status::success();
}

Status Classifier::heartbeat(const PublisherId& id, PublisherBootId boot) {
  std::lock_guard<std::mutex> guard(mutex_);
  const Status status = publishers_.touch(id, boot, now());
  if (status) ++authority_sequence_;
  return status;
}

std::uint32_t Classifier::expire_publisher_liveness() {
  std::lock_guard<std::mutex> guard(mutex_);
  const Tick tick = now();
  const std::uint32_t changed = publishers_.expire_liveness(tick);
  if (changed != 0) {
    ++authority_sequence_;
    // Liveness expiry also stales the evidence, because a record whose publisher is
    // idle is not current.  The engine applies the same rule at decision time; doing
    // it here as well keeps the store from holding authority it no longer has.
    const std::uint32_t staled = evidence_.mark_stale_by_predicate(
        [&](const EvidenceRecord& record) {
          return !publishers_.is_live(record.publisher, record.publisher_boot);
        },
        "publisher incarnation is no longer live in the current coordinator epoch", tick);
    logger_.info("publisher liveness sweep expired " + std::to_string(changed) +
                     " publishers and marked " + std::to_string(staled) + " evidence records stale");
  }
  return changed;
}

Result<PublisherRegistration> Classifier::find_publisher(const PublisherId& id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return publishers_.find(id);
}

// --- workloads and contracts ------------------------------------------------

Result<WorkloadRecord> Classifier::declare_workload(const WorkloadId& id, const PublisherId& owner,
                                                    WorkloadGeneration generation,
                                                    std::string description) {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<WorkloadContract> retired;
  Result<WorkloadRecord> record = workloads_.declare_workload(
      id, owner, generation, now(), std::move(description), &retired);
  if (!record) return record.status();
  for (const WorkloadContract& contract : retired) {
    // A contract bound to a superseded workload generation is no longer a current
    // statement, so anything derived from it must stop being current.
    const std::uint32_t changed = evidence_.mark_stale_by_predicate(
        [&](const EvidenceRecord& candidate) { return candidate.contract == contract.id; },
        "workload " + id.value() + " advanced past the generation contract " +
            contract.id.value() + " was bound to",
        now());
    (void)changed;
    logger_.info("contract " + contract.id.value() + " retired by workload generation advance",
                 id.value(), "STALE_GENERATION");
  }
  return record;
}

Result<WorkloadContract> Classifier::propose_contract(WorkloadContract contract) {
  std::lock_guard<std::mutex> guard(mutex_);
  return workloads_.propose_contract(std::move(contract), now());
}

Result<WorkloadContract> Classifier::activate_contract(const ContractId& id,
                                                       const PublisherId& caller) {
  std::lock_guard<std::mutex> guard(mutex_);
  WorkloadContract retired;
  Result<WorkloadContract> activated =
      workloads_.activate_contract(id, caller, now(), &retired);
  if (!activated) return activated.status();
  if (!retired.id.empty()) {
    const std::uint32_t changed = evidence_.mark_stale_by_predicate(
        [&](const EvidenceRecord& candidate) { return candidate.contract == retired.id; },
        "contract " + retired.id.value() + " was replaced by " + id.value(),
        now());
    (void)changed;
    logger_.info("contract " + retired.id.value() + " retired in favour of " + id.value(),
                 id.value(), "SUPERSEDED");
  }
  return activated;
}

Status Classifier::retire_contract(const ContractId& id, const PublisherId& caller) {
  std::lock_guard<std::mutex> guard(mutex_);
  Status status = workloads_.retire_contract(id, caller, now());
  if (!status) return status;
  evidence_.mark_stale_by_predicate(
      [&](const EvidenceRecord& candidate) { return candidate.contract == id; },
      "contract " + id.value() + " was retired", now());
  return Status::success();
}

Status Classifier::retire_workload(const WorkloadId& id, WorkloadGeneration generation) {
  std::lock_guard<std::mutex> guard(mutex_);
  Status status = workloads_.retire_workload(id, generation, now());
  if (!status) return status;
  evidence_.mark_stale_by_predicate(
      [&](const EvidenceRecord& candidate) { return candidate.workload == id; },
      "workload " + id.value() + " was retired", now());
  return Status::success();
}

Result<WorkloadRecord> Classifier::find_workload(const WorkloadId& id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return workloads_.find_workload(id);
}

Result<WorkloadContract> Classifier::find_contract(const ContractId& id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return workloads_.find_contract(id);
}

// --- flows -----------------------------------------------------------------

Status Classifier::refresh_flow(const FlowKey& key, FlowGeneration requested,
                                const SessionId& session, Tick tick,
                                FlowRegistration& registration) {
  Result<FlowRegistration> result = flows_.register_flow(key, requested, session, tick);
  if (!result) return result.status();
  registration = result.value();
  counters_.flows_registered += 1;
  if (registration.created) {
    evidence_.mark_stale_by_predicate(
        [&](const EvidenceRecord& candidate) { return candidate.flow_id == registration.record.id; },
        "flow incarnation replaced", tick);
  }
  if (registration.fenced_previous) {
    counters_.generation_fences += 1;
    mark_flow_generation_stale(registration.record.id, registration.record.generation, tick);
  }
  return Status::success();
}

void Classifier::mark_flow_generation_stale(const FlowId& flow, FlowGeneration superseded_by,
                                            Tick tick) {
  // Two things must happen when a flow generation advances, and doing only one of them
  // would leave a lie in the store:
  //
  //   1. evidence bound to a lower generation stops being current, so the engine
  //      cannot select it;
  //   2. recorded classifications for a lower generation are marked stale, so history
  //      does not report a superseded decision as the current answer.
  evidence_.mark_stale_by_predicate(
      [&](const EvidenceRecord& candidate) {
        return candidate.flow_id == flow && candidate.flow_generation < superseded_by;
      },
      "flow advanced to generation " + superseded_by.to_string() +
          "; evidence bound to an earlier incarnation is no longer current",
      tick);
  const std::uint32_t affected = decisions_.supersede_generation(flow, superseded_by, tick);
  if (affected != 0) {
    counters_.supersessions += affected;
  }
}

Result<FlowRegistration> Classifier::register_flow(const FlowKey& key, FlowGeneration generation,
                                                   const SessionId& session) {
  std::lock_guard<std::mutex> guard(mutex_);
  FlowRegistration registration;
  Status status = refresh_flow(key, generation, session, now(), registration);
  if (!status) return status;
  return registration;
}

Result<FlowRecord> Classifier::find_flow(const FlowKey& key) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return flows_.find_by_key(key);
}

Result<FlowRecord> Classifier::find_flow_generation(const FlowId& id,
                                                    FlowGeneration generation) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return flows_.find_generation(id, generation);
}

// --- evidence --------------------------------------------------------------

Result<EvidenceRecord> Classifier::admit_evidence(const SessionEnvelope& envelope,
                                                  const EvidencePayload& payload,
                                                  EvidenceSubmissionOutcome& outcome, Tick tick) {
  if (envelope.epoch != epoch_) {
    return stale_epoch_status(envelope, epoch_);
  }
  if (envelope.coordinator_boot != coordinator_boot_) {
    return Status::failure(ErrorCode::STALE_BOOT_ID,
                           "session is bound to coordinator boot " +
                               envelope.coordinator_boot.to_string() + " but the coordinator is at " +
                               coordinator_boot_.to_string());
  }
  if (!envelope.publisher_boot.valid()) {
    return Status::failure(ErrorCode::UNAUTHENTICATED,
                           "session envelope carries no publisher boot incarnation");
  }

  Result<PublisherRegistration> registration = publishers_.find(envelope.publisher);
  if (!registration) {
    return Status::failure(ErrorCode::UNKNOWN_PUBLISHER,
                           "publisher " + envelope.publisher.value() + " has no registered session");
  }
  if (registration.value().boot != envelope.publisher_boot) {
    // The envelope claims a boot incarnation that is not the one the session is bound
    // to.  This is the identity-binding rule: the session decides who the sender is.
    return Status::failure(ErrorCode::STALE_BOOT_ID,
                           "session envelope claims publisher boot " +
                               envelope.publisher_boot.to_string() + " but the live session is at " +
                               registration.value().boot.to_string());
  }
  if (registration.value().session != envelope.session) {
    return Status::failure(ErrorCode::UNAUTHENTICATED,
                           "session envelope does not match the authenticated session for " +
                               envelope.publisher.value());
  }
  if (!publishers_.is_live(envelope.publisher, envelope.publisher_boot)) {
    return Status::failure(ErrorCode::PUBLISHER_DEAD,
                           "publisher " + envelope.publisher.value() + " boot " +
                               envelope.publisher_boot.to_string() + " is " +
                               std::string(to_string(registration.value().state)));
  }

  // The effective source is the weaker of the peer's claim and the session ceiling.
  const EvidenceSource ceiling = [&]() {
    const std::uint8_t envelope_rank = source_rank(envelope.max_source);
    const std::uint8_t registered_rank = source_rank(registration.value().max_source);
    return envelope_rank < registered_rank ? envelope.max_source : registration.value().max_source;
  }();
  const EvidenceSource effective = clamp_source(payload.claimed_source, ceiling);
  if (source_rank(payload.claimed_source) > source_rank(ceiling)) {
    outcome.notes.push_back("claimed source " + std::string(to_string(payload.claimed_source)) +
                            " was reduced to " + std::string(to_string(effective)) +
                            " by the session authority ceiling");
  }
  if (source_is_heuristic(effective)) {
    // Gate one: the policy must permit heuristics at all.
    if (!policy_.allow_heuristic_evidence) {
      return Status::failure(ErrorCode::HEURISTIC_DISABLED,
                             "this policy does not permit heuristic evidence");
    }
    // Gate two: the submission must cite a declared hint that is attached to an enabled adapter.
    // Enforcing this is what makes "an adapter must be enabled by name" true rather than documented:
    // without it a peer could submit a heuristic under any label while every adapter was disabled.
    bool any_adapter_enabled = false;
    for (const HeuristicAdapterPolicy& adapter : policy_.heuristic_adapters) {
      if (adapter.enabled) any_adapter_enabled = true;
    }
    if (!any_adapter_enabled) {
      return Status::failure(ErrorCode::HEURISTIC_DISABLED,
                             "the policy permits heuristics but no adapter is enabled, so no "
                             "heuristic observation may be submitted");
    }
    const ClassifierPolicy::HeuristicClaim claim =
        ClassifierPolicy::claim_of(payload.metadata.binding);
    if (policy_.find_port_hint(claim.transport, claim.port) == nullptr) {
      return Status::failure(
          ErrorCode::HEURISTIC_DISABLED,
          "heuristic evidence must cite a declared, enabled hint; the submission named transport " +
              std::string(to_string(claim.transport)) + " port " + std::to_string(claim.port) +
              ", which no enabled adapter declares");
    }
  }
  if (!source_is_heuristic(effective) && source_rank(effective) == 0) {
    return Status::failure(ErrorCode::UNAUTHORIZED,
                           "evidence source could not be established for this session");
  }

  // A declared class of UNKNOWN is not a declaration.  Accepting it would let a peer
  // push a flow towards UNKNOWN, which is a legitimate answer but must never be an
  // assertion.
  if (is_unknown(payload.semantic)) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "UNKNOWN may not be declared as evidence; omit the record instead");
  }

  // Workload binding.  A record that names a workload must name one the publisher owns
  // and whose generation matches, or the claim is refused rather than recorded.
  if (!payload.workload.empty()) {
    Result<WorkloadRecord> workload = workloads_.find_workload(payload.workload);
    if (!workload) {
      return Status::failure(ErrorCode::UNKNOWN_WORKLOAD,
                             "evidence names undeclared workload " + payload.workload.value());
    }
    if (workload.value().owner != envelope.publisher) {
      return Status::failure(ErrorCode::UNAUTHORIZED,
                             "publisher " + envelope.publisher.value() + " does not own workload " +
                                 payload.workload.value());
    }
    if (workload.value().generation != payload.workload_generation) {
      return Status::failure(ErrorCode::STALE_GENERATION,
                             "evidence names workload generation " +
                                 payload.workload_generation.to_string() +
                                 " but the workload is at " +
                                 workload.value().generation.to_string());
    }
    if (workload.value().state == WorkloadState::RETIRED) {
      return Status::failure(ErrorCode::CONTRACT_RETIRED,
                             "workload " + payload.workload.value() + " is retired");
    }
  }

  if (!payload.contract.empty()) {
    Result<WorkloadContract> contract = workloads_.find_contract(payload.contract);
    if (!contract) {
      return Status::failure(ErrorCode::UNKNOWN_CONTRACT,
                             "evidence names unknown contract " + payload.contract.value());
    }
    if (contract.value().owner != envelope.publisher) {
      return Status::failure(ErrorCode::UNAUTHORIZED,
                             "publisher " + envelope.publisher.value() + " does not own contract " +
                                 payload.contract.value());
    }
    if (contract.value().state != ContractState::ACTIVE) {
      return Status::failure(ErrorCode::CONTRACT_RETIRED,
                             "evidence cites contract " + payload.contract.value() +
                                 " which is " +
                                 std::string(to_string(contract.value().state)));
    }
    if (contract.value().workload != payload.workload ||
        contract.value().workload_generation != payload.workload_generation) {
      return Status::failure(ErrorCode::CONTRACT_MISMATCH,
                             "cited contract " + payload.contract.value() +
                                 " is not bound to the workload generation the evidence names");
    }
  }

  // Flow binding.  The envelope's publisher may register a flow, but a flow
  // incarnation is a shared object: registering a *different* generation of a key that
  // another publisher already registered fences that publisher's evidence.  That is
  // intended — a new incarnation is a new incarnation — and it is reported.
  FlowRegistration flow;
  Status status = refresh_flow(payload.flow_key, payload.flow_generation, envelope.session, tick,
                               flow);
  if (!status) return status;
  if (flow.fenced_previous) {
    outcome.fenced_flow_generation = true;
    outcome.previous_flow_generation = flow.previous_generation;
  }

  // Replay and generation fencing.  The publisher's observed high-water mark is the
  // mechanism: a generation at or below it has already been used, so accepting it again
  // would make a previous acknowledgement meaningless.
  status = publishers_.observe_evidence_generation(envelope.publisher, envelope.publisher_boot,
                                                   payload.evidence_generation);
  if (!status) return status;

  const std::uint64_t window = payload.freshness_window != 0
                                   ? payload.freshness_window
                                   : policy_.default_freshness_window;

  EvidenceRecord record;
  // The identity is minted here from the authenticated envelope plus the generation.
  // A peer cannot choose its own evidence identity, which removes a whole class of
  // collision and replay games.
  {
    const std::string material = envelope.publisher.value() + "|" +
                                 envelope.publisher_boot.to_string() + "|" +
                                 payload.metadata.topic + "|" +
                                 payload.evidence_generation.to_string() + "|" +
                                 flow.record.id.to_hex() + "|" + flow.record.generation.to_string();
    const auto digest = sha256(material);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string id_text = "ev-";
    id_text.reserve(3 + 32);
    for (std::size_t i = 0; i < 16; ++i) {
      id_text.push_back(kHex[(digest[i] >> 4) & 0x0FU]);
      id_text.push_back(kHex[digest[i] & 0x0FU]);
    }
    record.id = make_evidence_id(id_text);
  }
  record.publisher = envelope.publisher;
  record.publisher_boot = envelope.publisher_boot;
  record.session = envelope.session;
  record.accepted_epoch = epoch_;
  record.accepted_boot = coordinator_boot_;
  record.workload = payload.workload;
  record.workload_generation = payload.workload_generation;
  record.contract = payload.contract;
  record.flow_id = flow.record.id;
  record.flow_generation = flow.record.generation;
  record.generation = payload.evidence_generation;
  std::uint64_t seq = 0;
  {
    Status next = sequence_.next(seq);
    if (!next) return next;
  }
  record.accepted_seq = seq;
  record.accepted_tick = tick;
  record.fresh_until = tick + window;
  record.semantic = payload.semantic;
  record.source = effective;
  record.state = EvidenceState::EVIDENCE_CURRENT;
  record.confidence = source_confidence(effective);
  record.metadata = payload.metadata;
  record.metadata.contract = payload.contract;
  record.content_digest = compute_evidence_digest(record);

  // Supersession: a strictly newer generation of the same topic from the same
  // publisher incarnation displaces the older record.  The older record is not
  // deleted; it is marked SUPERSEDED and cited that way.
  // The Result is bound to a named local on purpose.  In C++20 the temporary returned by
  // evidence_for_flow() is destroyed at the end of the range initialiser; only C++23 extends
  // its lifetime to the end of the loop.  Iterating evidence_for_flow(...).value() directly
  // therefore reads a vector that has already been freed, and once the allocator reuses that
  // storage the loop performs zero iterations -- which is how a supersession could be skipped
  // entirely, silently, with the replaced record still claiming to be current.
  const Result<std::vector<EvidenceId>> existing_ids = evidence_.evidence_for_flow(record.flow_id);
  for (const EvidenceId& candidate_id : existing_ids.value()) {
    Result<EvidenceRecord> candidate = evidence_.find(candidate_id);
    if (!candidate) continue;
    const EvidenceRecord& other = candidate.value();
    if (other.publisher != record.publisher) continue;
    if (other.publisher_boot != record.publisher_boot) continue;
    if (other.metadata.topic != record.metadata.topic) continue;
    if (other.generation >= record.generation) continue;
    Status mark = evidence_.set_state(
        other.id, EvidenceState::EVIDENCE_SUPERSEDED,
        "superseded by " + record.id.value() + " at generation " + record.generation.to_string(),
        tick);
    if (!mark) {
      // A supersession that cannot be recorded must not be silent: without it, an operator would
      // see a replacement record appear while the record it replaced still claims to be current.
      logger_.warn("could not mark evidence " + other.id.value() + " as superseded: " +
                       render_status(mark),
                   record.publisher.value(), std::string(to_string(mark.code)));
      continue;
    }
    SupersessionRecord supersession;
    supersession.previous_id = other.id;
    supersession.replacement_id = record.id;
    supersession.previous_generation = other.generation;
    supersession.replacement_generation = record.generation;
    supersession.publisher = record.publisher;
    supersession.seq = seq;
    supersession.recorded_tick = tick;
    decisions_.record_supersession(supersession);
    counters_.supersessions += 1;
    outcome.superseded_previous = true;
    outcome.superseded_id = other.id;
  }

  return record;
}

Result<EvidenceSubmissionOutcome> Classifier::submit_evidence(const SessionEnvelope& envelope,
                                                              const EvidencePayload& payload) {
  std::lock_guard<std::mutex> guard(mutex_);
  EvidenceSubmissionOutcome outcome;
  Result<EvidenceRecord> record = admit_evidence(envelope, payload, outcome, now());
  if (!record) {
    counters_.evidence_refused += 1;
    logger_.warn("evidence refused: " + render_status(record.status()), envelope.publisher.value(),
                 std::string(to_string(record.code())));
    return record.status();
  }
  outcome.record = record.value();
  outcome.effective_source = record.value().source;
  Status status = evidence_.insert(record.value());
  if (!status) {
    counters_.evidence_refused += 1;
    return status;
  }
  outcome.accepted = true;
  counters_.evidence_accepted += 1;
  // A successful publication is proof of life for the session, so liveness is
  // refreshed.  Liveness is never inferred from silence; only from contact.
  (void)publishers_.touch(envelope.publisher, envelope.publisher_boot, now());
  return outcome;
}

Status Classifier::withdraw_evidence(const SessionEnvelope& envelope, const EvidenceId& id,
                                     std::string reason) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (envelope.epoch != epoch_) {
    return stale_epoch_status(envelope, epoch_);
  }
  Result<EvidenceRecord> record = evidence_.find(id);
  if (!record) {
    return Status::failure(ErrorCode::NOT_FOUND, "no evidence record " + id.value());
  }
  if (record.value().publisher != envelope.publisher ||
      record.value().publisher_boot != envelope.publisher_boot) {
    // A publisher may withdraw its own evidence and nothing else.
    return Status::failure(ErrorCode::UNAUTHORIZED,
                           "publisher " + envelope.publisher.value() +
                               " may not withdraw evidence published by " +
                               record.value().publisher.value());
  }
  // The reason that is actually applied is captured first: the record read above is a copy
  // taken before the state change, so its state_reason is still the old one.
  const std::string applied_reason =
      reason.empty() ? std::string("withdrawn by its publisher") : std::move(reason);
  Status status = evidence_.set_state(id, EvidenceState::EVIDENCE_SUPERSEDED, applied_reason, now());
  if (!status) return status;
  RevocationRecord revocation;
  revocation.flow_id = record.value().flow_id;
  revocation.flow_generation = record.value().flow_generation;
  revocation.evidence_id = id;
  revocation.revoked_by_session = envelope.session;
  revocation.revoked_by_publisher = envelope.publisher;
  revocation.epoch = epoch_;
  std::uint64_t seq = 0;
  {
    Status next = sequence_.next(seq);
    if (!next) return next;
  }
  revocation.seq = seq;
  revocation.revoked_tick = now();
  revocation.reason = applied_reason;
  decisions_.record_revocation(revocation);
  counters_.revocations += 1;
  return Status::success();
}

Result<EvidenceRecord> Classifier::find_evidence(const EvidenceId& id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return evidence_.find(id);
}

Result<std::vector<EvidenceId>> Classifier::evidence_for_flow(const FlowId& id) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return evidence_.evidence_for_flow(id);
}

// --- classification --------------------------------------------------------

AuthorityContext Classifier::build_authority_context(Tick tick) const {
  // Liveness is read from the registry's live registrations, never inferred from a
  // record's own state.  A record can claim CURRENT all it likes; if its publisher
  // incarnation is not in this set, the engine will not select it.
  AuthorityContext context;
  context.epoch = epoch_;
  context.coordinator_boot = coordinator_boot_;
  context.tick = tick;
  for (const PublisherRegistration& registration : publishers_.registrations()) {
    context.known_publishers.insert(registration.id.value());
    if (registration.state == PublisherState::LIVE) {
      context.live_publisher_boots.insert(
          AuthorityContext::boot_key(registration.id, registration.boot));
    }
  }
  return context;
}

Result<ClassificationResult> Classifier::classify(const ClassificationQuery& query) {
  std::lock_guard<std::mutex> guard(mutex_);
  counters_.classifications += 1;

  Result<FlowRecord> flow = flows_.find_by_key(query.flow_key);
  if (!flow) {
    return Status::failure(ErrorCode::UNKNOWN_FLOW,
                           "flow is not registered: " + query.flow_key.to_string());
  }

  FlowGeneration generation = query.flow_generation;
  bool historical = false;
  if (generation.value == 0) {
    if (!query.accept_current_generation) {
      return Status::failure(ErrorCode::INVALID_ARGUMENT,
                             "a classification request must name a flow generation");
    }
    generation = flow.value().generation;
  } else if (generation != flow.value().generation) {
    // The caller asked about an incarnation that is not current.  The answer is still
    // produced from that incarnation's evidence, but it is marked historical so that a
    // caller cannot mistake it for a statement about the present.
    Result<FlowRecord> exact = flows_.find_generation(flow.value().id, generation);
    if (!exact) {
      return Status::failure(ErrorCode::UNKNOWN_FLOW,
                             "flow has no generation " + generation.to_string());
    }
    historical = true;
  }

  DecisionInput input;
  input.flow = flow.value();
  input.flow.generation = generation;
  input.policy = policy_;

  input.authority = build_authority_context(now());
  input.authority.authority_sequence = authority_sequence_;
  input.active_contracts = workloads_.active_contracts();
  input.workloads = workloads_.snapshot_workloads();
  input.generation_revoked = decisions_.is_revoked(input.flow.id, generation);

  Result<std::vector<EvidenceId>> ids = evidence_.evidence_for_flow(input.flow.id);
  if (ids) {
    input.evidence.reserve(ids.value().size());
    for (const EvidenceId& id : ids.value()) {
      Result<EvidenceRecord> record = evidence_.find(id);
      if (record) input.evidence.push_back(record.value());
    }
  }

  const Digest256 evidence_digest = compute_evidence_set_digest(input);
  DecisionKey key;
  key.flow_id = input.flow.id;
  key.flow_generation = generation;
  key.evidence_digest = evidence_digest;
  key.policy_generation = policy_.generation;

  ClassificationResult result;
  Classification memoized;
  if (decisions_.memo_lookup(key, memoized)) {
    result.classification = memoized;
    result.memo_hit = true;
  } else {
    result.classification = engine_.decide(input);
    decisions_.memo_store(key, result.classification);
    // ClassificationIndex::record already files the decision's contradictions into the per-flow
    // ring.  Recording them a second time here would double-count them, halving the effective
    // history bound and making a flapping flow evict its evidence of flapping at twice the
    // configured rate.  The batch path never had the duplicate, so the two disagreed.
    decisions_.record(result.classification);
    counters_.contradictions += result.classification.contradictions.size();
  }
  result.historical = historical;
  if (query.explain) {
    result.explanation = DecisionEngine::render_explanation(result.classification, input);
  }
  return result;
}

Result<Classifier::BatchOutcome> Classifier::classify_batch(
    const std::vector<ClassificationQuery>& queries) {
  std::lock_guard<std::mutex> guard(mutex_);
  const ResourceLimits limits = policy_.limits.effective();
  if (queries.size() > static_cast<std::size_t>(limits.max_batch_keys)) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "batch of " + std::to_string(queries.size()) +
                               " keys exceeds the configured bound of " +
                               std::to_string(limits.max_batch_keys));
  }
  counters_.batch_requests += 1;
  counters_.batch_keys += queries.size();
  BatchOutcome outcome;
  outcome.results.reserve(queries.size());
  outcome.statuses.reserve(queries.size());
  for (const ClassificationQuery& query : queries) {
    // The batch path re-enters classify() directly rather than through the public
    // API, because the lock is already held.  This is the only place that happens and
    // it is deliberate: taking the same mutex twice would deadlock, and releasing it
    // between keys would make the batch non-atomic with respect to concurrent
    // mutation.
    Result<ClassificationResult> single = [&]() -> Result<ClassificationResult> {
      Result<FlowRecord> flow = flows_.find_by_key(query.flow_key);
      if (!flow) {
        return Status::failure(ErrorCode::UNKNOWN_FLOW,
                               "flow is not registered: " + query.flow_key.to_string());
      }
      FlowGeneration generation = query.flow_generation.value == 0 ? flow.value().generation
                                                                  : query.flow_generation;
      bool historical = generation != flow.value().generation;
      if (historical) {
        Result<FlowRecord> exact = flows_.find_generation(flow.value().id, generation);
        if (!exact) {
          return Status::failure(ErrorCode::UNKNOWN_FLOW,
                                 "flow has no generation " + generation.to_string());
        }
      }

      DecisionInput input;
      input.flow = flow.value();
      input.flow.generation = generation;
      input.policy = policy_;
      input.authority = build_authority_context(now());
    input.authority.authority_sequence = authority_sequence_;
      input.authority.authority_sequence = authority_sequence_;
  input.authority.authority_sequence = authority_sequence_;
      input.active_contracts = workloads_.active_contracts();
      input.workloads = workloads_.snapshot_workloads();
      input.generation_revoked = decisions_.is_revoked(input.flow.id, generation);
      Result<std::vector<EvidenceId>> ids = evidence_.evidence_for_flow(input.flow.id);
      if (ids) {
        input.evidence.reserve(ids.value().size());
        for (const EvidenceId& id : ids.value()) {
          Result<EvidenceRecord> record = evidence_.find(id);
          if (record) input.evidence.push_back(record.value());
        }
      }
      const Digest256 evidence_digest = compute_evidence_set_digest(input);
      DecisionKey memo_key;
      memo_key.flow_id = input.flow.id;
      memo_key.flow_generation = generation;
      memo_key.evidence_digest = evidence_digest;
      memo_key.policy_generation = policy_.generation;

      ClassificationResult entry;
      Classification memoized;
      if (decisions_.memo_lookup(memo_key, memoized)) {
        entry.classification = memoized;
        entry.memo_hit = true;
      } else {
        entry.classification = engine_.decide(input);
        decisions_.memo_store(memo_key, entry.classification);
        decisions_.record(entry.classification);
        counters_.contradictions += entry.classification.contradictions.size();
      }
      entry.historical = historical;
      if (query.explain) {
        entry.explanation = DecisionEngine::render_explanation(entry.classification, input);
      }
      counters_.classifications += 1;
      return entry;
    }();

    if (single) {
      outcome.succeeded += 1;
      outcome.results.push_back(single.value());
      outcome.statuses.push_back(Status::success());
    } else {
      outcome.failed += 1;
      outcome.results.push_back(ClassificationResult{});
      outcome.statuses.push_back(single.status());
    }
  }
  return outcome;
}

// --- revocation ------------------------------------------------------------

Status Classifier::revoke_generation(const SessionEnvelope& envelope, const FlowId& flow,
                                     FlowGeneration generation, std::string reason) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (envelope.epoch != epoch_) {
    return stale_epoch_status(envelope, epoch_);
  }
  Result<FlowRecord> record = flows_.find_generation(flow, generation);
  if (!record) {
    return Status::failure(ErrorCode::UNKNOWN_FLOW,
                           "flow has no generation " + generation.to_string());
  }
  RevocationRecord revocation;
  revocation.flow_id = flow;
  revocation.flow_generation = generation;
  revocation.revoked_by_session = envelope.session;
  revocation.revoked_by_publisher = envelope.publisher;
  revocation.epoch = epoch_;
  std::uint64_t seq = 0;
  {
    Status next = sequence_.next(seq);
    if (!next) return next;
  }
  revocation.seq = seq;
  revocation.revoked_tick = now();
  revocation.reason = reason.empty() ? std::string("revoked by request") : std::move(reason);
  Status status = decisions_.record_revocation(revocation);
  if (!status) return status;
  counters_.revocations += 1;
  return Status::success();
}

Result<std::vector<ClassificationContradiction>> Classifier::contradictions_for(
    const FlowId& flow) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return decisions_.contradictions_for(flow);
}

std::vector<RevocationRecord> Classifier::revocations() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return decisions_.revocations();
}

std::vector<SupersessionRecord> Classifier::supersessions() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return decisions_.supersessions();
}

// --- introspection ---------------------------------------------------------

Classifier::Stats Classifier::stats() const {
  std::lock_guard<std::mutex> guard(mutex_);
  Stats stats;
  stats.counters = counters_;
  stats.flows = flows_.stats();
  stats.flows.size = flows_.size();
  stats.publishers = publishers_.stats();
  stats.publishers.publishers = publishers_.size();
  stats.workloads = workloads_.stats();
  stats.workloads.workloads = workloads_.workload_count();
  stats.workloads.contracts = workloads_.contract_count();
  stats.evidence = evidence_.stats();
  stats.evidence.records = evidence_.size();
  stats.classifications = decisions_.stats();
  stats.classifications.memo_entries = decisions_.memo_entries();
  stats.policy_generation = policy_.generation;
  stats.policy_digest = policy_digest_;
  stats.epoch = epoch_;
  stats.coordinator_boot = coordinator_boot_;
  stats.next_sequence = sequence_.value();
  stats.memo_entries = decisions_.memo_entries();
  return stats;
}

Result<std::string> Classifier::explain(const FlowKey& key, FlowGeneration generation) {
  ClassificationQuery query;
  query.flow_key = key;
  query.flow_generation = generation;
  query.explain = true;
  query.accept_current_generation = generation.value == 0;
  Result<ClassificationResult> result = classify(query);
  if (!result) return result.status();
  if (result.value().explanation.empty()) {
    // A memo hit returns the stored classification without re-rendering.  The
    // explanation is a pure function of the decision and the question, so rendering it
    // here is exact rather than approximate.
    DecisionInput input;
    Result<FlowRecord> flow = find_flow(key);
    if (!flow) return flow.status();
    input.flow = flow.value();
    input.flow.generation = result.value().classification.flow_generation;
    input.policy = policy();
    std::lock_guard<std::mutex> guard(mutex_);
    input.authority = build_authority_context(now());
    input.authority.authority_sequence = authority_sequence_;
  input.authority.authority_sequence = authority_sequence_;
    input.active_contracts = workloads_.active_contracts();
    input.workloads = workloads_.snapshot_workloads();
    input.generation_revoked =
        decisions_.is_revoked(input.flow.id, result.value().classification.flow_generation);
    Result<std::vector<EvidenceId>> ids = evidence_.evidence_for_flow(input.flow.id);
    if (ids) {
      for (const EvidenceId& id : ids.value()) {
        Result<EvidenceRecord> record = evidence_.find(id);
        if (record) input.evidence.push_back(record.value());
      }
    }
    return DecisionEngine::render_explanation(result.value().classification, input);
  }
  return result.value().explanation;
}

// --- persistence -----------------------------------------------------------

Status Classifier::restore(CoordinatorBootId boot, std::vector<PublisherRecord> publishers,
                           std::vector<WorkloadRecord> workloads,
                           std::vector<WorkloadContract> contracts, std::vector<FlowRecord> flows,
                           std::vector<EvidenceRecord> evidence,
                           std::vector<Classification> classifications,
                           std::vector<RevocationRecord> revocations,
                           std::vector<SupersessionRecord> supersessions,
                           CoordinatorEpoch persisted_epoch, std::uint64_t persisted_sequence) {
  std::lock_guard<std::mutex> guard(mutex_);
  coordinator_boot_ = boot;
  // The durable incarnation counters are observed, never lowered.  Reusing an epoch would
  // let a pre-restart session envelope pass the epoch fence; reusing a sequence number
  // would contradict the guarantee that a sequence is monotonic and never reused.
  if (persisted_epoch.value > epoch_.value) {
    epoch_ = persisted_epoch;
  }
  sequence_.observe(persisted_sequence);
  Status status = publishers_.restore_records(publishers, now());
  if (!status) return status;
  for (const WorkloadRecord& record : workloads) {
    status = workloads_.restore_workload(record);
    if (!status) return status;
  }
  for (const WorkloadContract& contract : contracts) {
    status = workloads_.restore_contract(contract);
    if (!status) return status;
  }
  for (const FlowRecord& record : flows) {
    status = flows_.restore_flow(record);
    if (!status) return status;
  }
  for (const EvidenceRecord& record : evidence) {
    status = evidence_.restore_record(record);
    if (!status) return status;
  }
  for (const Classification& classification : classifications) {
    status = decisions_.restore_classification(classification);
    if (!status) return status;
  }
  for (const RevocationRecord& record : revocations) {
    status = decisions_.restore_revocation(record);
    if (!status) return status;
  }
  for (const SupersessionRecord& record : supersessions) {
    status = decisions_.restore_supersession(record);
    if (!status) return status;
  }
  // Deliberately not restored: sessions (cleared by restore_records), liveness
  // (never persisted) and the decision memo (keyed to an evidence set that is now
  // stale, so it could not be soundly reused).
  publishers_.clear_sessions();
  logger_.info("classifier restored from durable state; every session and every liveness claim "
               "was dropped and every restored evidence record is stale until republished");
  return Status::success();
}

std::uint64_t Classifier::next_sequence() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return sequence_.value();
}

}  // namespace aifc
