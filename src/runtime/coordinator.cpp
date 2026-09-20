// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/runtime/coordinator.hpp"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/io/files.hpp"

namespace aifc {
namespace {

// The session identity is minted by the coordinator from the connection key and the
// handshake, never supplied by the peer.  Two connections from the same publisher get
// two identities, so revoking one does not revoke the other.
[[nodiscard]] SessionId mint_session_id(std::string_view connection_key,
                                        const PublisherId& publisher, PublisherBootId boot,
                                        std::uint64_t epoch) {
  const std::string material = std::string(connection_key) + "|" + publisher.value() + "|" +
                               boot.to_string() + "|" + std::to_string(epoch);
  const auto digest = sha256(material);
  static constexpr char kHex[] = "0123456789abcdef";
  std::string text = "sess-";
  text.reserve(5 + 16);
  for (std::size_t i = 0; i < 8; ++i) {
    text.push_back(kHex[(digest[i] >> 4) & 0x0FU]);
    text.push_back(kHex[digest[i] & 0x0FU]);
  }
  return SessionId(text);
}

}  // namespace

Coordinator::Coordinator(CoordinatorOptions options)
    : logger_(options.logger),
      options_(options),
      classifier_(ClassifierOptions{options_.policy, logger_, CoordinatorEpoch{1},
                                    CoordinatorBootId{1}, options_.clock}) {
  logger_.set_component("coordinator");
  options_ = std::move(options);
}

Status Coordinator::start(CoordinatorBootId boot) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (running_.load(std::memory_order_acquire)) {
    return Status::failure(ErrorCode::ALREADY_RUNNING, "coordinator is already running");
  }
  if (!boot.valid()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT,
                           "coordinator boot incarnation must be greater than zero");
  }

  if (!options_.state_path.empty()) {
    // A process that died mid-write leaves a temporary beside the state file.  A
    // temporary is never a valid snapshot -- atomic_replace only ever creates one for a
    // file it is about to replace -- so removing it cannot lose committed state.
    const std::string directory = path_directory(options_.state_path);
    Status created = create_directories(directory);
    if (!created) return created;
    Result<std::uint32_t> removed = recover_orphan_temporaries(directory, "");
    if (removed && removed.value() != 0) {
      logger_.info("removed " + std::to_string(removed.value()) +
                   " orphaned snapshot temporaries left by an earlier process");
    }

    Result<StateSnapshot> snapshot = read_snapshot_file(options_.state_path, options_.snapshot_limits);
    if (snapshot) {
      // Order matters: install the persisted policy first so that the stores are sized
      // by the policy that produced the data, then restore records, then advance the
      // epoch.  Advancing the epoch last means every restored record is compared
      // against the *new* epoch when the engine evaluates it.
      if (snapshot.value().policy.generation.valid()) {
        Result<ClassifierPolicyGeneration> policy_status =
            classifier_.set_policy(snapshot.value().policy);
        if (!policy_status) {
          logger_.warn("persisted policy was refused; continuing with the configured policy: " +
                           policy_status.status().message,
                       {}, "MALFORMED_INPUT");
        }
      }
      const Status restored =
          classifier_.restore(boot, snapshot.value().publishers, snapshot.value().workloads,
                              snapshot.value().contracts, snapshot.value().flows,
                              snapshot.value().evidence, snapshot.value().classifications,
                              snapshot.value().revocations, snapshot.value().supersessions,
                              snapshot.value().epoch, snapshot.value().sequence_high_water);
      if (!restored) {
        return Status::failure(restored.code,
                               "refusing to start on state that could not be restored: " +
                                   restored.message);
      }
      stats_.restarts += 1;
      logger_.info("coordinator restored " + std::to_string(snapshot.value().record_count()) +
                       " records from " + options_.state_path,
                   {}, "REVALIDATION_REQUIRED");
    } else if (snapshot.code() != ErrorCode::NOT_FOUND) {
      // A present but invalid state file is a hard failure.  Starting with a partial or
      // guessed state would be worse than not starting.
      return Status::failure(snapshot.code(), "refusing to start on an unreadable state file " +
                                                  options_.state_path + ": " + snapshot.message());
    }
  }

  // The epoch advance is what makes a restart safe: it invalidates every record
  // accepted before it and drops every session.  It happens after the restore so that
  // no restored record can be mistaken for a current one.
  Result<CoordinatorEpoch> epoch = classifier_.advance_epoch(boot);
  if (!epoch) return epoch.status();
  sessions_.clear();
  stats_.active_sessions = 0;
  running_.store(true, std::memory_order_release);
  logger_.info("coordinator started at epoch " + epoch.value().to_string() + " boot " +
               boot.to_string());
  return Status::success();
}

Status Coordinator::stop() {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!running_.load(std::memory_order_acquire)) {
    return Status::success();
  }
  running_.store(false, std::memory_order_release);
  sessions_.clear();
  stats_.active_sessions = 0;
  logger_.info("coordinator stopped");
  return Status::success();
}

Status Coordinator::require_handshake(const CoordinatorSession& session, const Frame& frame) const {
  if (!session.handshaken) {
    return Status::failure(ErrorCode::UNAUTHENTICATED,
                           "the session has not completed the protocol handshake; send HELLO first");
  }
  if (frame.header.epoch != classifier_.epoch().value) {
    return Status::failure(ErrorCode::STALE_EPOCH,
                           "frame declares coordinator epoch " +
                               std::to_string(frame.header.epoch) + " but the coordinator is at " +
                               classifier_.epoch().to_string());
  }
  return Status::success();
}

Result<SessionEnvelope> Coordinator::require_registered(std::string_view key,
                                                       CoordinatorSession& session,
                                                       const Frame& frame) {
  (void)key;
  const Status handshake = require_handshake(session, frame);
  if (!handshake) return handshake;
  if (!session.registered) {
    return Status::failure(ErrorCode::UNAUTHENTICATED,
                           "the session has not registered a publisher; send REGISTER_PUBLISHER "
                           "before any publisher-scoped message");
  }
  // The frame's declared epoch must match.  A frame that claims an epoch the coordinator
  // does not serve is refused before it can touch state.
  if (frame.header.epoch != classifier_.epoch().value) {
    return Status::failure(ErrorCode::STALE_EPOCH,
                           "frame declares coordinator epoch " +
                               std::to_string(frame.header.epoch) + " but the coordinator is at " +
                               classifier_.epoch().to_string());
  }
  SessionEnvelope envelope;
  envelope.publisher = session.publisher;
  envelope.publisher_boot = session.publisher_boot;
  envelope.session = session.session;
  envelope.epoch = classifier_.epoch();
  envelope.coordinator_boot = classifier_.coordinator_boot();
  envelope.max_source = session.max_source;
  envelope.received_tick = kTickNone;
  return envelope;
}

Result<CoordinatorResponse> Coordinator::handle(std::string_view connection_key,
                                                CoordinatorSession& session, const Frame& frame) {
  if (!running_.load(std::memory_order_acquire)) {
    return make_error_response(ErrorCode::NOT_RUNNING, "the coordinator is not running");
  }
  stats_.messages_handled += 1;
  switch (frame.header.kind) {
    case MessageKind::HELLO:
      return handle_hello(connection_key, session, frame);
    case MessageKind::REGISTER_PUBLISHER:
      return handle_register_publisher(connection_key, session, frame);
    case MessageKind::DECLARE_WORKLOAD:
      return handle_declare_workload(connection_key, session, frame);
    case MessageKind::PROPOSE_CONTRACT:
      return handle_propose_contract(connection_key, session, frame);
    case MessageKind::ACTIVATE_CONTRACT:
      return handle_activate_contract(connection_key, session, frame);
    case MessageKind::RETIRE_CONTRACT:
      return handle_retire_contract(connection_key, session, frame);
    case MessageKind::REGISTER_FLOW:
      return handle_register_flow(connection_key, session, frame);
    case MessageKind::PUBLISH_EVIDENCE:
      return handle_publish_evidence(connection_key, session, frame);
    case MessageKind::WITHDRAW_EVIDENCE:
      return handle_withdraw_evidence(connection_key, session, frame);
    case MessageKind::REVOKE_GENERATION:
      return handle_revoke(connection_key, session, frame);
    case MessageKind::CLASSIFY:
      return handle_classify(connection_key, session, frame);
    case MessageKind::STATS_REQUEST:
      return handle_stats(connection_key, session, frame);
    case MessageKind::HEARTBEAT: {
      // A heartbeat is contact, and contact is the only thing that refreshes liveness.
      if (session.registered) {
        (void)classifier_.heartbeat(session.publisher, session.publisher_boot);
      }
      CoordinatorResponse response;
      response.kind = MessageKind::HELLO_ACK;
      HelloResponse ack;
      ack.epoch = classifier_.epoch();
      ack.boot = classifier_.coordinator_boot();
      ack.granted_source = session.max_source;
      ack.coordinator_banner = product_banner();
      Status status = encode_hello_response(ack, response.payload);
      if (!status) return status;
      return response;
    }
    default:
      stats_.protocol_failures += 1;
      return make_error_response(ErrorCode::UNSUPPORTED_OPERATION,
                                 "message kind " +
                                     std::string(to_string(frame.header.kind)) +
                                     " is not accepted by the coordinator");
  }
}

Result<CoordinatorResponse> Coordinator::handle_hello(std::string_view key,
                                                      CoordinatorSession& session,
                                                      const Frame& frame) {
  Result<HelloRequest> hello = decode_hello(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!hello) {
    stats_.protocol_failures += 1;
    return make_error_response(hello.code(), hello.message());
  }
  if (hello.value().protocol_version < kProtocolVersionMin ||
      hello.value().protocol_version_min > kProtocolVersion) {
    stats_.protocol_failures += 1;
    return make_error_response(
        ErrorCode::UNSUPPORTED_VERSION,
        "peer supports protocol versions " + std::to_string(hello.value().protocol_version_min) +
            " to " + std::to_string(hello.value().protocol_version) +
            "; this coordinator speaks " + std::to_string(kProtocolVersionMin) + " to " +
            std::to_string(kProtocolVersion));
  }

  HelloResponse response;
  response.epoch = classifier_.epoch();
  response.boot = classifier_.coordinator_boot();
  // The granted source ceiling is the operator's choice, not the peer's request.  A
  // peer that sets kHelloFlagRequestHeuristics is asking to be admitted as a heuristic
  // source at most; it is never granted more than the configured default.
  EvidenceSource granted = options_.default_session_source;
  if ((hello.value().requested_flags & kHelloFlagRequestHeuristics) != 0U) {
    granted = source_rank(granted) < source_rank(EvidenceSource::HEURISTIC)
                  ? granted
                  : EvidenceSource::HEURISTIC;
  }
  response.granted_source = granted;
  response.coordinator_banner = product_banner();

  session.max_source = granted;
  session.handshaken = true;
  session.opened_tick = kTickNone;
  if (!hello.value().publisher.empty()) {
    session.publisher = hello.value().publisher;
  }
  session.session = mint_session_id(key, session.publisher, PublisherBootId{1},
                                    classifier_.epoch().value);

  std::lock_guard<std::mutex> guard(mutex_);
  sessions_[std::string(key)] = true;
  stats_.active_sessions = sessions_.size();

  CoordinatorResponse out;
  out.kind = MessageKind::HELLO_ACK;
  Status status = encode_hello_response(response, out.payload);
  if (!status) return status;
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_register_publisher(std::string_view key,
                                                                   CoordinatorSession& session,
                                                                   const Frame& frame) {
  Result<RegisterPublisherRequest> request =
      decode_register_publisher(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  if (frame.header.epoch != classifier_.epoch().value) {
    return make_error_response(ErrorCode::STALE_EPOCH,
                               "frame declares coordinator epoch " +
                                   std::to_string(frame.header.epoch) + " but the coordinator is at " +
                                   classifier_.epoch().to_string());
  }
  // Identity binding.  After the handshake the coordinator uses the identity the peer
  // presented here, and it binds it to this connection.  A later message cannot change
  // it, because later messages do not carry an identity at all.
  session.publisher = request.value().publisher;
  session.publisher_boot = request.value().boot;
  session.session = mint_session_id(key, session.publisher, session.publisher_boot,
                                    classifier_.epoch().value);

  Result<PublisherRegistration> registration = classifier_.register_publisher(
      session.publisher, session.publisher_boot, session.max_source, session.session,
      request.value().description);
  if (!registration) {
    stats_.messages_refused += 1;
    return make_error_response(registration.code(), registration.message());
  }
  session.registered = true;

  RegisterPublisherResponse response;
  response.session = session.session;
  response.epoch = classifier_.epoch();
  response.boot = classifier_.coordinator_boot();
  response.granted_source = session.max_source;
  response.default_freshness_window = classifier_.policy().default_freshness_window;

  CoordinatorResponse out;
  out.kind = MessageKind::HELLO_ACK;
  Status status = encode_register_publisher_response(response, out.payload);
  if (!status) return status;
  if (options_.persist_on_mutation) {
    // The durability point.  The acknowledgement is only produced after the effect is durable, so a
    // caller that receives success knows the mutation survives the process.  Discarding this status
    // would let a peer act on an acknowledgement for a change that was never committed.
    const Status committed = persist();
    if (!committed) {
      stats_.messages_refused += 1;
      return make_error_response(committed.code, committed.message);
    }
  }
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_declare_workload(std::string_view key,
                                                                 CoordinatorSession& session,
                                                                 const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<DeclareWorkloadRequest> request =
      decode_declare_workload(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  Result<WorkloadRecord> record = classifier_.declare_workload(
      request.value().workload, envelope.value().publisher, request.value().generation,
      request.value().description);
  if (!record) {
    stats_.messages_refused += 1;
    return make_error_response(record.code(), record.message());
  }
  CoordinatorResponse out;
  out.kind = MessageKind::DECLARE_WORKLOAD_RESULT;
  StatsResponse body;
  body.rendered = "workload " + record.value().id.value() + " generation " +
                  record.value().generation.to_string() + " state " +
                  std::string(to_string(record.value().state));
  Status status = encode_stats_response(body, out.payload);
  if (!status) return status;
  if (options_.persist_on_mutation) {
    // The durability point.  The acknowledgement is only produced after the effect is durable, so a
    // caller that receives success knows the mutation survives the process.  Discarding this status
    // would let a peer act on an acknowledgement for a change that was never committed.
    const Status committed = persist();
    if (!committed) {
      stats_.messages_refused += 1;
      return make_error_response(committed.code, committed.message);
    }
  }
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_propose_contract(std::string_view key,
                                                                 CoordinatorSession& session,
                                                                 const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<ProposeContractRequest> request =
      decode_propose_contract(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  // The owner is overwritten with the authenticated publisher.  A peer cannot propose a
  // contract on behalf of another publisher, and it cannot claim a derived-source
  // ceiling: both are coordinator decisions.
  WorkloadContract contract = request.value().contract;
  contract.owner = envelope.value().publisher;
  contract.derived_source = EvidenceSource::CONTRACT_DERIVED;
  Result<WorkloadContract> stored = classifier_.propose_contract(std::move(contract));
  if (!stored) {
    stats_.messages_refused += 1;
    return make_error_response(stored.code(), stored.message());
  }
  ContractResponse response;
  response.contract = stored.value();
  CoordinatorResponse out;
  out.kind = MessageKind::CONTRACT_RESULT;
  Status status = encode_contract_response(response, out.payload);
  if (!status) return status;
  if (options_.persist_on_mutation) {
    // The durability point.  The acknowledgement is only produced after the effect is durable, so a
    // caller that receives success knows the mutation survives the process.  Discarding this status
    // would let a peer act on an acknowledgement for a change that was never committed.
    const Status committed = persist();
    if (!committed) {
      stats_.messages_refused += 1;
      return make_error_response(committed.code, committed.message);
    }
  }
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_activate_contract(std::string_view key,
                                                                  CoordinatorSession& session,
                                                                  const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<ContractReferenceRequest> request =
      decode_contract_reference(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  Result<WorkloadContract> activated =
      classifier_.activate_contract(request.value().contract, envelope.value().publisher);
  if (!activated) {
    stats_.messages_refused += 1;
    return make_error_response(activated.code(), activated.message());
  }
  ContractResponse response;
  response.contract = activated.value();
  CoordinatorResponse out;
  out.kind = MessageKind::CONTRACT_RESULT;
  Status status = encode_contract_response(response, out.payload);
  if (!status) return status;
  if (options_.persist_on_mutation) {
    // The durability point.  The acknowledgement is only produced after the effect is durable, so a
    // caller that receives success knows the mutation survives the process.  Discarding this status
    // would let a peer act on an acknowledgement for a change that was never committed.
    const Status committed = persist();
    if (!committed) {
      stats_.messages_refused += 1;
      return make_error_response(committed.code, committed.message);
    }
  }
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_retire_contract(std::string_view key,
                                                                CoordinatorSession& session,
                                                                const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<ContractReferenceRequest> request =
      decode_contract_reference(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  Status status = classifier_.retire_contract(request.value().contract, envelope.value().publisher);
  if (!status) {
    stats_.messages_refused += 1;
    return make_error_response(status.code, status.message);
  }
  CoordinatorResponse out;
  out.kind = MessageKind::CONTRACT_RESULT;
  StatsResponse body;
  body.rendered = "contract " + request.value().contract.value() + " retired";
  status = encode_stats_response(body, out.payload);
  if (!status) return status;
  if (options_.persist_on_mutation) {
    // The durability point.  The acknowledgement is only produced after the effect is durable, so a
    // caller that receives success knows the mutation survives the process.  Discarding this status
    // would let a peer act on an acknowledgement for a change that was never committed.
    const Status committed = persist();
    if (!committed) {
      stats_.messages_refused += 1;
      return make_error_response(committed.code, committed.message);
    }
  }
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_register_flow(std::string_view key,
                                                              CoordinatorSession& session,
                                                              const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<RegisterFlowRequest> request =
      decode_register_flow(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  Result<FlowRegistration> registration = classifier_.register_flow(
      request.value().key, request.value().generation, envelope.value().session);
  if (!registration) {
    stats_.messages_refused += 1;
    return make_error_response(registration.code(), registration.message());
  }
  RegisterFlowResponse response;
  response.flow_id = registration.value().record.id;
  response.generation = registration.value().record.generation;
  response.fenced_previous = registration.value().fenced_previous;
  response.previous_generation = registration.value().previous_generation;
  CoordinatorResponse out;
  out.kind = MessageKind::REGISTER_FLOW_RESULT;
  Status status = encode_register_flow_response(response, out.payload);
  if (!status) return status;
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_publish_evidence(std::string_view key,
                                                                 CoordinatorSession& session,
                                                                 const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<PublishEvidenceRequest> request =
      decode_publish_evidence(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  Result<EvidenceSubmissionOutcome> outcome =
      classifier_.submit_evidence(envelope.value(), request.value().payload);
  if (!outcome) {
    stats_.messages_refused += 1;
    return make_error_response(outcome.code(), outcome.message());
  }
  PublishEvidenceResponse response;
  response.evidence_id = outcome.value().record.id;
  response.flow_id = outcome.value().record.flow_id;
  response.flow_generation = outcome.value().record.flow_generation;
  response.effective_source = outcome.value().effective_source;
  response.superseded_previous = outcome.value().superseded_previous;
  response.superseded_id = outcome.value().superseded_id;
  response.fenced_flow_generation = outcome.value().fenced_flow_generation;
  response.notes = outcome.value().notes;
  CoordinatorResponse out;
  out.kind = MessageKind::PUBLISH_EVIDENCE_RESULT;
  Status status = encode_publish_evidence_response(response, out.payload);
  if (!status) return status;
  if (options_.persist_on_mutation) {
    // The durability point.  The acknowledgement is only produced after the effect is durable, so a
    // caller that receives success knows the mutation survives the process.  Discarding this status
    // would let a peer act on an acknowledgement for a change that was never committed.
    const Status committed = persist();
    if (!committed) {
      stats_.messages_refused += 1;
      return make_error_response(committed.code, committed.message);
    }
  }
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_withdraw_evidence(std::string_view key,
                                                                  CoordinatorSession& session,
                                                                  const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<WithdrawEvidenceRequest> request =
      decode_withdraw_evidence(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  Status status =
      classifier_.withdraw_evidence(envelope.value(), request.value().evidence, request.value().reason);
  if (!status) {
    stats_.messages_refused += 1;
    return make_error_response(status.code, status.message);
  }
  CoordinatorResponse out;
  out.kind = MessageKind::WITHDRAW_RESULT;
  StatsResponse body;
  body.rendered = "evidence " + request.value().evidence.value() + " withdrawn";
  status = encode_stats_response(body, out.payload);
  if (!status) return status;
  if (options_.persist_on_mutation) {
    // The durability point.  The acknowledgement is only produced after the effect is durable, so a
    // caller that receives success knows the mutation survives the process.  Discarding this status
    // would let a peer act on an acknowledgement for a change that was never committed.
    const Status committed = persist();
    if (!committed) {
      stats_.messages_refused += 1;
      return make_error_response(committed.code, committed.message);
    }
  }
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_revoke(std::string_view key,
                                                       CoordinatorSession& session,
                                                       const Frame& frame) {
  Result<SessionEnvelope> envelope = require_registered(key, session, frame);
  if (!envelope) {
    stats_.messages_refused += 1;
    return make_error_response(envelope.code(), envelope.message());
  }
  Result<RevokeGenerationRequest> request =
      decode_revoke_generation(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  Status status = classifier_.revoke_generation(envelope.value(), request.value().flow_id,
                                                request.value().generation, request.value().reason);
  if (!status) {
    stats_.messages_refused += 1;
    return make_error_response(status.code, status.message);
  }
  CoordinatorResponse out;
  out.kind = MessageKind::WITHDRAW_RESULT;
  StatsResponse body;
  body.rendered = "flow generation revoked";
  status = encode_stats_response(body, out.payload);
  if (!status) return status;
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_classify(std::string_view key,
                                                         CoordinatorSession& session,
                                                         const Frame& frame) {
  (void)key;
  // Classification is deliberately not publisher-scoped: asking what a flow is does not require
  // being able to say what it is.  It does require a completed handshake, which is enforced here
  // rather than assumed of the caller -- an earlier version of this comment claimed the connection
  // handler did it, and the connection handler did nothing of the kind.
  const Status handshake = require_handshake(session, frame);
  if (!handshake) {
    stats_.messages_refused += 1;
    return make_error_response(handshake.code, handshake.message);
  }
  Result<ClassifyRequest> request =
      decode_classify_request(frame.payload, CodecLimits::from(classifier_.policy().limits));
  if (!request) {
    stats_.protocol_failures += 1;
    return make_error_response(request.code(), request.message());
  }
  std::vector<ClassificationQuery> queries;
  queries.reserve(request.value().entries.size());
  for (const ClassifyQueryEntry& entry : request.value().entries) {
    ClassificationQuery query;
    query.flow_key = entry.key;
    query.flow_generation = entry.generation;
    query.explain = entry.explain;
    query.accept_current_generation = entry.generation.value == 0;
    queries.push_back(query);
  }
  Result<Classifier::BatchOutcome> outcome = classifier_.classify_batch(queries);
  if (!outcome) {
    stats_.messages_refused += 1;
    return make_error_response(outcome.code(), outcome.message());
  }
  ClassifyResponse response;
  response.coordinator_epoch = classifier_.epoch().value;
  response.coordinator_boot = classifier_.coordinator_boot().value;
  response.succeeded = outcome.value().succeeded;
  response.failed = outcome.value().failed;
  response.classifications.reserve(outcome.value().results.size());
  response.per_key_codes.reserve(outcome.value().statuses.size());
  response.per_key_messages.reserve(outcome.value().statuses.size());
  response.explanations.reserve(outcome.value().results.size());
  for (std::size_t i = 0; i < outcome.value().results.size(); ++i) {
    response.classifications.push_back(outcome.value().results[i].classification);
    response.explanations.push_back(outcome.value().results[i].explanation);
    response.per_key_codes.push_back(outcome.value().statuses[i].code);
    response.per_key_messages.push_back(outcome.value().statuses[i].message);
  }
  CoordinatorResponse out;
  out.kind = MessageKind::CLASSIFY_RESULT;
  Status status = encode_classify_response(response, out.payload);
  if (!status) return status;
  return out;
}

Result<CoordinatorResponse> Coordinator::handle_stats(std::string_view key,
                                                      CoordinatorSession& session,
                                                      const Frame& frame) {
  (void)key;
  const Status handshake = require_handshake(session, frame);
  if (!handshake) {
    stats_.messages_refused += 1;
    return make_error_response(handshake.code, handshake.message);
  }
  const Stats stats_value = stats();
  StatsResponse body;
  body.rendered = "epoch=" + stats_value.classifier.epoch.to_string() +
                  " boot=" + stats_value.classifier.coordinator_boot.to_string() +
                  " publishers=" + std::to_string(stats_value.classifier.publishers.publishers) +
                  " live=" + std::to_string(stats_value.classifier.publishers.live) +
                  " flows=" + std::to_string(stats_value.classifier.flows.size) +
                  " evidence=" + std::to_string(stats_value.classifier.evidence.records) +
                  " decisions=" +
                  std::to_string(stats_value.classifier.classifications.decisions_recorded) +
                  " memo=" + std::to_string(stats_value.classifier.memo_entries) +
                  " messages=" + std::to_string(stats_value.coordinator.messages_handled) +
                  " refused=" + std::to_string(stats_value.coordinator.messages_refused);
  CoordinatorResponse out;
  out.kind = MessageKind::STATS_RESPONSE;
  Status status = encode_stats_response(body, out.payload);
  if (!status) return status;
  return out;
}

void Coordinator::close_session(std::string_view connection_key, CoordinatorSession& session) {
  {
    std::lock_guard<std::mutex> guard(mutex_);
    sessions_.erase(std::string(connection_key));
    stats_.active_sessions = sessions_.size();
  }
  if (!session.registered) return;
  // The session ended, so the incarnation that published through it has no current
  // authority.  The classifier marks the evidence stale rather than deleting it, so an
  // explanation still shows what used to be believed.
  Status status = classifier_.end_publisher_session(session.publisher, session.publisher_boot,
                                                   session.session);
  if (!status) {
    logger_.warn("failed to close publisher session " + session.publisher.value() + ": " +
                     status.message,
                 session.publisher.value(), std::string(to_string(status.code)));
  }
  if (options_.persist_on_mutation) {
    // A session close cannot be refused -- the connection is already gone -- so a failed commit is
    // reported rather than swallowed.  The next successful persist repairs the image.
    const Status committed = persist();
    if (!committed) {
      logger_.error("could not commit the state after a session ended: " + committed.message,
                    session.publisher.value(), std::string(to_string(committed.code)));
    }
  }
}

Status Coordinator::persist() {
  if (options_.state_path.empty()) {
    return Status::failure(ErrorCode::NOT_RUNNING,
                           "no state path is configured; there is nothing to persist to");
  }
  Result<StateSnapshot> image = snapshot();
  if (!image) return image.status();
  Status status = write_snapshot_file(options_.state_path, image.value(), options_.snapshot_limits);
  if (!status) {
    stats_.snapshot_failures += 1;
    logger_.error("snapshot write failed: " + status.message, {},
                  std::string(to_string(status.code)));
    return status;
  }
  stats_.snapshots_written += 1;
  return Status::success();
}

Result<StateSnapshot> Coordinator::snapshot() const {
  // The classifier produces the whole image under one acquisition of its own lock.  Reaching
  // through individual store accessors from here would walk containers that other threads are
  // mutating, which is a data race that shows up as heap corruption rather than as a wrong answer.
  const Classifier::DurableState state = classifier_.durable_state();
  StateSnapshot image;
  image.epoch = state.epoch;
  image.boot = state.coordinator_boot;
  image.sequence_high_water = state.sequence_high_water;
  image.policy = state.policy;
  image.publishers = state.publishers;
  image.workloads = state.workloads;
  image.contracts = state.contracts;
  image.flows = state.flows;
  image.evidence = state.evidence;
  image.classifications = state.classifications;
  image.revocations = state.revocations;
  image.supersessions = state.supersessions;
  return image;
}

Coordinator::Stats Coordinator::stats() const {
  Stats out;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    out.coordinator = stats_;
    out.coordinator.active_sessions = sessions_.size();
  }
  out.classifier = classifier_.stats();
  return out;
}

}  // namespace aifc
