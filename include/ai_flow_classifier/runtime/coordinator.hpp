// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The coordinator: the process that owns current authority.
//
// It owns the classifier, the session table and the durable state directory.  Its
// defining behaviour is what happens across a restart:
//
//   1. the durable snapshot is read and every record in it is restored;
//   2. the epoch is advanced and the boot incarnation is advanced with it;
//   3. every restored session and every liveness claim is dropped, and every restored
//      evidence record is marked stale with a reason that names the restart.
//
// The consequence is what the closure checks require: a coordinator restart cannot
// resurrect liveness or freshness.  It is not a flag that someone could forget to
// check; the state that would have to be resurrected is not read back in.

#ifndef AI_FLOW_CLASSIFIER_RUNTIME_COORDINATOR_HPP
#define AI_FLOW_CLASSIFIER_RUNTIME_COORDINATOR_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "ai_flow_classifier/classify/classifier.hpp"
#include "ai_flow_classifier/net/channel.hpp"
#include "ai_flow_classifier/protocol/frame.hpp"
#include "ai_flow_classifier/protocol/messages.hpp"
#include "ai_flow_classifier/state/snapshot.hpp"

namespace aifc {

struct CoordinatorOptions {
  std::string state_path;
  ClassifierPolicy policy = ClassifierPolicy::initial();
  Logger logger;
  EvidenceSource default_session_source = EvidenceSource::DECLARED_AUTHENTICATED;
  bool persist_on_mutation = false;
  SnapshotLimits snapshot_limits{};
  std::chrono::milliseconds receive_timeout{2000};
  // Forwarded to the classifier.  A test substitutes a manual source to reach an exact freshness
  // boundary; production leaves it null and gets the monotonic default.
  const TickSource* clock = nullptr;
};

struct CoordinatorStats {
  std::uint64_t connections_accepted = 0;
  std::uint64_t connections_rejected = 0;
  std::uint64_t messages_handled = 0;
  std::uint64_t messages_refused = 0;
  std::uint64_t protocol_failures = 0;
  std::uint64_t snapshots_written = 0;
  std::uint64_t snapshot_failures = 0;
  std::uint64_t restarts = 0;
  std::uint64_t evictions = 0;
  std::size_t active_sessions = 0;
};

// Session binding established at HELLO time.  After the handshake, the coordinator
// treats this as the identity of the peer and ignores anything the peer says about
// itself in later messages.
struct CoordinatorSession {
  SessionId session;
  PublisherId publisher;
  PublisherBootId publisher_boot;
  EvidenceSource max_source = EvidenceSource::HEURISTIC;
  // True once HELLO has been accepted.  Every request below the handshake is refused without it, so
  // a peer cannot reach the classification surface by guessing the current epoch.
  bool handshaken = false;
  // True once REGISTER_PUBLISHER has been accepted.
  bool registered = false;
  Tick opened_tick = kTickNone;
};

class Coordinator {
 public:
  explicit Coordinator(CoordinatorOptions options);

  // Starts the coordinator: reads durable state, advances the epoch and boot
  // incarnation, and clears every volatile authority claim.
  Status start(CoordinatorBootId boot);

  // Stops cleanly.  Idempotent.
  Status stop();

  [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_acquire); }

  // Handles exactly one decoded frame from a session and produces the response.
  // Exposed so that the protocol tests can drive the state machine without a socket,
  // and so that the multiprocess tests can drive it over a real one.
  //
  // Every handler is written so that it never calls back out while holding the
  // coordinator mutex: the response is built first and returned, and the caller writes
  // it after this function has returned.
  Result<CoordinatorResponse> handle(std::string_view connection_key, CoordinatorSession& session,
                                     const Frame& frame);

  // Tears down a session.  Called when a connection ends for any reason, including an
  // abrupt one.  Evidence published by that incarnation stops being current.
  void close_session(std::string_view connection_key, CoordinatorSession& session);

  Status persist();
  Result<StateSnapshot> snapshot() const;

  [[nodiscard]] Classifier& classifier() noexcept { return classifier_; }
  [[nodiscard]] const Classifier& classifier() const noexcept { return classifier_; }
  [[nodiscard]] CoordinatorEpoch epoch() const { return classifier_.epoch(); }
  [[nodiscard]] CoordinatorBootId boot() const { return classifier_.coordinator_boot(); }
  [[nodiscard]] const std::string& state_path() const noexcept { return options_.state_path; }

  struct Stats {
    CoordinatorStats coordinator;
    Classifier::Stats classifier;
  };
  [[nodiscard]] Stats stats() const;

 private:
  Result<CoordinatorResponse> handle_hello(std::string_view key, CoordinatorSession& session,
                                           const Frame& frame);
  Result<CoordinatorResponse> handle_register_publisher(std::string_view key,
                                                        CoordinatorSession& session,
                                                        const Frame& frame);
  Result<CoordinatorResponse> handle_declare_workload(std::string_view key,
                                                      CoordinatorSession& session,
                                                      const Frame& frame);
  Result<CoordinatorResponse> handle_propose_contract(std::string_view key,
                                                      CoordinatorSession& session,
                                                      const Frame& frame);
  Result<CoordinatorResponse> handle_activate_contract(std::string_view key,
                                                       CoordinatorSession& session,
                                                       const Frame& frame);
  Result<CoordinatorResponse> handle_retire_contract(std::string_view key,
                                                     CoordinatorSession& session,
                                                     const Frame& frame);
  Result<CoordinatorResponse> handle_register_flow(std::string_view key,
                                                   CoordinatorSession& session, const Frame& frame);
  Result<CoordinatorResponse> handle_publish_evidence(std::string_view key,
                                                      CoordinatorSession& session,
                                                      const Frame& frame);
  Result<CoordinatorResponse> handle_withdraw_evidence(std::string_view key,
                                                       CoordinatorSession& session,
                                                       const Frame& frame);
  Result<CoordinatorResponse> handle_revoke(std::string_view key, CoordinatorSession& session,
                                            const Frame& frame);
  Result<CoordinatorResponse> handle_classify(std::string_view key, CoordinatorSession& session,
                                              const Frame& frame);
  Result<CoordinatorResponse> handle_stats(std::string_view key, CoordinatorSession& session,
                                           const Frame& frame);

  // Requires that the session has completed its publisher registration and that the frame's
  // declared epoch matches.  Returns the envelope the classifier must be given.
  Result<SessionEnvelope> require_registered(std::string_view key, CoordinatorSession& session,
                                             const Frame& frame);

  // Requires only that the session completed the handshake.  Used by the requests that are
  // deliberately not publisher-scoped: asking what a flow is does not require being able to say
  // what it is, but it does require having identified oneself.
  Status require_handshake(const CoordinatorSession& session, const Frame& frame) const;

  // Declaration order is the initialisation order.  The logger is constructed first so
  // that every later member can safely take a copy of it.
  Logger logger_;
  CoordinatorOptions options_;
  // Mutable so that introspection and persistence, which are logically const, can still
  // read the counters through the classifier's internal synchronisation.
  mutable Classifier classifier_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, bool> sessions_;
  std::atomic<bool> running_{false};
  CoordinatorStats stats_{};
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_RUNTIME_COORDINATOR_HPP
