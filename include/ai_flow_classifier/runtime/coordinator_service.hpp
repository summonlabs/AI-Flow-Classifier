// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The coordinator service: a coordinator plus the loopback TCP front end.
//
// Lifecycle contract
// ------------------
//
// start():
//   * acquires the socket subsystem, binds the listener, starts the accept thread and
//     the configured number of worker threads;
//   * refuses to start twice, and refuses to start while stopping.
//
// stop():
//   * sets the stopping flag first, so no new work is admitted;
//   * closes the listener, which makes the accept loop return immediately;
//   * waits for the queue to drain, bounded by the configured queue depth;
//   * closes every active connection, which makes each blocked reader observe a closed
//     socket rather than waiting out its receive window;
//   * joins every thread;
//   * releases the socket subsystem.
//
// Repeated start/stop cycles are exercised by the lifecycle tests, and the accounting
// is part of the observable interface: a cycle that leaks a thread, a connection or a
// queue entry shows up in the counters rather than in a slow drift.

#ifndef AI_FLOW_CLASSIFIER_RUNTIME_COORDINATOR_SERVICE_HPP
#define AI_FLOW_CLASSIFIER_RUNTIME_COORDINATOR_SERVICE_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "ai_flow_classifier/net/channel.hpp"
#include "ai_flow_classifier/net/tcp.hpp"
#include "ai_flow_classifier/runtime/coordinator.hpp"

namespace aifc {

struct CoordinatorServiceOptions {
  CoordinatorOptions coordinator{};
  std::uint16_t port = 0;
  std::uint32_t backlog = 32;
  std::uint32_t worker_threads = 2;
  std::chrono::milliseconds accept_slice{50};
  std::chrono::milliseconds receive_timeout{2000};
  std::chrono::milliseconds drain_timeout{5000};
};

struct ServiceStats {
  std::uint64_t cycles_started = 0;
  std::uint64_t cycles_stopped = 0;
  std::uint64_t accepted = 0;
  std::uint64_t rejected = 0;
  std::uint64_t connections_served = 0;
  std::uint64_t queue_high_water = 0;
  std::uint64_t queue_rejections = 0;
  std::uint64_t threads_joined = 0;
  std::size_t active_connections = 0;
  std::size_t queued = 0;
};

class CoordinatorService {
 public:
  explicit CoordinatorService(CoordinatorServiceOptions options);
  ~CoordinatorService();
  CoordinatorService(const CoordinatorService&) = delete;
  CoordinatorService& operator=(const CoordinatorService&) = delete;

  Status start(CoordinatorBootId boot);
  Status stop();

  [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_acquire); }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] Coordinator& coordinator() noexcept { return coordinator_; }
  [[nodiscard]] const Coordinator& coordinator() const noexcept { return coordinator_; }
  [[nodiscard]] ServiceStats stats() const;

 private:
  struct Connection {
    std::shared_ptr<Channel> channel;
    std::string key;
  };

  void accept_loop();
  void worker_loop();
  void serve_connection(const std::shared_ptr<Channel>& channel, const std::string& key);
  void close_all_connections();
  void join_threads();

  CoordinatorServiceOptions options_;
  Logger logger_;
  Coordinator coordinator_;
  TcpListener listener_;
  std::uint16_t port_ = 0;

  mutable std::mutex mutex_;
  std::condition_variable queue_cv_;
  std::condition_variable drained_cv_;
  std::deque<Connection> queue_;
  std::unordered_map<std::string, std::shared_ptr<Channel>> active_;
  std::vector<std::thread> workers_;
  std::thread acceptor_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stopping_{false};
  std::uint64_t next_connection_id_ = 1;
  ServiceStats stats_{};
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_RUNTIME_COORDINATOR_SERVICE_HPP
