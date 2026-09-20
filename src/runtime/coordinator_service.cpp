// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/runtime/coordinator_service.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <utility>

namespace aifc {
namespace {

// The deadline a worker uses when waiting for a queue entry.  It is a polling period,
// not a request timeout: it exists so a worker notices a stop request promptly.
constexpr std::chrono::milliseconds kQueueSlice{50};

}  // namespace

CoordinatorService::CoordinatorService(CoordinatorServiceOptions options)
    : logger_(options.coordinator.logger),
      options_(options),
      coordinator_(options_.coordinator) {
  logger_.set_component("service");
  options_ = std::move(options);
}

CoordinatorService::~CoordinatorService() {
  // A destructor must not throw and must not leave threads running.
  (void)stop();
}

Status CoordinatorService::start(CoordinatorBootId boot) {
  {
    std::lock_guard<std::mutex> guard(mutex_);
    if (running_.load(std::memory_order_acquire)) {
      return Status::failure(ErrorCode::ALREADY_RUNNING, "service is already running");
    }
    if (stopping_.load(std::memory_order_acquire)) {
      return Status::failure(ErrorCode::SHUTTING_DOWN,
                             "service is still stopping; wait for stop() to return");
    }
    stopping_.store(true, std::memory_order_release);
  }

  Status status = SocketSubsystem::acquire();
  if (!status) {
    std::lock_guard<std::mutex> guard(mutex_);
    stopping_.store(false, std::memory_order_release);
    return status;
  }

  status = coordinator_.start(boot);
  if (!status) {
    SocketSubsystem::release();
    std::lock_guard<std::mutex> guard(mutex_);
    stopping_.store(false, std::memory_order_release);
    return status;
  }

  Result<TcpListener> listener =
      TcpListener::listen_loopback(options_.port, std::max<std::uint32_t>(options_.backlog, 1U));
  if (!listener) {
    (void)coordinator_.stop();
    SocketSubsystem::release();
    std::lock_guard<std::mutex> guard(mutex_);
    stopping_.store(false, std::memory_order_release);
    return listener.status();
  }

  {
    std::lock_guard<std::mutex> guard(mutex_);
    listener_ = std::move(listener).value();
    port_ = listener_.port();
    queue_.clear();
    active_.clear();
    running_.store(true, std::memory_order_release);
    stopping_.store(false, std::memory_order_release);
    stats_.cycles_started += 1;
  }

  // Threads are created after the state they read is published.  Nothing is started
  // while a lock is held, because a thread that immediately blocks on that lock would
  // otherwise be joined by a stop() that is itself waiting for the lock.
  acceptor_ = std::thread([this]() { accept_loop(); });
  const std::uint32_t workers = std::max<std::uint32_t>(options_.worker_threads, 1U);
  workers_.reserve(workers);
  for (std::uint32_t i = 0; i < workers; ++i) {
    workers_.emplace_back([this]() { worker_loop(); });
  }

  logger_.info("service listening on " + loopback_endpoint(port_) + " with " +
               std::to_string(workers) + " worker threads");
  return Status::success();
}

void CoordinatorService::accept_loop() {
  while (!stopping_.load(std::memory_order_acquire)) {
    // The listener is closed by stop(), which makes this call return a socket error
    // instead of blocking for a full slice.  The slice is the fallback.
    Result<Socket> accepted = listener_.accept(options_.accept_slice);
    if (!accepted) {
      if (stopping_.load(std::memory_order_acquire)) break;
      // A transient accept failure is not fatal: the loop re-checks the stop flag and
      // tries again rather than tearing the service down.
      continue;
    }
    if (!accepted.value().valid()) continue;

    std::string key;
    {
      std::lock_guard<std::mutex> guard(mutex_);
      // stop() sets stopping_ while holding this same mutex, and then drains and clears the
      // queue.  The re-check therefore has to happen here, inside the critical section that
      // pushes, not before it: a connection accepted in that window would otherwise be queued
      // after the drain and after the clear, never served (every worker has already been told to
      // stop) and never closed either, because close_all_connections() has already run.  The
      // observable result was a service that reported a queued entry after stop() had returned,
      // holding a socket that stayed open until the next cycle.
      if (stopping_.load(std::memory_order_acquire)) {
        accepted.value().close();
        continue;
      }
      key = "conn-" + std::to_string(next_connection_id_++);
      if (active_.size() >= static_cast<std::size_t>(options_.coordinator.policy.limits.max_sessions) ||
          queue_.size() >= static_cast<std::size_t>(options_.coordinator.policy.limits.max_queue_depth)) {
        // The bounds are enforced here, before anything is queued, so a flood of
        // connections cannot grow the queue without limit.
        stats_.rejected += 1;
        stats_.queue_rejections += 1;
        accepted.value().close();
        continue;
      }
      auto channel = std::make_shared<Channel>(
          std::move(accepted.value()), options_.coordinator.policy.limits.max_frame_payload);
      active_.emplace(key, channel);
      queue_.push_back(Connection{channel, key});
      stats_.accepted += 1;
      stats_.queue_high_water = std::max<std::uint64_t>(stats_.queue_high_water, queue_.size());
      stats_.active_connections = active_.size();
    }
    queue_cv_.notify_one();
  }
}

void CoordinatorService::worker_loop() {
  for (;;) {
    Connection connection;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      queue_cv_.wait_for(lock, kQueueSlice, [this]() {
        return !queue_.empty() || stopping_.load(std::memory_order_acquire);
      });
      if (queue_.empty()) {
        if (stopping_.load(std::memory_order_acquire)) return;
        continue;
      }
      connection = std::move(queue_.front());
      queue_.pop_front();
      stats_.queued = queue_.size();
    }
    drained_cv_.notify_all();
    serve_connection(connection.channel, connection.key);
  }
}

void CoordinatorService::serve_connection(const std::shared_ptr<Channel>& channel,
                                          const std::string& key) {
  CoordinatorSession session;
  const auto deadline = std::chrono::steady_clock::now() + options_.receive_timeout;
  while (!stopping_.load(std::memory_order_acquire)) {
    Result<Frame> frame = channel->receive(options_.accept_slice);
    if (!frame) {
      if (frame.code() == ErrorCode::CONNECTION_CLOSED) {
        // Either the peer closed the stream or no complete frame arrived within the
        // slice.  Distinguish by checking whether the socket is still there.
        if (!channel->valid()) break;
        if (std::chrono::steady_clock::now() > deadline) break;
        continue;
      }
      if (frame.code() == ErrorCode::INTEGRITY_FAILURE ||
          frame.code() == ErrorCode::MALFORMED_FRAME) {
        // The bytes themselves are not trustworthy, so nothing is written back: the only correct
        // response to a stream this end cannot parse is to stop reading it.  Answering would ask the
        // peer to keep talking on a channel that has already been shown to be corrupt.
        break;
      }
      // Any other failure is terminal for this connection too, but the stream was coherent up to this
      // point, so the peer is told once on a best-effort basis before the connection closes.
      (void)channel->send(MessageKind::ERROR_RESPONSE,
                          make_error_response(frame.code(), frame.message()).payload,
                          coordinator_.epoch().value, coordinator_.boot().value);
      break;
    }
    const Frame& decoded = frame.value();
    Result<CoordinatorResponse> response = coordinator_.handle(key, session, decoded);
    if (!response) {
      CoordinatorResponse error = make_error_response(response.code(), response.message());
      (void)channel->send(error.kind, error.payload, coordinator_.epoch().value,
                          coordinator_.boot().value);
      break;
    }
    Status sent = channel->send(response.value().kind, response.value().payload,
                                coordinator_.epoch().value, coordinator_.boot().value);
    if (!sent) break;
    if (response.value().close_after_send) break;
  }

  coordinator_.close_session(key, session);
  channel->shutdown_send();
  {
    std::lock_guard<std::mutex> guard(mutex_);
    active_.erase(key);
    stats_.connections_served += 1;
    stats_.active_connections = active_.size();
  }
  channel->close();
}

void CoordinatorService::close_all_connections() {
  std::vector<std::shared_ptr<Channel>> channels;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    channels.reserve(active_.size());
    for (const auto& entry : active_) {
      channels.push_back(entry.second);
    }
  }
  // Sockets are closed with no lock held.  Closing a socket unblocks the reader that is
  // waiting on it, which is the mechanism that makes shutdown prompt rather than
  // dependent on a peer that has gone silent.
  for (const std::shared_ptr<Channel>& channel : channels) {
    channel->close();
  }
}

void CoordinatorService::join_threads() {
  if (acceptor_.joinable()) {
    acceptor_.join();
    stats_.threads_joined += 1;
  }
  for (std::thread& worker : workers_) {
    if (worker.joinable()) {
      worker.join();
      stats_.threads_joined += 1;
    }
  }
  workers_.clear();
}

Status CoordinatorService::stop() {
  bool expected_running = false;
  {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!running_.load(std::memory_order_acquire) && !stopping_.load(std::memory_order_acquire)) {
      return Status::success();
    }
    stopping_.store(true, std::memory_order_release);
    expected_running = running_.exchange(false, std::memory_order_acq_rel);
  }
  if (!expected_running && workers_.empty() && !acceptor_.joinable()) {
    return Status::success();
  }

  // 1. Stop accepting new work.  Closing the listener makes the pending accept return.
  listener_.close();
  queue_cv_.notify_all();

  // 2. Let queued work drain, but never wait forever: a peer that never completes a
  //    frame must not be able to hold the shutdown open indefinitely.
  {
    std::unique_lock<std::mutex> lock(mutex_);
    drained_cv_.wait_for(lock, options_.drain_timeout, [this]() { return queue_.empty(); });
    queue_.clear();
  }

  // 3. Unblock every reader by closing its socket.
  close_all_connections();
  queue_cv_.notify_all();

  // 4. Join.  No lock is held here, and every joinable thread has already been told to
  //    stop and had its blocking call cancelled, so these joins cannot deadlock.
  join_threads();

  {
    std::lock_guard<std::mutex> guard(mutex_);
    active_.clear();
    stats_.active_connections = 0;
    stats_.queued = 0;
    stats_.cycles_stopped += 1;
    stopping_.store(false, std::memory_order_release);
  }

  (void)coordinator_.stop();
  SocketSubsystem::release();
  logger_.info("service stopped; accepted=" + std::to_string(stats_.accepted) +
               " served=" + std::to_string(stats_.connections_served));
  return Status::success();
}

ServiceStats CoordinatorService::stats() const {
  std::lock_guard<std::mutex> guard(mutex_);
  ServiceStats out = stats_;
  out.active_connections = active_.size();
  out.queued = queue_.size();
  return out;
}

}  // namespace aifc
