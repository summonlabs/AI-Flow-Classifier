// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Framed channel: a socket plus a frame codec plus a send mutex.
//
// A channel is the only thing the coordinator uses to talk to a peer.  It owns the
// receive accumulator, so a peer that sends a partial frame and then goes silent can
// never make the reader allocate beyond one frame's worth of buffer.

#ifndef AI_FLOW_CLASSIFIER_NET_CHANNEL_HPP
#define AI_FLOW_CLASSIFIER_NET_CHANNEL_HPP

#include <ostream>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/net/tcp.hpp"
#include "ai_flow_classifier/protocol/frame.hpp"

namespace aifc {

struct ChannelStats {
  std::uint64_t frames_sent = 0;
  std::uint64_t frames_received = 0;
  std::uint64_t bytes_sent = 0;
  std::uint64_t bytes_received = 0;
  std::uint64_t send_failures = 0;
  std::uint64_t receive_failures = 0;
  std::uint64_t decode_failures = 0;
};

class Channel {
 public:
  Channel() = default;
  Channel(Socket socket, std::uint32_t max_payload)
      : socket_(std::move(socket)), stream_(max_payload) {}

  Channel(const Channel&) = delete;
  Channel& operator=(const Channel&) = delete;
  Channel(Channel&& other) noexcept;
  Channel& operator=(Channel&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept { return socket_.valid(); }
  [[nodiscard]] Socket& socket() noexcept { return socket_; }
  [[nodiscard]] const Socket& socket() const noexcept { return socket_; }
  [[nodiscard]] const ChannelStats& stats() const noexcept { return stats_; }
  [[nodiscard]] std::uint32_t max_payload() const noexcept { return stream_.max_payload(); }

  [[nodiscard]] Result<std::string> peer_address() const { return socket_.peer_address(); }

  // Sends one frame.  The header's sequence field is filled in from an internal
  // counter so that a caller cannot accidentally reuse a sequence number.
  Status send(MessageKind kind, const ByteBuffer& payload, std::uint64_t epoch, std::uint64_t boot);

  // Waits for and returns one frame.  A timeout yields CONNECTION_CLOSED so that the
  // caller's loop can re-check its shutdown flag; there is no separate "would block"
  // result because a channel has no non-blocking mode.
  Result<Frame> receive(std::chrono::milliseconds timeout);

  Status shutdown_send();
  void close() noexcept;

 private:
  Socket socket_;
  FrameStream stream_{kMaxFramePayload};
  mutable std::mutex send_mutex_;
  std::uint64_t next_sequence_ = 1;
  ChannelStats stats_{};
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_NET_CHANNEL_HPP
