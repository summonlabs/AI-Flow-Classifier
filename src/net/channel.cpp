// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/net/channel.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <utility>

namespace aifc {
namespace {

// How long one receive call waits before returning control to its loop.  This is not a
// request timeout: it is the period at which a blocked reader notices that the runtime
// is shutting down.  The value is a property of the loop, not of the peer.
constexpr std::chrono::milliseconds kReceiveSlice{50};

}  // namespace

Channel::Channel(Channel&& other) noexcept
    : socket_(std::move(other.socket_)),
      stream_(other.stream_.max_payload()),
      next_sequence_(other.next_sequence_),
      stats_(other.stats_) {}

Channel& Channel::operator=(Channel&& other) noexcept {
  if (this != &other) {
    socket_ = std::move(other.socket_);
    stream_ = FrameStream(other.stream_.max_payload());
    next_sequence_ = other.next_sequence_;
    stats_ = other.stats_;
  }
  return *this;
}

Status Channel::send(MessageKind kind, const ByteBuffer& payload, std::uint64_t epoch,
                     std::uint64_t boot) {
  if (!socket_.valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "channel socket is not open");
  }
  FrameHeader header;
  header.version = kProtocolVersion;
  header.kind = kind;
  header.epoch = epoch;
  header.boot = boot;
  header.payload_length = static_cast<std::uint32_t>(payload.size());

  std::lock_guard<std::mutex> guard(send_mutex_);
  header.sequence = next_sequence_;
  Result<ByteBuffer> encoded = encode_frame(header, payload, stream_.max_payload());
  if (!encoded) {
    stats_.send_failures += 1;
    return encoded.status();
  }
  // The sequence is only advanced once the frame is on the wire, so a failed send does
  // not silently consume a sequence number and a retry reuses it.
  Result<std::size_t> written = socket_.send(encoded.value().data(), encoded.value().size());
  if (!written) {
    stats_.send_failures += 1;
    return written.status();
  }
  next_sequence_ += 1;
  stats_.frames_sent += 1;
  stats_.bytes_sent += written.value();
  return Status::success();
}

Result<Frame> Channel::receive(std::chrono::milliseconds timeout) {
  if (!socket_.valid()) {
    return Status::failure(ErrorCode::NOT_RUNNING, "channel socket is not open");
  }
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    Frame frame;
    Result<bool> decoded = stream_.next(frame);
    if (!decoded) {
      stats_.decode_failures += 1;
      return decoded.status();
    }
    if (decoded.value()) {
      stats_.frames_received += 1;
      return frame;
    }

    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return Status::failure(ErrorCode::CONNECTION_CLOSED,
                             "no complete frame arrived within the receive window");
    }
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    const auto slice = std::min(remaining, kReceiveSlice);
    Result<bool> ready = socket_.wait_readable(slice);
    if (!ready) {
      stats_.receive_failures += 1;
      return ready.status();
    }
    if (!ready.value()) {
      continue;
    }
    std::uint8_t chunk[16384];
    Result<std::size_t> received = socket_.receive(chunk, sizeof(chunk));
    if (!received) {
      stats_.receive_failures += 1;
      return received.status();
    }
    if (received.value() == 0) {
      // A clean end of stream with a partial frame buffered is a truncated frame, which
      // is a defect on the peer's part rather than a normal close.
      if (stream_.buffered() != 0) {
        stats_.decode_failures += 1;
        return Status::failure(ErrorCode::CONNECTION_RESET,
                               "peer closed the stream with " +
                                   std::to_string(stream_.buffered()) +
                                   " bytes of an incomplete frame buffered");
      }
      return Status::failure(ErrorCode::CONNECTION_CLOSED, "peer closed the connection");
    }
    stats_.bytes_received += received.value();
    Status appended = stream_.append(chunk, received.value());
    if (!appended) {
      stats_.decode_failures += 1;
      return appended;
    }
  }
}

Status Channel::shutdown_send() { return socket_.shutdown_send(); }

void Channel::close() noexcept {
  socket_.close();
  stream_.clear();
}

}  // namespace aifc
