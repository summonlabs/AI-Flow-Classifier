// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Wire framing.
//
//   offset  size  field
//        0     4  magic "AIFC"
//        4     2  protocol version
//        6     2  message kind
//        8     4  flags
//       12     8  connection sequence
//       20     8  sender epoch
//       28     8  sender boot id
//       36     4  payload length
//       40     4  CRC-32 of the header bytes 0..39 followed by the payload
//       44     N  payload
//
// Rules the reader enforces:
//
//   * the magic is checked first, so a stream that is not this protocol fails
//     immediately rather than being misinterpreted;
//   * a version outside [kProtocolVersionMin, kProtocolVersion] is refused with
//     UNSUPPORTED_VERSION;
//   * a payload longer than the effective bound is refused before allocation;
//   * the CRC is verified over the header and payload together, in constant time;
//   * a frame whose CRC fails is never partially applied: the caller receives an
//     integrity failure and the connection is expected to be closed.
//
// CRC-32 detects accidental corruption.  It is not a signature and this file does
// not pretend otherwise; authenticity comes from the session envelope, not from the
// frame.

#ifndef AI_FLOW_CLASSIFIER_PROTOCOL_FRAME_HPP
#define AI_FLOW_CLASSIFIER_PROTOCOL_FRAME_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/config.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

inline constexpr std::size_t kFrameHeaderBytes = 44;
inline constexpr std::uint8_t kFrameMagic[4] = {'A', 'I', 'F', 'C'};

enum class MessageKind : std::uint16_t {
  HELLO = 1,
  HELLO_ACK = 2,
  REGISTER_PUBLISHER = 3,
  DECLARE_WORKLOAD = 4,
  PROPOSE_CONTRACT = 5,
  ACTIVATE_CONTRACT = 6,
  RETIRE_CONTRACT = 7,
  REGISTER_FLOW = 8,
  PUBLISH_EVIDENCE = 9,
  WITHDRAW_EVIDENCE = 10,
  REVOKE_GENERATION = 11,
  CLASSIFY = 12,
  CLASSIFY_RESULT = 13,
  STATS_REQUEST = 14,
  STATS_RESPONSE = 15,
  ERROR_RESPONSE = 16,
  HEARTBEAT = 17,

  // One kind per response body.  An earlier version reused STATS_RESPONSE for the workload,
  // contract, flow-registration and evidence-acknowledgement bodies, which meant a peer that
  // decoded by kind -- the only sound way to decode -- received TRAILING_GARBAGE from a response
  // the coordinator had just produced.  A response kind that does not identify its body is not a
  // protocol.
  DECLARE_WORKLOAD_RESULT = 18,
  CONTRACT_RESULT = 19,
  REGISTER_FLOW_RESULT = 20,
  PUBLISH_EVIDENCE_RESULT = 21,
  WITHDRAW_RESULT = 22,
};

inline constexpr std::uint16_t kMaxMessageKind = 22;

[[nodiscard]] std::string_view to_string(MessageKind kind) noexcept;
[[nodiscard]] bool is_known_message_kind(std::uint16_t value) noexcept;
[[nodiscard]] bool is_response_kind(MessageKind kind) noexcept;

struct FrameHeader {
  std::uint16_t version = kProtocolVersion;
  MessageKind kind = MessageKind::HELLO;
  std::uint32_t flags = 0;
  std::uint64_t sequence = 0;
  std::uint64_t epoch = 0;
  std::uint64_t boot = 0;
  std::uint32_t payload_length = 0;
  std::uint32_t checksum = 0;
};

struct Frame {
  FrameHeader header;
  ByteBuffer payload;
};

// Encodes a frame, including the integrity tag.  Returns CAPACITY_EXCEEDED when the
// payload exceeds max_payload.
[[nodiscard]] Result<ByteBuffer> encode_frame(const FrameHeader& header, const ByteBuffer& payload,
                                             std::uint32_t max_payload);

// Attempts to decode one frame from the front of the buffer.
//
//   * Result value  : the decoded frame.
//   * consumed      : how many bytes the frame occupied.  Zero when more data is
//                     needed, in which case the status is ok and the caller should
//                     read more bytes.
//   * A non-ok status means the buffer can never become valid; the caller must close
//     the connection.
[[nodiscard]] Status try_decode_frame(const std::uint8_t* data, std::size_t size,
                                      std::uint32_t max_payload, Frame& frame,
                                      std::size_t& consumed);

// A stream accumulator that decodes frames as bytes arrive.  It refuses to buffer
// more than max_payload + header bytes, so a peer that never completes a frame cannot
// make the reader allocate without bound.
class FrameStream {
 public:
  explicit FrameStream(std::uint32_t max_payload)
      : max_payload_(max_payload), buffer_(static_cast<std::size_t>(max_payload) + kFrameHeaderBytes) {}

  Status append(const std::uint8_t* data, std::size_t size);
  // Returns true when a frame was produced.  A false return with ok() means "need
  // more bytes".
  Result<bool> next(Frame& frame);
  [[nodiscard]] std::size_t buffered() const noexcept { return size_; }
  [[nodiscard]] std::uint32_t max_payload() const noexcept { return max_payload_; }
  void clear() noexcept { size_ = 0; }

 private:
  std::uint32_t max_payload_;
  ByteBuffer buffer_;
  std::size_t size_ = 0;
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_PROTOCOL_FRAME_HPP
