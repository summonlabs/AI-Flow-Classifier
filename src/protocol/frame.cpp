// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/protocol/frame.hpp"

#include <cstring>
#include <string>

#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kKindOffset = 6;
constexpr std::size_t kFlagsOffset = 8;
constexpr std::size_t kSequenceOffset = 12;
constexpr std::size_t kEpochOffset = 20;
constexpr std::size_t kBootOffset = 28;
constexpr std::size_t kLengthOffset = 36;
constexpr std::size_t kChecksumOffset = 40;

}  // namespace

std::string_view to_string(MessageKind kind) noexcept {
  switch (kind) {
    case MessageKind::HELLO:
      return "HELLO";
    case MessageKind::HELLO_ACK:
      return "HELLO_ACK";
    case MessageKind::REGISTER_PUBLISHER:
      return "REGISTER_PUBLISHER";
    case MessageKind::DECLARE_WORKLOAD:
      return "DECLARE_WORKLOAD";
    case MessageKind::PROPOSE_CONTRACT:
      return "PROPOSE_CONTRACT";
    case MessageKind::ACTIVATE_CONTRACT:
      return "ACTIVATE_CONTRACT";
    case MessageKind::RETIRE_CONTRACT:
      return "RETIRE_CONTRACT";
    case MessageKind::REGISTER_FLOW:
      return "REGISTER_FLOW";
    case MessageKind::PUBLISH_EVIDENCE:
      return "PUBLISH_EVIDENCE";
    case MessageKind::WITHDRAW_EVIDENCE:
      return "WITHDRAW_EVIDENCE";
    case MessageKind::REVOKE_GENERATION:
      return "REVOKE_GENERATION";
    case MessageKind::CLASSIFY:
      return "CLASSIFY";
    case MessageKind::CLASSIFY_RESULT:
      return "CLASSIFY_RESULT";
    case MessageKind::STATS_REQUEST:
      return "STATS_REQUEST";
    case MessageKind::STATS_RESPONSE:
      return "STATS_RESPONSE";
    case MessageKind::ERROR_RESPONSE:
      return "ERROR_RESPONSE";
    case MessageKind::HEARTBEAT:
      return "HEARTBEAT";
    case MessageKind::DECLARE_WORKLOAD_RESULT:
      return "DECLARE_WORKLOAD_RESULT";
    case MessageKind::CONTRACT_RESULT:
      return "CONTRACT_RESULT";
    case MessageKind::REGISTER_FLOW_RESULT:
      return "REGISTER_FLOW_RESULT";
    case MessageKind::PUBLISH_EVIDENCE_RESULT:
      return "PUBLISH_EVIDENCE_RESULT";
    case MessageKind::WITHDRAW_RESULT:
      return "WITHDRAW_RESULT";
  }
  return "UNRECOGNIZED_MESSAGE_KIND";
}

bool is_known_message_kind(std::uint16_t value) noexcept {
  return value >= 1U && value <= kMaxMessageKind;
}

bool is_response_kind(MessageKind kind) noexcept {
  switch (kind) {
    case MessageKind::HELLO_ACK:
    case MessageKind::CLASSIFY_RESULT:
    case MessageKind::STATS_RESPONSE:
    case MessageKind::ERROR_RESPONSE:
    case MessageKind::DECLARE_WORKLOAD_RESULT:
    case MessageKind::CONTRACT_RESULT:
    case MessageKind::REGISTER_FLOW_RESULT:
    case MessageKind::PUBLISH_EVIDENCE_RESULT:
    case MessageKind::WITHDRAW_RESULT:
      return true;
    default:
      return false;
  }
}

Result<ByteBuffer> encode_frame(const FrameHeader& header, const ByteBuffer& payload,
                                std::uint32_t max_payload) {
  if (payload.size() > static_cast<std::size_t>(max_payload)) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "frame payload of " + std::to_string(payload.size()) +
                               " bytes exceeds the limit of " + std::to_string(max_payload));
  }
  if (!is_known_message_kind(static_cast<std::uint16_t>(header.kind))) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "message kind is not defined");
  }
  ByteBuffer out(kFrameHeaderBytes + payload.size());
  std::memcpy(out.data() + kMagicOffset, kFrameMagic, sizeof(kFrameMagic));
  store_u16_le(out.data() + kVersionOffset, header.version);
  store_u16_le(out.data() + kKindOffset, static_cast<std::uint16_t>(header.kind));
  store_u32_le(out.data() + kFlagsOffset, header.flags);
  store_u64_le(out.data() + kSequenceOffset, header.sequence);
  store_u64_le(out.data() + kEpochOffset, header.epoch);
  store_u64_le(out.data() + kBootOffset, header.boot);
  store_u32_le(out.data() + kLengthOffset, static_cast<std::uint32_t>(payload.size()));
  if (!payload.empty()) {
    std::memcpy(out.data() + kFrameHeaderBytes, payload.data(), payload.size());
  }
  // The checksum covers the header with the checksum field zeroed, followed by the
  // payload.  Zeroing first means the tag does not depend on itself.
  store_u32_le(out.data() + kChecksumOffset, 0U);
  const std::uint32_t checksum = crc32(out.data(), out.size());
  store_u32_le(out.data() + kChecksumOffset, checksum);
  return out;
}

Status try_decode_frame(const std::uint8_t* data, std::size_t size, std::uint32_t max_payload,
                        Frame& frame, std::size_t& consumed) {
  consumed = 0;
  if (size < kFrameHeaderBytes) {
    // Not enough bytes for a complete header yet.  This is not an error and it is not an answer: the
    // caller reads more and tries again.
    //
    // The one thing that can be decided from a prefix is that the stream is *not* this protocol, so a
    // mismatching magic is refused as soon as four bytes are available.  A matching magic decides
    // nothing -- the rest of the header is still missing -- so the read succeeds and the caller waits
    // for more.  Answering or closing on a matching four-byte prefix would tear down a peer that is
    // simply slower than the reader.
    if (size < sizeof(kFrameMagic)) {
      return Status::success();
    }
    if (std::memcmp(data + kMagicOffset, kFrameMagic, sizeof(kFrameMagic)) != 0) {
      return Status::failure(ErrorCode::MALFORMED_FRAME,
                             "stream does not begin with the AIFC frame magic");
    }
    return Status::success();
  }
  if (std::memcmp(data + kMagicOffset, kFrameMagic, sizeof(kFrameMagic)) != 0) {
    return Status::failure(ErrorCode::MALFORMED_FRAME,
                           "stream does not begin with the AIFC frame magic");
  }

  const std::uint16_t version = load_u16_le(data + kVersionOffset);
  if (version < kProtocolVersionMin || version > kProtocolVersion) {
    return Status::failure(ErrorCode::UNSUPPORTED_VERSION,
                           "frame declares protocol version " + std::to_string(version) +
                               "; this build supports " + std::to_string(kProtocolVersionMin) +
                               " to " + std::to_string(kProtocolVersion));
  }
  const std::uint16_t kind_value = load_u16_le(data + kKindOffset);
  if (!is_known_message_kind(kind_value)) {
    return Status::failure(ErrorCode::MALFORMED_FRAME,
                           "frame declares undefined message kind " + std::to_string(kind_value));
  }
  const std::uint32_t payload_length = load_u32_le(data + kLengthOffset);
  if (payload_length > max_payload) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "frame declares a payload of " + std::to_string(payload_length) +
                               " bytes, exceeding the limit of " + std::to_string(max_payload));
  }
  if (payload_length > size - kFrameHeaderBytes) {
    // The full frame has not arrived yet.
    return Status::success();
  }

  const std::size_t total = kFrameHeaderBytes + static_cast<std::size_t>(payload_length);
  const std::uint32_t declared_checksum = load_u32_le(data + kChecksumOffset);

  // Recompute the tag over the header exactly as it was sent, then compare in
  // constant time.  The comparison is only a habit here -- this is CRC-32, not a MAC
  // -- but it costs nothing and keeps the pattern uniform.
  ByteBuffer scratch(data, data + total);
  store_u32_le(scratch.data() + kChecksumOffset, 0U);
  const std::uint32_t computed = crc32(scratch.data(), scratch.size());
  const std::uint8_t declared_bytes[4] = {static_cast<std::uint8_t>(declared_checksum & 0xFFU),
                                          static_cast<std::uint8_t>((declared_checksum >> 8) & 0xFFU),
                                          static_cast<std::uint8_t>((declared_checksum >> 16) & 0xFFU),
                                          static_cast<std::uint8_t>((declared_checksum >> 24) & 0xFFU)};
  const std::uint8_t computed_bytes[4] = {static_cast<std::uint8_t>(computed & 0xFFU),
                                          static_cast<std::uint8_t>((computed >> 8) & 0xFFU),
                                          static_cast<std::uint8_t>((computed >> 16) & 0xFFU),
                                          static_cast<std::uint8_t>((computed >> 24) & 0xFFU)};
  if (!constant_time_equal(declared_bytes, computed_bytes, 4)) {
    return Status::failure(ErrorCode::INTEGRITY_FAILURE,
                           "frame integrity tag mismatch: declared " +
                               std::to_string(declared_checksum) + ", computed " +
                               std::to_string(computed));
  }

  frame.header.version = version;
  frame.header.kind = static_cast<MessageKind>(kind_value);
  frame.header.flags = load_u32_le(data + kFlagsOffset);
  frame.header.sequence = load_u64_le(data + kSequenceOffset);
  frame.header.epoch = load_u64_le(data + kEpochOffset);
  frame.header.boot = load_u64_le(data + kBootOffset);
  frame.header.payload_length = payload_length;
  frame.header.checksum = declared_checksum;
  frame.payload.assign(data + kFrameHeaderBytes, data + total);
  consumed = total;
  return Status::success();
}

Status FrameStream::append(const std::uint8_t* data, std::size_t size) {
  const std::size_t capacity = buffer_.size();
  if (size > capacity - size_) {
    return Status::failure(
        ErrorCode::CAPACITY_EXCEEDED,
        "peer sent " + std::to_string(size_) + " buffered bytes plus " + std::to_string(size) +
            " new bytes, which cannot contain a complete frame within the "
            "configured payload bound of " + std::to_string(max_payload_));
  }
  if (size != 0) {
    std::memcpy(buffer_.data() + size_, data, size);
    size_ += size;
  }
  return Status::success();
}

Result<bool> FrameStream::next(Frame& frame) {
  std::size_t consumed = 0;
  Frame decoded;
  Status status = try_decode_frame(buffer_.data(), size_, max_payload_, decoded, consumed);
  if (!status) return status;
  if (consumed == 0) {
    return false;
  }
  frame = std::move(decoded);
  if (consumed < size_) {
    std::memmove(buffer_.data(), buffer_.data() + consumed, size_ - consumed);
  }
  size_ -= consumed;
  return true;
}

}  // namespace aifc
