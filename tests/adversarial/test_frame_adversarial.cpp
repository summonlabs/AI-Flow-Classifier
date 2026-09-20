// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Frame-level adversarial surface: bad magic, version skew in both directions, an
// undefined message kind, a declared payload length above the bound, a length that
// lies about the remaining bytes, a corrupted integrity tag, a truncated header, a
// truncated payload, two frames glued together, a frame split at every possible
// offset, a peer that sends a header and then stops, and a stream that tries to
// exceed the buffered bound.
//
// Capability labels
// -----------------
//   REAL        src/protocol/frame.cpp, exercised through its public API
//               (encode_frame, try_decode_frame, FrameStream).
//   SYNTHETIC   every byte fed to it.  No capture, no socket and no peer process is
//               involved in this file, and no case here claims otherwise.
//   UNSUPPORTED nothing in this surface is stubbed, skipped or disabled.
//
// What the integrity tag does and does not claim: the frame tag is CRC-32, which
// detects accidental corruption and is explicitly not a signature.  These cases
// therefore assert that a corrupted tag is refused; they never assert that an
// accepted frame is authentic.  Authenticity comes from the session envelope, which
// is exercised by the protocol and integration surfaces, not by this file.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/foundation/rng.hpp"
#include "ai_flow_classifier/protocol/frame.hpp"
#include "test_framework.hpp"

namespace {

using aifc::ByteBuffer;
using aifc::ErrorCode;
using aifc::Frame;
using aifc::FrameStream;
using aifc::MessageKind;
using aifc::Status;

// Deliberately small, so that the declared-length bound is reached with a handful of
// bytes and a bound violation can never be confused with a memory limit.  It is also
// chosen so that two small frames fit inside one stream buffer, which lets the
// split test feed two chunks without hitting the buffering bound.
constexpr std::uint32_t kMaxPayload = 64U;
constexpr std::size_t kSmallPayload = 8U;

// Field offsets of the canonical frame header.  They are restated here rather than
// borrowed from the implementation so that a silent layout change is a test failure
// and not a silently reinterpreted frame.
constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kVersionOffset = 4;
constexpr std::size_t kKindOffset = 6;
constexpr std::size_t kFlagsOffset = 8;
constexpr std::size_t kLengthOffset = 36;
constexpr std::size_t kChecksumOffset = 40;

[[nodiscard]] std::string hex_dump(const std::uint8_t* data, std::size_t size,
                                   std::size_t limit = 48) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  const std::size_t shown = size < limit ? size : limit;
  for (std::size_t i = 0; i < shown; ++i) {
    if (i != 0) out.push_back(' ');
    out.push_back(kHex[(data[i] >> 4) & 0x0FU]);
    out.push_back(kHex[data[i] & 0x0FU]);
  }
  if (shown != size) {
    out += " ... (";
    out += std::to_string(size);
    out += " bytes total)";
  }
  return out;
}

[[nodiscard]] std::string hex_dump(const ByteBuffer& bytes) {
  return hex_dump(bytes.data(), bytes.size());
}

[[nodiscard]] ByteBuffer payload_of(std::size_t size, std::uint8_t seed) {
  ByteBuffer out(size);
  for (std::size_t i = 0; i < size; ++i) {
    out[i] = static_cast<std::uint8_t>((static_cast<std::uint32_t>(seed) + i * 31U) & 0xFFU);
  }
  return out;
}

[[nodiscard]] aifc::FrameHeader reference_header() {
  aifc::FrameHeader header;
  header.version = aifc::kProtocolVersion;
  header.kind = MessageKind::PUBLISH_EVIDENCE;
  header.flags = 0x00000010U;
  header.sequence = 7;
  header.epoch = 3;
  header.boot = 9;
  return header;
}

[[nodiscard]] aifc::FrameHeader header_for(MessageKind kind, std::uint64_t sequence) {
  aifc::FrameHeader header = reference_header();
  header.kind = kind;
  header.sequence = sequence;
  header.epoch = 11;
  header.boot = 13;
  return header;
}

struct Decoded {
  Status status;
  std::size_t consumed = 0;
  Frame frame;
};

[[nodiscard]] Decoded decode(const std::uint8_t* data, std::size_t size,
                             std::uint32_t max_payload) {
  Decoded out;
  out.status = aifc::try_decode_frame(data, size, max_payload, out.frame, out.consumed);
  return out;
}

[[nodiscard]] Decoded decode(const ByteBuffer& bytes, std::uint32_t max_payload) {
  return decode(bytes.data(), bytes.size(), max_payload);
}

[[nodiscard]] ByteBuffer encode_or_fail(const aifc::FrameHeader& header,
                                        const ByteBuffer& payload, std::uint32_t max_payload,
                                        const std::string& what) {
  auto encoded = aifc::encode_frame(header, payload, max_payload);
  if (!encoded) {
    AIFC_FAIL("could not build the input for " << what << ": "
                                               << aifc::render_status(encoded.status()));
    return ByteBuffer{};
  }
  return encoded.value();
}

[[nodiscard]] ByteBuffer reference_image(std::size_t payload_size) {
  const ByteBuffer payload = payload_of(payload_size, 0x5AU);
  return encode_or_fail(reference_header(), payload, kMaxPayload,
                        "the reference frame of " + std::to_string(payload_size) +
                            " payload bytes");
}

void expect_code(const Decoded& decoded, ErrorCode expected, const std::string& context) {
  if (decoded.status.ok()) {
    AIFC_FAIL(context << ": expected " << aifc::to_string(expected)
                      << " but the decoder accepted the input and consumed " << decoded.consumed
                      << " bytes");
    return;
  }
  if (decoded.status.code != expected) {
    AIFC_FAIL(context << ": expected " << aifc::to_string(expected) << " but got "
                      << aifc::render_status(decoded.status));
  }
}

void expect_needs_more(const Decoded& decoded, const std::string& context) {
  if (!decoded.status) {
    AIFC_FAIL(context << ": expected a partial read (ok, consumed 0) but got "
                      << aifc::render_status(decoded.status));
    return;
  }
  if (decoded.consumed != 0) {
    AIFC_FAIL(context << ": expected a partial read (consumed 0) but the decoder consumed "
                      << decoded.consumed << " bytes");
  }
}

// A non-success decode must not have written anything into the caller's frame.  This is
// the "never invent a frame" rule expressed directly on the output parameter.
void expect_frame_untouched(const Frame& frame, const std::string& context) {
  if (!frame.payload.empty() || frame.header.payload_length != 0 || frame.header.sequence != 0 ||
      frame.header.epoch != 0 || frame.header.boot != 0) {
    AIFC_FAIL(context << ": the decoder wrote a frame on a non-success path: payload="
                      << frame.payload.size()
                      << " payload_length=" << frame.header.payload_length
                      << " sequence=" << frame.header.sequence << " epoch=" << frame.header.epoch
                      << " boot=" << frame.header.boot);
  }
}

void expect_same_payload(const ByteBuffer& actual, const ByteBuffer& expected,
                         const std::string& context) {
  if (actual.size() != expected.size()) {
    AIFC_FAIL(context << ": payload is " << actual.size() << " bytes, expected "
                      << expected.size() << "; actual=[" << hex_dump(actual) << "] expected=["
                      << hex_dump(expected) << "]");
    return;
  }
  for (std::size_t i = 0; i < actual.size(); ++i) {
    if (actual[i] != expected[i]) {
      AIFC_FAIL(context << ": payload byte " << i << " is "
                        << static_cast<unsigned>(actual[i]) << ", expected "
                        << static_cast<unsigned>(expected[i]) << "; actual=[" << hex_dump(actual)
                        << "]");
      return;
    }
  }
}

void patch_u16(ByteBuffer& bytes, std::size_t offset, std::uint16_t value) {
  aifc::store_u16_le(bytes.data() + offset, value);
}

void patch_u32(ByteBuffer& bytes, std::size_t offset, std::uint32_t value) {
  aifc::store_u32_le(bytes.data() + offset, value);
}

void flip_bit(ByteBuffer& bytes, std::size_t offset, std::size_t bit) {
  bytes[offset] = static_cast<std::uint8_t>(bytes[offset] ^ static_cast<std::uint8_t>(1U << bit));
}

[[nodiscard]] bool code_is_documented_refusal(ErrorCode code) {
  switch (code) {
    case ErrorCode::MALFORMED_FRAME:
    case ErrorCode::UNSUPPORTED_VERSION:
    case ErrorCode::CAPACITY_EXCEEDED:
    case ErrorCode::INTEGRITY_FAILURE:
      return true;
    default:
      return false;
  }
}

// The expectation for a single bit flip anywhere in a well-formed frame image.  It is
// derived from the documented reader order -- magic, version, kind, declared length,
// remaining bytes, integrity tag -- so this case fails if that order ever changes.
struct Expectation {
  bool needs_more = false;
  ErrorCode code = ErrorCode::OK;
};

[[nodiscard]] Expectation expectation_for_flip(const ByteBuffer& image, std::size_t offset,
                                               std::uint32_t max_payload) {
  Expectation expectation;
  const std::size_t available = image.size() - aifc::kFrameHeaderBytes;
  if (offset < kVersionOffset) {
    expectation.code = ErrorCode::MALFORMED_FRAME;
    return expectation;
  }
  if (offset < kKindOffset) {
    expectation.code = ErrorCode::UNSUPPORTED_VERSION;
    return expectation;
  }
  if (offset < kFlagsOffset) {
    const std::uint16_t kind = aifc::load_u16_le(image.data() + kKindOffset);
    expectation.code =
        aifc::is_known_message_kind(kind) ? ErrorCode::INTEGRITY_FAILURE : ErrorCode::MALFORMED_FRAME;
    return expectation;
  }
  if (offset >= kLengthOffset && offset < kChecksumOffset) {
    const std::uint32_t declared = aifc::load_u32_le(image.data() + kLengthOffset);
    if (declared > max_payload) {
      expectation.code = ErrorCode::CAPACITY_EXCEEDED;
    } else if (declared > available) {
      expectation.needs_more = true;
    } else {
      expectation.code = ErrorCode::INTEGRITY_FAILURE;
    }
    return expectation;
  }
  expectation.code = ErrorCode::INTEGRITY_FAILURE;
  return expectation;
}

struct SentFrame {
  aifc::FrameHeader header;
  ByteBuffer payload;
  ByteBuffer image;
};

[[nodiscard]] std::vector<SentFrame> build_glued_frames() {
  const MessageKind kinds[] = {MessageKind::HELLO, MessageKind::PUBLISH_EVIDENCE,
                               MessageKind::CLASSIFY};
  std::vector<SentFrame> frames;
  for (std::size_t i = 0; i < 3; ++i) {
    SentFrame sent;
    sent.header = header_for(kinds[i], 100U + i);
    sent.payload = payload_of(kSmallPayload, static_cast<std::uint8_t>(0xA0U + i));
    sent.image = encode_or_fail(sent.header, sent.payload, kMaxPayload,
                                "glued frame " + std::to_string(i));
    frames.push_back(std::move(sent));
  }
  return frames;
}

[[nodiscard]] ByteBuffer concatenate(const std::vector<SentFrame>& frames) {
  ByteBuffer out;
  for (const SentFrame& frame : frames) {
    out.insert(out.end(), frame.image.begin(), frame.image.end());
  }
  return out;
}

void expect_matches(const Frame& actual, const SentFrame& expected, const std::string& context) {
  if (actual.header.sequence != expected.header.sequence) {
    AIFC_FAIL(context << ": frame sequence is " << actual.header.sequence << ", expected "
                      << expected.header.sequence);
    return;
  }
  if (actual.header.kind != expected.header.kind) {
    AIFC_FAIL(context << ": frame kind is " << aifc::to_string(actual.header.kind)
                      << ", expected " << aifc::to_string(expected.header.kind));
    return;
  }
  if (actual.header.epoch != expected.header.epoch || actual.header.boot != expected.header.boot ||
      actual.header.flags != expected.header.flags) {
    AIFC_FAIL(context << ": frame identity fields differ: epoch=" << actual.header.epoch
                      << " boot=" << actual.header.boot << " flags=" << actual.header.flags
                      << " expected epoch=" << expected.header.epoch
                      << " boot=" << expected.header.boot << " flags=" << expected.header.flags);
    return;
  }
  expect_same_payload(actual.payload, expected.payload, context);
}

}  // namespace

AIFC_TEST("frame adversarial: magic, version and message kind are checked first") {
  const ByteBuffer payload = payload_of(16, 0x5AU);
  const ByteBuffer image =
      encode_or_fail(reference_header(), payload, kMaxPayload, "the reference frame");

  {
    const Decoded decoded = decode(image, kMaxPayload);
    AIFC_CHECK_MSG(decoded.status.ok(),
                   "the reference frame of " << image.size() << " bytes must decode: "
                                             << aifc::render_status(decoded.status) << " image=["
                                             << hex_dump(image) << "]");
    AIFC_CHECK_EQ(decoded.consumed, image.size());
    expect_same_payload(decoded.frame.payload, payload, "reference frame");
  }

  // --- not enough bytes for even the magic: a partial read, never an error ---
  for (std::size_t size = 0; size < sizeof(aifc::kFrameMagic); ++size) {
    const Decoded decoded = decode(image.data(), size, kMaxPayload);
    const std::string context = "prefix of " + std::to_string(size) + " bytes";
    expect_needs_more(decoded, context);
    expect_frame_untouched(decoded.frame, context);
  }

  // --- bad magic, with the whole magic present ---
  for (std::size_t byte = 0; byte < sizeof(aifc::kFrameMagic); ++byte) {
    for (std::size_t bit = 0; bit < 8; ++bit) {
      ByteBuffer mutated = image;
      flip_bit(mutated, byte, bit);
      const Decoded decoded = decode(mutated, kMaxPayload);
      const std::string context = "magic byte " + std::to_string(byte) + " bit " +
                                  std::to_string(bit) + " flipped, image=[" + hex_dump(mutated) +
                                  "]";
      expect_code(decoded, ErrorCode::MALFORMED_FRAME, context);
      expect_frame_untouched(decoded.frame, context);
    }
  }
  // --- bad magic inside a header that has not finished arriving ---
  for (std::size_t size = sizeof(aifc::kFrameMagic); size < aifc::kFrameHeaderBytes; ++size) {
    ByteBuffer mutated = image;
    mutated[kMagicOffset] = static_cast<std::uint8_t>(mutated[kMagicOffset] ^ 0xFFU);
    const Decoded decoded = decode(mutated.data(), size, kMaxPayload);
    expect_code(decoded, ErrorCode::MALFORMED_FRAME,
                "truncated header of " + std::to_string(size) +
                    " bytes carrying a bad magic byte, image=[" + hex_dump(mutated.data(), size) +
                    "]");
  }

  // --- version skew in both directions ---
  const std::uint16_t bad_versions[] = {
      0U, static_cast<std::uint16_t>(aifc::kProtocolVersionMin - 1U),
      static_cast<std::uint16_t>(aifc::kProtocolVersion + 1U), 0xFFFFU};
  for (const std::uint16_t version : bad_versions) {
    ByteBuffer mutated = image;
    patch_u16(mutated, kVersionOffset, version);
    const Decoded decoded = decode(mutated, kMaxPayload);
    const std::string context =
        "frame declaring protocol version " + std::to_string(version) +
        " while this build supports " + std::to_string(aifc::kProtocolVersionMin) + " to " +
        std::to_string(aifc::kProtocolVersion);
    expect_code(decoded, ErrorCode::UNSUPPORTED_VERSION, context);
    expect_frame_untouched(decoded.frame, context);
  }

  // --- undefined message kind ---
  const std::uint16_t bad_kinds[] = {0U, static_cast<std::uint16_t>(aifc::kMaxMessageKind + 1U),
                                     0x00FFU, 0xFFFFU};
  for (const std::uint16_t kind : bad_kinds) {
    ByteBuffer mutated = image;
    patch_u16(mutated, kKindOffset, kind);
    const Decoded decoded = decode(mutated, kMaxPayload);
    const std::string context = "frame declaring undefined message kind " + std::to_string(kind);
    expect_code(decoded, ErrorCode::MALFORMED_FRAME, context);
    expect_frame_untouched(decoded.frame, context);
    AIFC_CHECK_MSG(!aifc::is_known_message_kind(kind),
                   "kind " << kind << " must not be reported as known");
  }
  for (std::uint16_t kind = 1; kind <= aifc::kMaxMessageKind; ++kind) {
    AIFC_CHECK_MSG(aifc::is_known_message_kind(kind),
                   "kind " << kind << " must be known (it is inside 1.." << aifc::kMaxMessageKind
                           << ")");
  }
  AIFC_CHECK(!aifc::is_known_message_kind(static_cast<std::uint16_t>(aifc::kMaxMessageKind + 1U)));
  AIFC_CHECK(aifc::is_response_kind(MessageKind::HELLO_ACK));
  AIFC_CHECK(aifc::is_response_kind(MessageKind::CLASSIFY_RESULT));
  AIFC_CHECK(aifc::is_response_kind(MessageKind::STATS_RESPONSE));
  AIFC_CHECK(aifc::is_response_kind(MessageKind::ERROR_RESPONSE));
  AIFC_CHECK(!aifc::is_response_kind(MessageKind::HELLO));
  AIFC_CHECK(!aifc::is_response_kind(MessageKind::PUBLISH_EVIDENCE));
  AIFC_CHECK(!aifc::is_response_kind(static_cast<MessageKind>(aifc::kMaxMessageKind + 1U)));
}

AIFC_TEST("frame adversarial: a payload length above the bound is refused before allocation") {
  const ByteBuffer payload = payload_of(16, 0x11U);
  const ByteBuffer image =
      encode_or_fail(reference_header(), payload, kMaxPayload, "the reference frame");

  // The declared length is absurd and only 44 bytes exist.  The refusal must be the
  // bound and not "not enough bytes yet": a reader that checked the remaining bytes
  // first would sit and wait for four gigabytes.
  {
    ByteBuffer mutated = image;
    patch_u32(mutated, kLengthOffset, 0xFFFFFFFFU);
    const Decoded decoded = decode(mutated, kMaxPayload);
    expect_code(decoded, ErrorCode::CAPACITY_EXCEEDED,
                "frame declaring 0xFFFFFFFF payload bytes with only " +
                    std::to_string(mutated.size()) + " bytes present");
    expect_frame_untouched(decoded.frame, "absurd declared length");
  }
  {
    ByteBuffer mutated = image;
    patch_u32(mutated, kLengthOffset, kMaxPayload + 1U);
    const Decoded decoded = decode(mutated, kMaxPayload);
    expect_code(decoded, ErrorCode::CAPACITY_EXCEEDED,
                "frame declaring " + std::to_string(kMaxPayload + 1U) +
                    " payload bytes against a bound of " + std::to_string(kMaxPayload));
  }
  // The bound is inclusive: a declared length exactly at the bound is not a capacity
  // failure, it is a frame that has not finished arriving.
  {
    ByteBuffer mutated = image;
    patch_u32(mutated, kLengthOffset, kMaxPayload);
    expect_needs_more(decode(mutated, kMaxPayload),
                      "frame declaring exactly the bound (" + std::to_string(kMaxPayload) +
                          " payload bytes)");
  }
  // The encoder refuses to emit what the decoder would refuse to read.
  {
    const ByteBuffer too_big = payload_of(static_cast<std::size_t>(kMaxPayload) + 1U, 0x22U);
    AIFC_CHECK_ERR(aifc::encode_frame(reference_header(), too_big, kMaxPayload),
                   ErrorCode::CAPACITY_EXCEEDED);
    const ByteBuffer exactly = payload_of(kMaxPayload, 0x22U);
    auto encoded = aifc::encode_frame(reference_header(), exactly, kMaxPayload);
    AIFC_CHECK_OK(encoded);
    if (encoded) {
      AIFC_CHECK_EQ(encoded.value().size(), aifc::kFrameHeaderBytes + kMaxPayload);
      const Decoded decoded = decode(encoded.value(), kMaxPayload);
      AIFC_CHECK_MSG(decoded.status.ok(), "a frame at exactly the bound must decode: "
                                              << aifc::render_status(decoded.status));
      expect_same_payload(decoded.frame.payload, exactly, "frame at exactly the bound");
    }
  }
  // A zero bound means zero: only an empty payload is admissible.
  {
    auto empty = aifc::encode_frame(reference_header(), ByteBuffer{}, 0U);
    AIFC_CHECK_OK(empty);
    if (empty) {
      const Decoded decoded = decode(empty.value(), 0U);
      AIFC_CHECK_MSG(decoded.status.ok(), "an empty frame must decode under a zero bound: "
                                              << aifc::render_status(decoded.status));
      AIFC_CHECK_EQ(decoded.frame.payload.size(), std::size_t{0});
    }
    const ByteBuffer one = payload_of(1, 0x33U);
    AIFC_CHECK_ERR(aifc::encode_frame(reference_header(), one, 0U), ErrorCode::CAPACITY_EXCEEDED);
    const ByteBuffer one_byte_frame =
        encode_or_fail(reference_header(), one, kMaxPayload, "a one byte payload frame");
    expect_code(decode(one_byte_frame, 0U), ErrorCode::CAPACITY_EXCEEDED,
                "one byte payload frame read under a zero bound");
  }
  // An undefined message kind cannot be encoded either.
  {
    aifc::FrameHeader header = reference_header();
    header.kind = static_cast<MessageKind>(aifc::kMaxMessageKind + 1U);
    AIFC_CHECK_ERR(aifc::encode_frame(header, ByteBuffer{}, kMaxPayload),
                   ErrorCode::INVALID_ARGUMENT);
  }
}

AIFC_TEST("frame adversarial: a length that lies about the remaining bytes yields no frame") {
  const ByteBuffer payload = payload_of(32, 0x7CU);
  const ByteBuffer image =
      encode_or_fail(reference_header(), payload, kMaxPayload, "the reference frame");

  for (std::size_t size = 0; size < image.size(); ++size) {
    const Decoded decoded = decode(image.data(), size, kMaxPayload);
    const std::string context = "prefix of " + std::to_string(size) + " of " +
                                std::to_string(image.size()) + " bytes";
    expect_needs_more(decoded, context);
    expect_frame_untouched(decoded.frame, context);
  }

  // A truncated payload, stated as a declared length that overstates what is present.
  {
    ByteBuffer mutated = image;
    patch_u32(mutated, kLengthOffset, static_cast<std::uint32_t>(payload.size()) + 1U);
    const std::string context = "frame declaring one payload byte more than it carries";
    const Decoded decoded = decode(mutated, kMaxPayload);
    expect_needs_more(decoded, context);
    expect_frame_untouched(decoded.frame, context);
  }
  // A declared length that understates what is present: the tag covers the payload the
  // header declares, so a shortened frame cannot carry a matching tag.
  {
    ByteBuffer mutated = image;
    patch_u32(mutated, kLengthOffset, static_cast<std::uint32_t>(payload.size()) - 1U);
    expect_code(decode(mutated, kMaxPayload), ErrorCode::INTEGRITY_FAILURE,
                "frame understating its payload by one byte");
  }
}

AIFC_TEST("frame adversarial: every single bit flip is refused with the documented code") {
  const ByteBuffer payload = payload_of(32, 0x42U);
  const ByteBuffer image =
      encode_or_fail(reference_header(), payload, kMaxPayload, "the reference frame");

  for (std::size_t offset = 0; offset < image.size(); ++offset) {
    for (std::size_t bit = 0; bit < 8; ++bit) {
      ByteBuffer mutated = image;
      flip_bit(mutated, offset, bit);
      const Decoded decoded = decode(mutated, kMaxPayload);
      const std::string context =
          "byte " + std::to_string(offset) + " (" +
          (offset < aifc::kFrameHeaderBytes ? "header" : "payload") + ") bit " +
          std::to_string(bit) + " flipped, image=[" + hex_dump(mutated) + "]";
      const Expectation expectation = expectation_for_flip(mutated, offset, kMaxPayload);
      if (expectation.needs_more) {
        expect_needs_more(decoded, context);
        expect_frame_untouched(decoded.frame, context);
        continue;
      }
      expect_code(decoded, expectation.code, context);
      expect_frame_untouched(decoded.frame, context);
    }
  }

  // The named integrity failures, so that the code is pinned by name and not only by
  // the table above.
  {
    ByteBuffer altered_payload = payload;
    flip_bit(altered_payload, 5, 3);
    ByteBuffer mutated = image;
    flip_bit(mutated, aifc::kFrameHeaderBytes + 5U, 3U);
    expect_code(decode(mutated, kMaxPayload), ErrorCode::INTEGRITY_FAILURE,
                "payload byte 5 bit 3 flipped");
    // Re-tagging the same content makes it acceptable, which proves the refusal above
    // was the tag and nothing else.
    const ByteBuffer retagged =
        encode_or_fail(reference_header(), altered_payload, kMaxPayload, "the re-tagged frame");
    const Decoded accepted = decode(retagged, kMaxPayload);
    AIFC_CHECK_MSG(accepted.status.ok(), "a frame re-tagged over the same content must decode: "
                                             << aifc::render_status(accepted.status));
    expect_same_payload(accepted.frame.payload, altered_payload, "re-tagged frame");
  }
  {
    ByteBuffer mutated = image;
    flip_bit(mutated, kChecksumOffset, 0U);
    expect_code(decode(mutated, kMaxPayload), ErrorCode::INTEGRITY_FAILURE,
                "integrity tag byte 0 bit 0 flipped");
  }
  {
    ByteBuffer mutated = image;
    flip_bit(mutated, kFlagsOffset + 1U, 2U);
    expect_code(decode(mutated, kMaxPayload), ErrorCode::INTEGRITY_FAILURE,
                "header flags bit flipped");
  }
  // The reference image itself was not modified by any of the above.
  {
    const ByteBuffer fresh =
        encode_or_fail(reference_header(), payload, kMaxPayload, "a fresh reference frame");
    AIFC_CHECK_MSG(fresh == image, "the reference frame encoding changed during this case");
  }
}

AIFC_TEST("frame adversarial: two frames glued together both decode, in order") {
  const std::vector<SentFrame> frames = build_glued_frames();
  const ByteBuffer glued = concatenate(frames);
  AIFC_CHECK_EQ(glued.size(), 3U * (aifc::kFrameHeaderBytes + kSmallPayload));

  // --- raw reader walk ---
  std::size_t offset = 0;
  std::size_t index = 0;
  while (offset < glued.size() && index < frames.size()) {
    const Decoded decoded = decode(glued.data() + offset, glued.size() - offset, kMaxPayload);
    const std::string context =
        "glued stream at offset " + std::to_string(offset) + " frame " + std::to_string(index);
    AIFC_CHECK_MSG(decoded.status.ok(), context << ": " << aifc::render_status(decoded.status));
    if (!decoded.status) break;
    AIFC_CHECK_MSG(decoded.consumed == frames[index].image.size(),
                   context << ": consumed " << decoded.consumed << " bytes, expected "
                           << frames[index].image.size());
    expect_matches(decoded.frame, frames[index], context);
    offset += decoded.consumed;
    ++index;
  }
  AIFC_CHECK_EQ(index, frames.size());
  AIFC_CHECK_EQ(offset, glued.size());
  // Nothing is left, so the next read is a partial read and not an error.
  {
    const Decoded tail = decode(glued.data() + glued.size(), 0, kMaxPayload);
    expect_needs_more(tail, "exhausted glued stream");
  }

  // --- stream walk, one append per frame ---
  {
    FrameStream stream(kMaxPayload);
    for (std::size_t i = 0; i < frames.size(); ++i) {
      const Status appended = stream.append(frames[i].image.data(), frames[i].image.size());
      AIFC_CHECK_MSG(appended.ok(), "append of frame " << i << " failed: "
                                                       << aifc::render_status(appended));
      Frame frame;
      auto produced = stream.next(frame);
      AIFC_CHECK_MSG(produced.ok(), "next() after frame " << i << " failed: "
                                                          << aifc::render_status(produced.status()));
      if (!produced) continue;
      AIFC_CHECK_MSG(produced.value(), "frame " << i << " was not produced by the stream: "
                                                << aifc::render_status(produced.status()));
      if (produced.value()) expect_matches(frame, frames[i], "stream frame " + std::to_string(i));
      AIFC_CHECK_EQ(stream.buffered(), std::size_t{0});
    }
    Frame frame;
    auto produced = stream.next(frame);
    AIFC_CHECK(produced.ok());
    if (produced) AIFC_CHECK_MSG(!produced.value(), "an exhausted stream produced another frame");
  }
}

AIFC_TEST("frame adversarial: a frame split at every possible offset produces exactly that frame") {
  const std::vector<SentFrame> all_frames = build_glued_frames();
  // Exactly two frames: both fit inside one stream buffer, so no split of this image
  // can trip the buffering bound and every split is genuinely exercised.  The
  // buffering bound itself is covered by its own case below.
  const std::vector<SentFrame> frames = {all_frames[0], all_frames[1]};
  const ByteBuffer glued = concatenate(frames);

  // Two appends, split at every offset.
  for (std::size_t split = 0; split <= glued.size(); ++split) {
    FrameStream stream(kMaxPayload);
    std::vector<Frame> produced;
    bool failed = false;
    const auto feed = [&](const std::uint8_t* data, std::size_t size, const char* what) {
      const Status appended = stream.append(data, size);
      if (!appended) {
        AIFC_FAIL("split at " << split << ", append of " << what << " (" << size
                              << " bytes) failed: " << aifc::render_status(appended));
        failed = true;
        return;
      }
      for (;;) {
        Frame frame;
        auto next = stream.next(frame);
        if (!next) {
          AIFC_FAIL("split at " << split << ", next() after " << what
                                << " failed: " << aifc::render_status(next.status()));
          failed = true;
          return;
        }
        if (!next.value()) return;
        produced.push_back(std::move(frame));
      }
    };
    feed(glued.data(), split, "the first chunk");
    if (failed) continue;
    feed(glued.data() + split, glued.size() - split, "the second chunk");
    if (failed) continue;
    if (produced.size() != frames.size()) {
      AIFC_FAIL("split at " << split << ": produced " << produced.size() << " frames, expected "
                            << frames.size());
      continue;
    }
    for (std::size_t i = 0; i < frames.size(); ++i) {
      expect_matches(produced[i], frames[i],
                     "split at " + std::to_string(split) + " frame " + std::to_string(i));
    }
  }

  // One byte at a time, which is the worst case a stream can be asked to absorb.
  {
    FrameStream stream(kMaxPayload);
    std::vector<Frame> produced;
    for (std::size_t i = 0; i < glued.size(); ++i) {
      const Status appended = stream.append(glued.data() + i, 1);
      AIFC_CHECK_MSG(appended.ok(), "byte-by-byte append at byte " << i << " failed: "
                                                                   << aifc::render_status(appended));
      if (!appended) break;
      for (;;) {
        Frame frame;
        auto next = stream.next(frame);
        AIFC_CHECK_MSG(next.ok(), "byte-by-byte next() at byte " << i << " failed: "
                                                                 << aifc::render_status(next.status()));
        if (!next || !next.value()) break;
        produced.push_back(std::move(frame));
      }
    }
    AIFC_CHECK_EQ(produced.size(), frames.size());
    for (std::size_t i = 0; i < produced.size() && i < frames.size(); ++i) {
      expect_matches(produced[i], frames[i], "byte-by-byte frame " + std::to_string(i));
    }
  }
}

AIFC_TEST("frame adversarial: a header followed by silence never becomes a frame") {
  const ByteBuffer payload = payload_of(16, 0x6DU);
  const ByteBuffer image =
      encode_or_fail(reference_header(), payload, kMaxPayload, "the reference frame");
  const std::size_t header_bytes = aifc::kFrameHeaderBytes;

  {
    const Decoded decoded = decode(image.data(), header_bytes, kMaxPayload);
    expect_needs_more(decoded, "header alone through try_decode_frame");
    expect_frame_untouched(decoded.frame, "header alone through try_decode_frame");
  }

  FrameStream stream(kMaxPayload);
  {
    const Status appended = stream.append(image.data(), header_bytes);
    AIFC_CHECK_MSG(appended.ok(), "appending a bare header failed: "
                                      << aifc::render_status(appended));
    AIFC_CHECK_EQ(stream.buffered(), header_bytes);
  }
  // Silence: next() reports "need more bytes", repeatedly, and never a frame.
  for (int attempt = 0; attempt < 3; ++attempt) {
    Frame frame;
    auto next = stream.next(frame);
    AIFC_CHECK_MSG(next.ok(), "next() over a stalled header failed at attempt "
                                  << attempt << ": " << aifc::render_status(next.status()));
    if (!next) break;
    AIFC_CHECK_MSG(!next.value(), "a stalled header produced a frame at attempt " << attempt);
    expect_frame_untouched(frame, "stalled header");
    AIFC_CHECK_EQ(stream.buffered(), header_bytes);
  }
  // A zero length append is not progress either.
  {
    const Status appended = stream.append(image.data() + header_bytes, 0);
    AIFC_CHECK_MSG(appended.ok(), "a zero length append failed: "
                                      << aifc::render_status(appended));
    AIFC_CHECK_EQ(stream.buffered(), header_bytes);
  }
  // Every byte of the payload except the last: still no frame.
  {
    const Status appended =
        stream.append(image.data() + header_bytes, payload.size() - 1U);
    AIFC_CHECK_MSG(appended.ok(), "appending all but one payload byte failed: "
                                      << aifc::render_status(appended));
    Frame frame;
    auto next = stream.next(frame);
    AIFC_CHECK(next.ok());
    if (next) {
      AIFC_CHECK_MSG(!next.value(), "a frame missing its last payload byte was produced");
      expect_frame_untouched(frame, "frame missing its last payload byte");
    }
  }
  // The last byte completes the frame.
  {
    const Status appended =
        stream.append(image.data() + header_bytes + payload.size() - 1U, 1);
    AIFC_CHECK_MSG(appended.ok(), "the final payload byte failed to append: "
                                      << aifc::render_status(appended));
    Frame frame;
    auto next = stream.next(frame);
    AIFC_CHECK_MSG(next.ok(), "the completed frame failed: " << aifc::render_status(next.status()));
    if (next) {
      AIFC_CHECK_MSG(next.value(), "the completed frame was not produced");
      if (next.value()) expect_matches(frame, SentFrame{reference_header(), payload, image},
                                       "frame completed one byte at a time");
    }
    AIFC_CHECK_EQ(stream.buffered(), std::size_t{0});
  }
  // And the stream is empty again: another next() yields nothing.
  {
    Frame frame;
    auto next = stream.next(frame);
    AIFC_CHECK(next.ok());
    if (next) AIFC_CHECK(!next.value());
  }
}

AIFC_TEST("frame adversarial: exceeding the buffered bound is CAPACITY_EXCEEDED and changes nothing") {
  const ByteBuffer payload = payload_of(16, 0x99U);
  const ByteBuffer image =
      encode_or_fail(reference_header(), payload, kMaxPayload, "the reference frame");
  const std::size_t header_bytes = aifc::kFrameHeaderBytes;

  // A stream bound of 8 payload bytes: its buffer holds 8 + 44 = 52 bytes.
  const ByteBuffer small_payload = payload_of(8, 0x99U);
  const ByteBuffer small_frame =
      encode_or_fail(reference_header(), small_payload, 8U, "an 8 byte payload frame");
  AIFC_CHECK_EQ(small_frame.size(), header_bytes + 8U);

  FrameStream stream(8U);
  AIFC_CHECK_EQ(stream.max_payload(), 8U);
  {
    const Status appended = stream.append(small_frame.data(), header_bytes);
    AIFC_CHECK_MSG(appended.ok(), "appending a header failed: "
                                      << aifc::render_status(appended));
    AIFC_CHECK_EQ(stream.buffered(), header_bytes);
    Frame frame;
    auto next = stream.next(frame);
    AIFC_CHECK_MSG(next.ok(), "a frame that has not finished arriving is not an error: "
                                  << aifc::render_status(next.status()));
    if (next) {
      AIFC_CHECK_MSG(!next.value(), "a header alone was reported as a complete frame");
    }
    expect_frame_untouched(frame, "header alone against a stream bound");
  }
  // The buffered bound refuses the excess and copies nothing: the reported buffered
  // length still describes exactly what the stream holds.
  {
    const Status appended = stream.append(image.data() + header_bytes, 9U);
    if (appended.ok()) {
      AIFC_FAIL("appending 9 bytes over a stream already holding " << header_bytes
                                                                   << " bytes against a bound of "
                                                                   << 8U + header_bytes
                                                                   << " must fail");
    } else if (appended.code != ErrorCode::CAPACITY_EXCEEDED) {
      AIFC_FAIL("exceeding the buffered bound: expected CAPACITY_EXCEEDED but got "
                << aifc::render_status(appended));
    }
    AIFC_CHECK_EQ(stream.buffered(), header_bytes);
  }
  // A whole oversized chunk is refused in one call as well.
  {
    const Status appended = stream.append(image.data(), image.size());
    if (appended.ok()) {
      AIFC_FAIL("appending a whole " << image.size() << " byte frame against a bound of "
                                     << 8U + header_bytes << " must fail");
    } else if (appended.code != ErrorCode::CAPACITY_EXCEEDED) {
      AIFC_FAIL("oversized chunk: expected CAPACITY_EXCEEDED but got "
                << aifc::render_status(appended));
    }
    AIFC_CHECK_EQ(stream.buffered(), header_bytes);
  }
  // Exactly the bound is accepted, and the frame comes out.
  {
    FrameStream exact_stream(8U);
    const Status appended = exact_stream.append(small_frame.data(), small_frame.size());
    AIFC_CHECK_MSG(appended.ok(), "a frame at exactly the buffered bound must be accepted: "
                                      << aifc::render_status(appended));
    AIFC_CHECK_EQ(exact_stream.buffered(), small_frame.size());
    Frame frame;
    auto next = exact_stream.next(frame);
    AIFC_CHECK_MSG(next.ok(), "a frame at exactly the bound must decode: "
                                  << aifc::render_status(next.status()));
    if (next) {
      AIFC_CHECK_MSG(next.value(), "a frame at exactly the buffered bound was not produced");
      if (next.value()) {
        expect_same_payload(frame.payload, small_payload, "frame at exactly the buffered bound");
        AIFC_CHECK_EQ(exact_stream.buffered(), std::size_t{0});
      }
    }
  }
  // A frame whose declared payload exceeds the stream bound is refused when it is
  // decoded, which is a different path from the buffered bound above.
  {
    FrameStream small(8U);
    const Status appended = small.append(image.data(), header_bytes + 8U);
    AIFC_CHECK_MSG(appended.ok(), "a header plus 8 payload bytes must be buffered: "
                                      << aifc::render_status(appended));
    Frame frame;
    auto next = small.next(frame);
    AIFC_CHECK_MSG(!next.ok(),
                   "a frame declaring 16 payload bytes against a stream bound of 8 must be "
                   "refused, not buffered forever");
    if (!next.ok()) {
      AIFC_CHECK_MSG(next.status().code == ErrorCode::CAPACITY_EXCEEDED,
                     "an over-bound declared payload must be CAPACITY_EXCEEDED but was "
                         << aifc::render_status(next.status()));
    }
    expect_frame_untouched(frame, "over-bound declared payload");
  }
  // clear() returns the stream to its empty state.
  {
    stream.clear();
    AIFC_CHECK_EQ(stream.buffered(), std::size_t{0});
    const Status appended = stream.append(small_frame.data(), small_frame.size());
    AIFC_CHECK_MSG(appended.ok(), "a cleared stream must accept a fresh frame: "
                                      << aifc::render_status(appended));
    AIFC_CHECK_EQ(stream.buffered(), small_frame.size());
    Frame frame;
    auto next = stream.next(frame);
    AIFC_CHECK(next.ok());
    if (next) {
      AIFC_CHECK_MSG(next.value(), "the frame appended after clear() was not produced");
      if (next.value()) expect_same_payload(frame.payload, small_payload, "frame after clear()");
    }
  }
}

AIFC_TEST("frame adversarial: seeded multi-byte corruption never invents a frame") {
  const std::uint64_t seed = 0x5EED0000000000C1ULL;
  const ByteBuffer payload = payload_of(24, 0x3CU);
  const ByteBuffer image =
      encode_or_fail(reference_header(), payload, kMaxPayload, "the reference frame");

  aifc::Rng rng(seed);
  const int kIterations = 2000;
  for (int iteration = 0; iteration < kIterations; ++iteration) {
    ByteBuffer corrupted = image;
    const std::uint64_t flips = 1U + rng.next_below(5U);
    std::string offsets;
    for (std::uint64_t flip = 0; flip < flips; ++flip) {
      const std::size_t offset = static_cast<std::size_t>(rng.next_below(corrupted.size()));
      const std::size_t bit = static_cast<std::size_t>(rng.next_below(8U));
      flip_bit(corrupted, offset, bit);
      if (!offsets.empty()) offsets += ",";
      offsets += std::to_string(offset) + ":" + std::to_string(bit);
    }
    const std::string context = aifc::format_seed(seed) + " iteration=" +
                                std::to_string(iteration) + " flips=" + offsets + " image=[" +
                                hex_dump(corrupted) + "]";
    const Decoded decoded = decode(corrupted, kMaxPayload);
    if (decoded.status.ok() && decoded.consumed == 0) {
      // The mutated header now declares more payload than the buffer holds, so the
      // reader is waiting for bytes that are not coming.  It must not have produced a
      // frame, and that is the whole assertion for this input.
      expect_frame_untouched(decoded.frame, context);
      continue;
    }
    if (!decoded.status) {
      if (decoded.consumed != 0) {
        AIFC_FAIL(context << ": a refused frame consumed " << decoded.consumed
                          << " bytes; a refused frame must consume nothing");
      }
      if (!code_is_documented_refusal(decoded.status.code)) {
        AIFC_FAIL(context << ": refused with an undocumented code "
                          << aifc::render_status(decoded.status));
      }
      expect_frame_untouched(decoded.frame, context);
      continue;
    }
    // Accepted: the frame must be internally consistent and must re-encode to exactly
    // the bytes that were read.  A decoder that invented or normalised a field would
    // fail here.
    if (!aifc::is_known_message_kind(static_cast<std::uint16_t>(decoded.frame.header.kind))) {
      AIFC_FAIL(context << ": accepted a frame with an undefined message kind");
      continue;
    }
    if (decoded.frame.header.version < aifc::kProtocolVersionMin ||
        decoded.frame.header.version > aifc::kProtocolVersion) {
      AIFC_FAIL(context << ": accepted a frame with version " << decoded.frame.header.version);
      continue;
    }
    if (decoded.frame.payload.size() != decoded.frame.header.payload_length) {
      AIFC_FAIL(context << ": accepted a frame whose payload is " << decoded.frame.payload.size()
                        << " bytes against a declared length of "
                        << decoded.frame.header.payload_length);
      continue;
    }
    if (decoded.consumed != aifc::kFrameHeaderBytes + decoded.frame.payload.size()) {
      AIFC_FAIL(context << ": accepted a frame but consumed " << decoded.consumed
                        << " bytes for a frame of "
                        << (aifc::kFrameHeaderBytes + decoded.frame.payload.size()) << " bytes");
      continue;
    }
    auto reencoded = aifc::encode_frame(decoded.frame.header, decoded.frame.payload, kMaxPayload);
    if (!reencoded) {
      AIFC_FAIL(context << ": an accepted frame could not be re-encoded: "
                        << aifc::render_status(reencoded.status()));
      continue;
    }
    if (reencoded.value() != corrupted) {
      AIFC_FAIL(context << ": an accepted frame does not re-encode to the bytes that were read;"
                           " re-encoded=["
                        << hex_dump(reencoded.value()) << "]");
    }
  }
}
