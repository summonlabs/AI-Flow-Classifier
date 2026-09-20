// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Unit proof surface: foundation layer.
//
// Capability labels used throughout this file:
//
//   REAL        the behaviour is exercised through the shipped implementation
//   SYNTHETIC   the inputs are invented here; no captured traffic, no fabric hardware and
//               no external service is involved anywhere in this suite
//   UNSUPPORTED a capability this build does not have; nothing below claims it
//
// Every failure message names the exact input that failed (the literal bytes, the seed, the
// error text), because "expected equal" without the values is not a diagnosis.

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "test_framework.hpp"

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/config.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"
#include "ai_flow_classifier/foundation/math.hpp"
#include "ai_flow_classifier/foundation/rng.hpp"

namespace {

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

[[nodiscard]] std::string hex_of(const std::uint8_t* data, std::size_t size) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(kDigits[(data[i] >> 4) & 0x0FU]);
    out.push_back(kDigits[data[i] & 0x0FU]);
  }
  return out;
}

template <std::size_t N>
[[nodiscard]] std::string hex_of(const std::array<std::uint8_t, N>& value) {
  return hex_of(value.data(), value.size());
}

[[nodiscard]] std::string status_text(const aifc::Status& status) {
  return std::string(aifc::to_string(status.code)) + " (" + status.message + ")";
}

[[nodiscard]] bool contains(const std::string& haystack, std::string_view needle) {
  return haystack.find(needle) != std::string::npos;
}

}  // namespace

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

AIFC_TEST("foundation/sha256: FIPS 180-4 published vectors (REAL)") {
  // The four published example messages from FIPS 180-4 / the NIST example set.  The two long
  // ones are exactly the 448 bit and 896 bit multi-block cases, so the padding path and the
  // multi-block compression path are both pinned by a published value rather than by a value
  // this test computed for itself.
  const std::string message_448 =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  const std::string message_896 =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqr"
      "lmnopqrsmnopqrstnopqrstu";

  AIFC_CHECK_EQ(hex_of(aifc::sha256(std::string_view{})),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  AIFC_CHECK_EQ(hex_of(aifc::sha256(std::string_view{"abc"})),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  AIFC_CHECK_EQ(hex_of(aifc::sha256(std::string_view{message_448})),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  AIFC_CHECK_EQ(hex_of(aifc::sha256(std::string_view{message_896})),
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

  // The streaming interface must agree with the one-shot interface for every chunk split of
  // the 896 bit message, including the splits that straddle the 64 byte block boundary.
  const auto expected = aifc::sha256(std::string_view{message_896});
  for (std::size_t split = 0; split <= message_896.size(); ++split) {
    aifc::Sha256 hasher;
    hasher.update(std::string_view{message_896}.substr(0, split));
    hasher.update(std::string_view{message_896}.substr(split));
    const auto streamed = hasher.finish();
    AIFC_CHECK_MSG(streamed == expected,
                   "streaming SHA-256 of the 896 bit message split at offset "
                       << split << " disagreed with the one-shot digest "
                       << hex_of(streamed) << " != " << hex_of(expected));
  }

  // A 1000000 byte message is the other published vector; building it here keeps the test
  // self-contained and exercises many blocks.
  const std::string million(1000000U, 'a');
  AIFC_CHECK_EQ(hex_of(aifc::sha256(std::string_view{million})),
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

AIFC_TEST("foundation/crc32: IEEE 802.3 vector and incremental update (REAL)") {
  AIFC_CHECK_EQ(aifc::crc32(reinterpret_cast<const std::uint8_t*>("123456789"), 9U),
                0xCBF43926U);
  AIFC_CHECK_EQ(aifc::crc32(nullptr, 0U), 0x00000000U);
  AIFC_CHECK_EQ(aifc::crc32(reinterpret_cast<const std::uint8_t*>("The quick brown fox jumps over the lazy dog"), 43U),
                0x414FA339U);

  // A CRC is a running value, so splitting the input must not change the answer.  A frame
  // reader depends on this: it feeds bytes as they arrive.
  const std::string text = "123456789";
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(text.data());
  const std::uint32_t one_shot = aifc::crc32(bytes, text.size());
  for (std::size_t split = 0; split <= text.size(); ++split) {
    aifc::Crc32 running;
    running.update(bytes, split);
    running.update(bytes + split, text.size() - split);
    AIFC_CHECK_MSG(running.value() == one_shot,
                   "incremental CRC-32 of \"123456789\" split at offset "
                       << split << " produced 0x" << std::hex << running.value() << std::dec
                       << " instead of 0x" << std::hex << one_shot << std::dec);
  }

  // The mixer is used for index bucketing only; the property that matters is that it is a
  // pure function of its input.
  AIFC_CHECK_EQ(aifc::mix64(0U), aifc::mix64(0U));
  AIFC_CHECK_NE(aifc::mix64(1U), aifc::mix64(2U));
  AIFC_CHECK_EQ(aifc::stable_hash_text("flow-key"), aifc::stable_hash_text("flow-key"));
  AIFC_CHECK_NE(aifc::stable_hash_text("flow-key"), aifc::stable_hash_text("flow-kez"));
}

// ---------------------------------------------------------------------------
// Checked arithmetic and confidence
// ---------------------------------------------------------------------------

AIFC_TEST("foundation/math: checked_add and checked_mul overflow (REAL)") {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

  std::uint64_t out = 12345U;
  AIFC_CHECK_OK(aifc::checked_add_u64(kMax - 1U, 1U, out));
  AIFC_CHECK_EQ(out, kMax);

  out = 777U;
  AIFC_CHECK_ERR(aifc::checked_add_u64(kMax, 1U, out), aifc::ErrorCode::ARITHMETIC_OVERFLOW);
  AIFC_CHECK_EQ(out, 777U);  // the output is untouched on overflow

  out = 5U;
  AIFC_CHECK_OK(aifc::checked_add_u64(0U, 0U, out));
  AIFC_CHECK_EQ(out, 0U);

  out = 9U;
  AIFC_CHECK_OK(aifc::checked_mul_u64(0U, kMax, out));
  AIFC_CHECK_EQ(out, 0U);  // zero times anything is zero, not an overflow

  constexpr std::uint64_t kTwoPow31 = 1ULL << 31U;
  constexpr std::uint64_t kTwoPow32 = 1ULL << 32U;

  out = 11U;
  AIFC_CHECK_OK(aifc::checked_mul_u64(kTwoPow31, kTwoPow32, out));
  AIFC_CHECK_EQ(out, kTwoPow31 * kTwoPow32);

  out = 13U;
  AIFC_CHECK_ERR(aifc::checked_mul_u64(kMax, 2U, out), aifc::ErrorCode::ARITHMETIC_OVERFLOW);
  AIFC_CHECK_EQ(out, 13U);
  AIFC_CHECK_ERR(aifc::checked_mul_u64(kTwoPow32, kTwoPow32, out),
                 aifc::ErrorCode::ARITHMETIC_OVERFLOW);

  std::uint32_t small = 3U;
  AIFC_CHECK_OK(aifc::checked_add_u32(0xFFFFFFFEU, 1U, small));
  AIFC_CHECK_EQ(small, 0xFFFFFFFFU);
  small = 4U;
  AIFC_CHECK_ERR(aifc::checked_add_u32(0xFFFFFFFFU, 1U, small), aifc::ErrorCode::ARITHMETIC_OVERFLOW);
  AIFC_CHECK_EQ(small, 4U);
  small = 6U;
  AIFC_CHECK_OK(aifc::checked_mul_u32(65535U, 65535U, small));
  AIFC_CHECK_EQ(small, 4294836225U);
  AIFC_CHECK_ERR(aifc::checked_mul_u32(65536U, 65536U, small), aifc::ErrorCode::ARITHMETIC_OVERFLOW);

  const auto narrowed = aifc::narrow_u32(4294967295ULL, "generation");
  AIFC_CHECK_OK(narrowed);
  AIFC_CHECK_EQ(narrowed.value(), 4294967295U);
  const auto too_wide = aifc::narrow_u32(4294967296ULL, "generation");
  AIFC_CHECK_ERR(too_wide, aifc::ErrorCode::OUT_OF_RANGE);
  AIFC_CHECK_MSG(contains(too_wide.status().message, "generation"),
                 "narrow_u32 message must name the value being narrowed, got: "
                     << too_wide.status().message);
}

AIFC_TEST("foundation/math: Confidence rendering, parsing and exactness (REAL)") {
  // Canonical rendering: always four fractional digits, never binary floating point.
  AIFC_CHECK_EQ(aifc::Confidence::none().to_decimal(), std::string("0.0000"));
  AIFC_CHECK_EQ(aifc::Confidence::full().to_decimal(), std::string("1.0000"));
  AIFC_CHECK_EQ(aifc::Confidence::from_basis_points(1U).to_decimal(), std::string("0.0001"));
  AIFC_CHECK_EQ(aifc::Confidence::from_basis_points(9000U).to_decimal(), std::string("0.9000"));
  AIFC_CHECK_EQ(aifc::Confidence::from_basis_points(1234U).to_decimal(), std::string("0.1234"));
  AIFC_CHECK_EQ(aifc::Confidence::from_percent(100U).to_decimal(), std::string("1.0000"));
  // A basis point count above the scale saturates at full confidence.
  AIFC_CHECK_EQ(aifc::Confidence::from_basis_points(99999U).to_decimal(), std::string("1.0000"));
  AIFC_CHECK_EQ(aifc::Confidence::from_percent(200U).to_decimal(), std::string("1.0000"));

  // Exact parsing of every representable shape.
  const std::uint32_t round_trip[] = {0U,    1U,    9U,    10U,   99U,   100U,
                                      900U,  1000U, 4000U, 5000U, 9000U, 9999U, 10000U};
  for (const std::uint32_t basis_points : round_trip) {
    const std::string rendered = aifc::Confidence::from_basis_points(basis_points).to_decimal();
    const auto parsed = aifc::parse_confidence(rendered);
    AIFC_CHECK_MSG(parsed.ok(), "parse_confidence(\"" << rendered
                                                      << "\") failed: " << status_text(parsed.status()));
    if (parsed.ok()) {
      AIFC_CHECK_MSG(parsed.value().basis_points() == basis_points,
                     "parse_confidence(\"" << rendered << "\") produced "
                                           << parsed.value().basis_points() << " basis points instead of "
                                           << basis_points);
    }
  }

  const auto shorthand = aifc::parse_confidence("0.9");
  AIFC_CHECK_OK(shorthand);
  AIFC_CHECK_EQ(shorthand.value().basis_points(), 9000U);
  const auto integer = aifc::parse_confidence("1");
  AIFC_CHECK_OK(integer);
  AIFC_CHECK_EQ(integer.value().basis_points(), 10000U);
  // Trailing zeros beyond four fractional digits do not change the value, so they are exact
  // rather than "more precision than the representation holds".
  const auto padded = aifc::parse_confidence("0.900000");
  AIFC_CHECK_OK(padded);
  AIFC_CHECK_EQ(padded.value().basis_points(), 9000U);

  // Refusals.  A value that is not exactly representable is refused rather than rounded,
  // because two different inputs that render identically would make a decision unreproducible.
  const auto too_precise = aifc::parse_confidence("0.90001");
  AIFC_CHECK_ERR(too_precise, aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_MSG(contains(too_precise.status().message, "0.90001") ||
                     contains(too_precise.status().message, "fractional"),
                 "refusing \"0.90001\" must say why, got: " << too_precise.status().message);

  const auto above_one = aifc::parse_confidence("1.5");
  AIFC_CHECK_ERR(above_one, aifc::ErrorCode::OUT_OF_RANGE);
  AIFC_CHECK_MSG(contains(above_one.status().message, "1.0"),
                 "refusing \"1.5\" must name the bound, got: " << above_one.status().message);

  AIFC_CHECK_ERR(aifc::parse_confidence("abc"), aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_confidence(""), aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_confidence("2"), aifc::ErrorCode::OUT_OF_RANGE);
  AIFC_CHECK_ERR(aifc::parse_confidence("1.0001"), aifc::ErrorCode::OUT_OF_RANGE);
  AIFC_CHECK_ERR(aifc::parse_confidence("0.00001"), aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_confidence("0.9000abc"), aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_confidence(".5"), aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_confidence("-0.5"), aifc::ErrorCode::MALFORMED_INPUT);

  // Saturating selection and the explicit penalty.
  AIFC_CHECK_EQ(aifc::Confidence::weaker(aifc::Confidence::from_basis_points(4000U),
                                         aifc::Confidence::from_basis_points(9000U))
                    .basis_points(),
                4000U);
  AIFC_CHECK_EQ(aifc::Confidence::stronger(aifc::Confidence::from_basis_points(4000U),
                                           aifc::Confidence::from_basis_points(9000U))
                    .basis_points(),
                9000U);
  AIFC_CHECK_EQ(aifc::Confidence::from_basis_points(1500U).reduced_by(2000U).basis_points(), 0U);
  AIFC_CHECK_EQ(aifc::Confidence::from_basis_points(9000U).reduced_by(2000U).basis_points(), 7000U);
}

AIFC_TEST("foundation/bytes: BufferWriter and BufferReader round trip (REAL)") {
  aifc::BufferWriter writer(128U);
  AIFC_CHECK_OK(writer.put_u8(0x7FU));
  AIFC_CHECK_OK(writer.put_bool(true));
  AIFC_CHECK_OK(writer.put_bool(false));
  AIFC_CHECK_OK(writer.put_u16(0xBEEFU));
  AIFC_CHECK_OK(writer.put_u32(0xDEADBEEFU));
  AIFC_CHECK_OK(writer.put_u64(0x0123456789ABCDEFULL));
  AIFC_CHECK_OK(writer.put_i64(-2));
  AIFC_CHECK_OK(writer.put_string("canonical"));
  AIFC_CHECK_OK(writer.put_bytes(aifc::ByteBuffer{1U, 2U, 3U}));
  // u8 + bool + bool + u16 + u32 + u64 + i64 + ("canonical" with its 4 byte prefix) +
  // ({1,2,3} with its 4 byte prefix) = 1 + 1 + 1 + 2 + 4 + 8 + 8 + 13 + 7 = 45.
  AIFC_CHECK_EQ(writer.size(), std::size_t{45});

  const aifc::ByteBuffer encoded = writer.take();
  // Fixed width little endian with no padding: the u32 field starts at offset 5 and its four
  // bytes carry the value least significant byte first.
  // 0xDEADBEEF is stored least significant byte first: EF BE AD DE.
  AIFC_CHECK_EQ(encoded[5], static_cast<std::uint8_t>(0xEFU));
  AIFC_CHECK_EQ(encoded[6], static_cast<std::uint8_t>(0xBEU));
  AIFC_CHECK_EQ(encoded[7], static_cast<std::uint8_t>(0xADU));
  AIFC_CHECK_EQ(encoded[8], static_cast<std::uint8_t>(0xDEU));

  aifc::BufferReader reader(encoded, aifc::kMaxStringBytes);
  const auto u8 = reader.get_u8();
  AIFC_CHECK_OK(u8);
  AIFC_CHECK_EQ(u8.value(), static_cast<std::uint8_t>(0x7FU));
  const auto yes = reader.get_bool();
  AIFC_CHECK_OK(yes);
  AIFC_CHECK_EQ(yes.value(), true);
  const auto no = reader.get_bool();
  AIFC_CHECK_OK(no);
  AIFC_CHECK_EQ(no.value(), false);
  const auto u16 = reader.get_u16();
  AIFC_CHECK_OK(u16);
  AIFC_CHECK_EQ(u16.value(), static_cast<std::uint16_t>(0xBEEFU));
  const auto u32 = reader.get_u32();
  AIFC_CHECK_OK(u32);
  AIFC_CHECK_EQ(u32.value(), 0xDEADBEEFU);
  const auto u64 = reader.get_u64();
  AIFC_CHECK_OK(u64);
  AIFC_CHECK_EQ(u64.value(), 0x0123456789ABCDEFULL);
  const auto i64 = reader.get_i64();
  AIFC_CHECK_OK(i64);
  AIFC_CHECK_EQ(i64.value(), static_cast<std::int64_t>(-2));
  const auto text = reader.get_string();
  AIFC_CHECK_OK(text);
  AIFC_CHECK_EQ(text.value(), std::string("canonical"));
  const auto blob = reader.get_blob(16U);
  AIFC_CHECK_OK(blob);
  AIFC_CHECK_EQ(blob.value().size(), std::size_t{3});
  AIFC_CHECK_OK(reader.finish());
  AIFC_CHECK(reader.exhausted());

  // Trailing garbage is reported, not ignored.  The record here is one byte long with one
  // extra byte after it, so the exact count in the message is checkable.
  aifc::BufferWriter short_writer(8U);
  AIFC_CHECK_OK(short_writer.put_u8(0x7FU));
  aifc::ByteBuffer padded = short_writer.take();
  padded.push_back(0xABU);

  aifc::BufferReader trailing(padded, aifc::kMaxStringBytes);
  AIFC_CHECK_OK(trailing.get_u8());
  const aifc::Status trailing_status = trailing.finish();
  AIFC_CHECK_ERR(trailing_status, aifc::ErrorCode::TRAILING_GARBAGE);
  AIFC_CHECK_MSG(contains(trailing_status.message, "1 trailing bytes"),
                 "TRAILING_GARBAGE must report how many bytes remain, got: "
                     << trailing_status.message);

  // ... but a bounded, explicitly permitted trailer is accepted and consumed.
  aifc::BufferReader trailer_reader(padded, aifc::kMaxStringBytes);
  AIFC_CHECK_OK(trailer_reader.get_u8());
  AIFC_CHECK_OK(trailer_reader.finish_with_trailer(1U));
  AIFC_CHECK(trailer_reader.exhausted());

  aifc::BufferReader strict_reader(padded, aifc::kMaxStringBytes);
  AIFC_CHECK_OK(strict_reader.get_u8());
  AIFC_CHECK_ERR(strict_reader.finish_with_trailer(0U), aifc::ErrorCode::TRAILING_GARBAGE);

  // The same rule at the full record size: the count reports every byte that is left.
  aifc::ByteBuffer long_padded = encoded;
  long_padded.push_back(0x00U);
  aifc::BufferReader long_reader(long_padded, aifc::kMaxStringBytes);
  AIFC_CHECK_OK(long_reader.get_u8());
  const aifc::Status long_status = long_reader.finish();
  AIFC_CHECK_ERR(long_status, aifc::ErrorCode::TRAILING_GARBAGE);
  AIFC_CHECK_MSG(contains(long_status.message, "45 trailing bytes"),
                 "the count must cover the whole unconsumed remainder, got: "
                     << long_status.message);
}

AIFC_TEST("foundation/bytes: truncation and the encoder bound (REAL)") {
  aifc::BufferWriter writer(200U);
  AIFC_CHECK_OK(writer.put_u64(1U));
  AIFC_CHECK_OK(writer.put_string("truncated"));
  const aifc::ByteBuffer encoded = writer.take();

  // Every read past the end is MALFORMED_RECORD and leaves the offset where it was, so a
  // caller cannot advance past the truncation and read a following field from the wrong place.
  for (std::size_t length = 0; length < 8U; ++length) {
    aifc::BufferReader short_reader(encoded.data(), length, aifc::kMaxStringBytes);
    const auto value = short_reader.get_u64();
    AIFC_CHECK_MSG(!value.ok(), "get_u64 from " << length << " bytes must fail");
    if (!value.ok()) {
      AIFC_CHECK_MSG(value.code() == aifc::ErrorCode::MALFORMED_RECORD,
                     "get_u64 from " << length << " bytes produced "
                                     << std::string(aifc::to_string(value.code())) << " ("
                                     << value.status().message << ") instead of MALFORMED_RECORD");
    }
    AIFC_CHECK_EQ(short_reader.offset(), std::size_t{0});
  }

  // The record is u64 + (4 byte prefix + 9 byte string) = 21 bytes.  Cutting it at 14 bytes
  // leaves the declared string length readable and the string itself short by seven bytes.
  AIFC_CHECK_EQ(encoded.size(), std::size_t{21});
  const aifc::ByteBuffer cut(encoded.begin(), encoded.begin() + 14);
  aifc::BufferReader bytes_reader(cut, aifc::kMaxStringBytes);
  AIFC_CHECK_OK(bytes_reader.get_u64());
  const auto truncated_string = bytes_reader.get_string();
  AIFC_CHECK_ERR(truncated_string, aifc::ErrorCode::MALFORMED_RECORD);
  if (!truncated_string) {
    AIFC_CHECK_MSG(contains(truncated_string.status().message, "9") &&
                       contains(truncated_string.status().message, "2"),
                   "the truncation must name the declared length and the bytes present, got: "
                       << truncated_string.status().message);
  }

  // A boolean field that is not 0 or 1 is refused rather than coerced.
  const aifc::ByteBuffer not_a_bool{2U};
  aifc::BufferReader bool_reader(not_a_bool, aifc::kMaxStringBytes);
  const auto flag = bool_reader.get_bool();
  AIFC_CHECK_ERR(flag, aifc::ErrorCode::MALFORMED_RECORD);

  // The writer refuses to exceed the bound it was constructed with and does not partially
  // write the field that did not fit.
  aifc::BufferWriter bounded(4U);
  AIFC_CHECK_OK(bounded.put_u32(0xAABBCCDDU));
  AIFC_CHECK_EQ(bounded.size(), std::size_t{4});
  AIFC_CHECK_ERR(bounded.put_u8(1U), aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_ERR(bounded.put_string("x"), aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_EQ(bounded.size(), std::size_t{4});

  const aifc::Status none_written = aifc::BufferWriter(0U).put_u8(1U);
  AIFC_CHECK_ERR(none_written, aifc::ErrorCode::CAPACITY_EXCEEDED);
}

AIFC_TEST("foundation/bytes: a declared length is checked before allocation (REAL)") {
  // A four byte length prefix that claims 4 GiB with nothing behind it.  The reader must
  // refuse on the declared length (CAPACITY_EXCEEDED) or on the bytes actually present
  // (MALFORMED_RECORD) -- never by attempting to reserve the declared amount.
  const aifc::ByteBuffer hostile{0xFFU, 0xFFU, 0xFFU, 0xFFU};

  aifc::BufferReader limited(hostile, aifc::kMaxStringBytes);
  const auto over_limit = limited.get_blob(1024U);
  AIFC_CHECK_ERR(over_limit, aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_MSG(contains(over_limit.status().message, "4294967295") &&
                     contains(over_limit.status().message, "1024"),
                 "the refusal must name the declared length and the limit, got: "
                     << over_limit.status().message);
  AIFC_CHECK_EQ(limited.offset(), std::size_t{4});

  aifc::BufferReader unlimited(hostile, aifc::kMaxStringBytes);
  const auto beyond_end = unlimited.get_blob(0xFFFFFFFFU);
  AIFC_CHECK_ERR(beyond_end, aifc::ErrorCode::MALFORMED_RECORD);
  AIFC_CHECK_MSG(contains(beyond_end.status().message, "4294967295"),
                 "the refusal must name the missing byte count, got: "
                     << beyond_end.status().message);
  AIFC_CHECK_EQ(unlimited.offset(), std::size_t{4});
  AIFC_CHECK_EQ(unlimited.remaining(), std::size_t{0});

  // The same rule for a collection count: it is bounded before the caller reserves.
  aifc::BufferReader counts(hostile, aifc::kMaxStringBytes);
  const auto count = counts.get_count(4096U);
  AIFC_CHECK_ERR(count, aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_MSG(contains(count.status().message, "4294967295"),
                 "the count refusal must name the declared count, got: " << count.status().message);

  // A declared length that fits the limit but not the buffer is a truncation, and the prefix
  // is the only thing consumed.
  const aifc::ByteBuffer short_blob{0x05U, 0x00U, 0x00U, 0x00U, 'a', 'b'};
  aifc::BufferReader short_reader(short_blob, aifc::kMaxStringBytes);
  const auto truncated = short_reader.get_blob(64U);
  AIFC_CHECK_ERR(truncated, aifc::ErrorCode::MALFORMED_RECORD);
  AIFC_CHECK_EQ(short_reader.offset(), std::size_t{4});
  AIFC_CHECK_EQ(short_reader.remaining(), std::size_t{2});

  // A zero length blob is legal and consumes only its prefix.
  const aifc::ByteBuffer empty_blob{0x00U, 0x00U, 0x00U, 0x00U};
  aifc::BufferReader empty_reader(empty_blob, aifc::kMaxStringBytes);
  const auto empty = empty_reader.get_blob(64U);
  AIFC_CHECK_OK(empty);
  AIFC_CHECK_EQ(empty.value().size(), std::size_t{0});
  AIFC_CHECK_OK(empty_reader.finish());

  // Constant time comparison is still a comparison.
  const std::uint8_t left[4] = {1U, 2U, 3U, 4U};
  const std::uint8_t same[4] = {1U, 2U, 3U, 4U};
  const std::uint8_t different[4] = {1U, 2U, 3U, 5U};
  AIFC_CHECK(aifc::constant_time_equal(left, same, 4U));
  AIFC_CHECK(!aifc::constant_time_equal(left, different, 4U));
  AIFC_CHECK(aifc::constant_time_equal(left, different, 0U));
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

AIFC_TEST("foundation/ids: canonicalize_identity accept and reject sets (REAL)") {
  struct Accepted {
    std::string_view input;
    std::string_view canonical;
  };
  const Accepted accepted[] = {
      {"publisher-1", "publisher-1"},
      {"Publisher-1", "publisher-1"},
      {"PUBLISHER.1", "publisher.1"},
      {"a", "a"},
      {"0", "0"},
      {"workload.rank:7_collective-x", "workload.rank:7_collective-x"},
      {"WeIrD-CaSe.9:0_1", "weird-case.9:0_1"},
  };
  for (const Accepted& entry : accepted) {
    const auto canonical = aifc::canonicalize_identity(entry.input);
    AIFC_CHECK_MSG(canonical.ok(), "canonicalize_identity(\""
                                       << entry.input << "\") failed: "
                                       << status_text(canonical.status()));
    if (canonical.ok()) {
      AIFC_CHECK_MSG(canonical.value() == entry.canonical,
                     "canonicalize_identity(\"" << entry.input << "\") produced \""
                                                << canonical.value() << "\" instead of \""
                                                << entry.canonical << "\"");
    }
    if (canonical.ok()) {
      AIFC_CHECK(aifc::is_canonical_identity(canonical.value()));
    }
  }

  const std::string exactly_max(aifc::kMaxIdentityBytes, 'a');
  AIFC_CHECK(aifc::canonicalize_identity(exactly_max).ok());
  const std::string one_over(aifc::kMaxIdentityBytes + 1U, 'a');
  const auto too_long = aifc::canonicalize_identity(one_over);
  AIFC_CHECK_ERR(too_long, aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_MSG(contains(too_long.status().message, "128"),
                 "the oversize refusal must name the bound, got: " << too_long.status().message);

  const std::string_view rejected[] = {
      std::string_view{},          "has space",   "at@sign",     "slash/inside",
      "back\\slash",               "new\nline",   "tab\tinside", "quote\"mark",
      "semi;colon",                "comma,here",  "plus+minus",  "equals=sign",
      "\xC3\xBCnicode",            "star*",       "percent%",    "dollar$",
  };
  for (const std::string_view input : rejected) {
    const auto canonical = aifc::canonicalize_identity(input);
    AIFC_CHECK_MSG(!canonical.ok(),
                   "canonicalize_identity must reject the " << input.size()
                                                            << " byte input \"" << input << "\"");
    if (!canonical.ok()) {
      AIFC_CHECK_MSG(canonical.code() == aifc::ErrorCode::MALFORMED_INPUT,
                     "canonicalize_identity(\"" << input << "\") produced "
                                                << std::string(aifc::to_string(canonical.code()))
                                                << " instead of MALFORMED_INPUT");
    }
    AIFC_CHECK(!aifc::is_canonical_identity(input));
  }

  AIFC_CHECK(!aifc::is_canonical_identity(""));
  AIFC_CHECK(!aifc::is_canonical_identity("Upper"));
  AIFC_CHECK(!aifc::is_canonical_identity(one_over));
  AIFC_CHECK(aifc::is_canonical_identity("lower-1.2_3:4"));
}

AIFC_TEST("foundation/ids: Id128 and Digest256 hex rendering round trip (REAL)") {
  aifc::Id128 id;
  id.hi = 0x0123456789ABCDEFULL;
  id.lo = 0xFEDCBA9876543210ULL;
  const std::string hex = id.to_hex();
  AIFC_CHECK_EQ(hex.size(), std::size_t{32});
  AIFC_CHECK_EQ(hex, std::string("0123456789abcdeffedcba9876543210"));

  // The rendering is fixed width, lower case and byte-order stable, so it is a usable key.
  AIFC_CHECK_EQ(aifc::Id128::zero().to_hex(),
                std::string("00000000000000000000000000000000"));
  const aifc::Id128 low_word{0U, 1U};
  const aifc::Id128 high_word{1U, 0U};
  AIFC_CHECK_EQ(low_word.to_hex(), std::string("00000000000000000000000000000001"));
  AIFC_CHECK_EQ(high_word.to_hex(), std::string("00000000000000010000000000000000"));

  // Distinct identities must render distinctly: the hex form is the human-facing identity.
  std::vector<std::string> seen;
  for (std::uint64_t value = 0; value < 64U; ++value) {
    const aifc::Id128 candidate{value, value * 0x9E3779B97F4A7C15ULL};
    const std::string rendered = candidate.to_hex();
    for (const std::string& other : seen) {
      AIFC_CHECK_MSG(other != rendered,
                     "two distinct Id128 values rendered identically as " << rendered
                                                                          << " (value=" << value << ")");
    }
    seen.push_back(rendered);
  }

  aifc::Digest256 digest;
  for (std::size_t i = 0; i < aifc::Digest256::kBytes; ++i) {
    digest.bytes[i] = static_cast<std::uint8_t>(i);
  }
  const std::string digest_hex = digest.to_hex();
  AIFC_CHECK_EQ(digest_hex.size(), std::size_t{64});
  AIFC_CHECK_EQ(digest_hex,
                std::string("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
  AIFC_CHECK_EQ(aifc::Digest256::zero().to_hex(), std::string(64U, '0'));
  AIFC_CHECK(aifc::Digest256::zero().is_zero());
  AIFC_CHECK(!digest.is_zero());
  AIFC_CHECK_NE(hex_of(aifc::sha256(std::string_view{"a"})),
                hex_of(aifc::sha256(std::string_view{"b"})));
}

// ---------------------------------------------------------------------------
// Randomness, counters, time and limits
// ---------------------------------------------------------------------------

AIFC_TEST("foundation/rng: determinism, bounds and identity generation (REAL)") {
  constexpr std::uint64_t kSeed = 0x5EED1234ABCDEF01ULL;
  aifc::Rng first(kSeed);
  aifc::Rng second(kSeed);
  AIFC_CHECK_EQ(first.state(), second.state());
  for (int draw = 0; draw < 64; ++draw) {
    const std::uint64_t left = first.next_u64();
    const std::uint64_t right = second.next_u64();
    AIFC_CHECK_MSG(left == right,
                   "rng " << aifc::format_seed(kSeed) << " draw " << draw << " produced 0x"
                          << std::hex << left << " and 0x" << right << std::dec
                          << " for two generators with the same seed");
  }

  // A different seed must produce a different stream; the first few draws are compared so a
  // generator that ignores its seed is caught immediately.
  aifc::Rng other(kSeed + 1U);
  aifc::Rng reference(kSeed);
  int differences = 0;
  for (int draw = 0; draw < 8; ++draw) {
    if (other.next_u64() != reference.next_u64()) ++differences;
  }
  AIFC_CHECK_MSG(differences > 0, "seed " << aifc::format_seed(kSeed)
                                          << " and seed " << aifc::format_seed(kSeed + 1U)
                                          << " produced identical streams");

  // Seed zero is documented to mean "the default constant", so it must equal the default
  // constructed generator rather than producing the all-zero state.
  aifc::Rng zero_seed(0U);
  aifc::Rng default_seed;
  AIFC_CHECK_EQ(zero_seed.next_u64(), default_seed.next_u64());

  // Bounds.
  aifc::Rng bounded(kSeed);
  AIFC_CHECK_EQ(bounded.next_below(0U), 0U);
  for (int draw = 0; draw < 32; ++draw) {
    AIFC_CHECK_MSG(bounded.next_below(1U) == 0U, "next_below(1) must always produce 0");
  }
  const std::uint64_t bounds[] = {2U, 3U, 7U, 1000U, 65536U, 1ULL << 40U,
                                  std::numeric_limits<std::uint64_t>::max()};
  for (const std::uint64_t bound : bounds) {
    for (int draw = 0; draw < 64; ++draw) {
      const std::uint64_t value = bounded.next_below(bound);
      AIFC_CHECK_MSG(value < bound,
                     "next_below(" << bound << ") draw " << draw << " produced " << value);
    }
  }
  // Every residue must be reachable for a small bound, so the generator is not stuck on one.
  bool residue_seen[8] = {};
  for (int draw = 0; draw < 256; ++draw) {
    residue_seen[bounded.next_below(8U)] = true;
  }
  for (std::size_t residue = 0; residue < 8U; ++residue) {
    AIFC_CHECK_MSG(residue_seen[residue],
                   "next_below(8) never produced the residue " << residue);
  }

  // Identities are never the zero sentinel.
  aifc::Rng identities(kSeed);
  for (int draw = 0; draw < 256; ++draw) {
    const aifc::Id128 id = identities.next_id128();
    AIFC_CHECK_MSG(!id.is_zero(), "next_id128 draw " << draw << " produced the zero identity");
  }

  AIFC_CHECK_EQ(aifc::seed_from_text("precedence"), aifc::seed_from_text("precedence"));
  AIFC_CHECK_NE(aifc::seed_from_text("precedence"), aifc::seed_from_text("contradiction"));
  AIFC_CHECK_EQ(aifc::format_seed(0x0123456789ABCDEFULL), std::string("seed=0x0123456789abcdef"));
  AIFC_CHECK_EQ(aifc::format_seed(0U), std::string("seed=0x0000000000000000"));
}

AIFC_TEST("foundation/math: Counter exhaustion and monotonicity (REAL)") {
  aifc::Counter counter;
  AIFC_CHECK_EQ(counter.value(), 0U);
  std::uint64_t out = 0;
  AIFC_CHECK_OK(counter.next(out));
  AIFC_CHECK_EQ(out, 1U);
  AIFC_CHECK_OK(counter.next(out));
  AIFC_CHECK_EQ(out, 2U);
  AIFC_CHECK_EQ(counter.value(), 2U);

  // observe() only ever raises.
  counter.observe(1U);
  AIFC_CHECK_EQ(counter.value(), 2U);
  counter.observe(9U);
  AIFC_CHECK_EQ(counter.value(), 9U);
  AIFC_CHECK_OK(counter.next(out));
  AIFC_CHECK_EQ(out, 10U);

  // An exhausted counter refuses rather than wrapping, and does not modify its value.
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  aifc::Counter exhausted(kMax);
  AIFC_CHECK(exhausted.is_exhausted());
  std::uint64_t untouched = 4242U;
  AIFC_CHECK_ERR(exhausted.next(untouched), aifc::ErrorCode::COUNTER_EXHAUSTED);
  AIFC_CHECK_EQ(exhausted.value(), kMax);
  AIFC_CHECK_EQ(untouched, 4242U);

  aifc::Counter almost(kMax - 1U);
  AIFC_CHECK(!almost.is_exhausted());
  AIFC_CHECK_OK(almost.next(out));
  AIFC_CHECK_EQ(out, kMax);
  AIFC_CHECK(almost.is_exhausted());
  AIFC_CHECK_ERR(almost.next(out), aifc::ErrorCode::COUNTER_EXHAUSTED);
}

AIFC_TEST("foundation/clock: format_unix_millis_utc and tick sources (REAL)") {
  // Rendering is UTC, second resolution, ISO 8601 with a trailing Z.
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(0U), std::string("1970-01-01T00:00:00Z"));
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(1U), std::string("1970-01-01T00:00:00Z"));
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(999U), std::string("1970-01-01T00:00:00Z"));
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(1000U), std::string("1970-01-01T00:00:01Z"));
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(951782400000ULL), std::string("2000-02-29T00:00:00Z"));
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(946684800000ULL), std::string("2000-01-01T00:00:00Z"));
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(1234567890123ULL), std::string("2009-02-13T23:31:30Z"));
  AIFC_CHECK_EQ(aifc::format_unix_millis_utc(1609459200000ULL), std::string("2021-01-01T00:00:00Z"));

  // Every rendering has the same shape, so a log line is machine readable.
  for (std::uint64_t millis = 0U; millis < 4000U; millis += 997U) {
    const std::string rendered = aifc::format_unix_millis_utc(millis);
    AIFC_CHECK_MSG(rendered.size() == 20U && rendered[4] == '-' && rendered[7] == '-' &&
                       rendered[10] == 'T' && rendered[13] == ':' && rendered[16] == ':' &&
                       rendered[19] == 'Z',
                   "format_unix_millis_utc(" << millis << ") produced \"" << rendered
                                             << "\" which is not the canonical 20 character form");
  }

  // The manual source is the deterministic clock the rest of the suite uses.
  aifc::ManualTickSource manual(1U);
  AIFC_CHECK_EQ(manual.now(), 1U);
  AIFC_CHECK_EQ(manual.advance(41U), 42U);
  AIFC_CHECK_EQ(manual.now(), 42U);
  AIFC_CHECK_EQ(manual.set(7U), 7U);
  AIFC_CHECK_EQ(manual.now(), 7U);

  // The steady source is monotonic and starts at its origin.  This is REAL but it is a
  // property check rather than a value check, because the value is wall-clock derived.
  aifc::SteadyTickSource steady;
  const aifc::Tick start = steady.now();
  const aifc::Tick later = steady.now();
  AIFC_CHECK_MSG(later >= start,
                 "SteadyTickSource went backwards: " << start << " then " << later);
  AIFC_CHECK_EQ(aifc::tick_none(), 0U);
}

AIFC_TEST("foundation/config: ResourceLimits::effective clamping (REAL)") {
  // The defaults are already effective, and effective() is idempotent.
  const aifc::ResourceLimits defaults;
  const aifc::ResourceLimits clamped_defaults = defaults.effective();
  AIFC_CHECK_EQ(clamped_defaults.max_frame_payload, defaults.max_frame_payload);
  AIFC_CHECK_EQ(clamped_defaults.max_string_bytes, defaults.max_string_bytes);
  AIFC_CHECK_EQ(clamped_defaults.max_blob_bytes, defaults.max_blob_bytes);
  AIFC_CHECK_EQ(clamped_defaults.max_collection_count, defaults.max_collection_count);
  AIFC_CHECK_EQ(clamped_defaults.max_batch_keys, defaults.max_batch_keys);
  AIFC_CHECK_EQ(clamped_defaults.max_flows, defaults.max_flows);
  AIFC_CHECK_EQ(clamped_defaults.max_workers, defaults.max_workers);
  AIFC_CHECK_EQ(clamped_defaults.default_freshness_window, defaults.default_freshness_window);
  AIFC_CHECK_EQ(clamped_defaults.max_session_idle_ticks, defaults.max_session_idle_ticks);
  AIFC_CHECK_EQ(clamped_defaults.effective().max_flows, defaults.max_flows);
  AIFC_CHECK(aifc::limits_are_structurally_valid(defaults));

  // Per-input bounds: zero means the smallest legal value, an oversized value is reduced to
  // the hard structural bound, and a value already inside the range is untouched.
  aifc::ResourceLimits limits;
  limits.max_frame_payload = 0U;
  limits.max_string_bytes = 0U;
  limits.max_blob_bytes = 0U;
  limits.max_collection_count = 0U;
  limits.max_batch_keys = 0U;
  const aifc::ResourceLimits zeroed = limits.effective();
  AIFC_CHECK_EQ(zeroed.max_frame_payload, 64U);
  AIFC_CHECK_EQ(zeroed.max_string_bytes, 1U);
  AIFC_CHECK_EQ(zeroed.max_blob_bytes, 1U);
  AIFC_CHECK_EQ(zeroed.max_collection_count, 1U);
  AIFC_CHECK_EQ(zeroed.max_batch_keys, 1U);

  aifc::ResourceLimits oversized;
  oversized.max_frame_payload = 0xFFFFFFFFU;
  oversized.max_string_bytes = 0xFFFFFFFFU;
  oversized.max_blob_bytes = 0xFFFFFFFFU;
  oversized.max_collection_count = 0xFFFFFFFFU;
  oversized.max_batch_keys = 0xFFFFFFFFU;
  oversized.max_flows = 0xFFFFFFFFU;
  oversized.max_publishers = 0xFFFFFFFFU;
  oversized.max_workloads = 0xFFFFFFFFU;
  oversized.max_contracts = 0xFFFFFFFFU;
  oversized.max_pending_contracts = 0xFFFFFFFFU;
  oversized.max_sessions = 0xFFFFFFFFU;
  oversized.max_config_overrides = 0xFFFFFFFFU;
  oversized.max_evidence_per_flow = 0xFFFFFFFFU;
  oversized.max_evidence_records = 0xFFFFFFFFU;
  oversized.max_decisions_per_flow = 0xFFFFFFFFU;
  oversized.max_contradictions_per_flow = 0xFFFFFFFFU;
  oversized.max_contradictions = 0xFFFFFFFFU;
  oversized.max_supersessions = 0xFFFFFFFFU;
  oversized.max_revocations = 0xFFFFFFFFU;
  oversized.max_flow_key_index = 0xFFFFFFFFU;
  oversized.max_workers = 0xFFFFFFFFU;
  oversized.max_queue_depth = 0xFFFFFFFFU;
  oversized.max_inflight_requests = 0xFFFFFFFFU;
  oversized.max_retry_attempts = 0xFFFFFFFFU;
  const aifc::ResourceLimits bounded = oversized.effective();
  AIFC_CHECK_EQ(bounded.max_frame_payload, aifc::kMaxFramePayload);
  AIFC_CHECK_EQ(bounded.max_string_bytes, aifc::kMaxStringBytes);
  AIFC_CHECK_EQ(bounded.max_blob_bytes, aifc::kMaxBlobBytes);
  AIFC_CHECK_EQ(bounded.max_collection_count, aifc::kMaxCollectionCount);
  AIFC_CHECK_EQ(bounded.max_batch_keys, aifc::kMaxBatchKeys);
  AIFC_CHECK_EQ(bounded.max_flows, 1U << 22U);
  AIFC_CHECK_EQ(bounded.max_publishers, 1U << 20U);
  AIFC_CHECK_EQ(bounded.max_workloads, 1U << 20U);
  AIFC_CHECK_EQ(bounded.max_contracts, 1U << 20U);
  AIFC_CHECK_EQ(bounded.max_pending_contracts, 1U << 20U);
  AIFC_CHECK_EQ(bounded.max_sessions, 1U << 16U);
  AIFC_CHECK_EQ(bounded.max_config_overrides, 1U << 16U);
  AIFC_CHECK_EQ(bounded.max_evidence_per_flow, 4096U);
  AIFC_CHECK_EQ(bounded.max_evidence_records, 1U << 24U);
  AIFC_CHECK_EQ(bounded.max_decisions_per_flow, 1024U);
  AIFC_CHECK_EQ(bounded.max_contradictions_per_flow, 4096U);
  AIFC_CHECK_EQ(bounded.max_contradictions, 1U << 24U);
  AIFC_CHECK_EQ(bounded.max_supersessions, 1U << 24U);
  AIFC_CHECK_EQ(bounded.max_revocations, 1U << 24U);
  AIFC_CHECK_EQ(bounded.max_flow_key_index, 1U << 24U);
  AIFC_CHECK_EQ(bounded.max_workers, 256U);
  AIFC_CHECK_EQ(bounded.max_queue_depth, 1U << 20U);
  AIFC_CHECK_EQ(bounded.max_inflight_requests, 1U << 20U);
  AIFC_CHECK_EQ(bounded.max_retry_attempts, 64U);

  // Registry and history bounds honour zero as zero: a zero bound means "refuse every
  // insert", never "unbounded".
  aifc::ResourceLimits disabled;
  disabled.max_flows = 0U;
  disabled.max_publishers = 0U;
  disabled.max_workloads = 0U;
  disabled.max_contracts = 0U;
  disabled.max_pending_contracts = 0U;
  disabled.max_sessions = 0U;
  disabled.max_config_overrides = 0U;
  disabled.max_evidence_per_flow = 0U;
  disabled.max_evidence_records = 0U;
  disabled.max_decisions_per_flow = 0U;
  disabled.max_contradictions_per_flow = 0U;
  disabled.max_contradictions = 0U;
  disabled.max_supersessions = 0U;
  disabled.max_revocations = 0U;
  disabled.max_flow_key_index = 0U;
  disabled.max_workers = 0U;
  disabled.max_queue_depth = 0U;
  disabled.max_inflight_requests = 0U;
  disabled.max_retry_attempts = 0U;
  const aifc::ResourceLimits still_zero = disabled.effective();
  AIFC_CHECK_EQ(still_zero.max_flows, 0U);
  AIFC_CHECK_EQ(still_zero.max_publishers, 0U);
  AIFC_CHECK_EQ(still_zero.max_workloads, 0U);
  AIFC_CHECK_EQ(still_zero.max_contracts, 0U);
  AIFC_CHECK_EQ(still_zero.max_pending_contracts, 0U);
  AIFC_CHECK_EQ(still_zero.max_sessions, 0U);
  AIFC_CHECK_EQ(still_zero.max_config_overrides, 0U);
  AIFC_CHECK_EQ(still_zero.max_evidence_per_flow, 0U);
  AIFC_CHECK_EQ(still_zero.max_evidence_records, 0U);
  AIFC_CHECK_EQ(still_zero.max_decisions_per_flow, 0U);
  AIFC_CHECK_EQ(still_zero.max_contradictions_per_flow, 0U);
  AIFC_CHECK_EQ(still_zero.max_contradictions, 0U);
  AIFC_CHECK_EQ(still_zero.max_supersessions, 0U);
  AIFC_CHECK_EQ(still_zero.max_revocations, 0U);
  AIFC_CHECK_EQ(still_zero.max_flow_key_index, 0U);
  AIFC_CHECK_EQ(still_zero.max_workers, 0U);
  AIFC_CHECK_EQ(still_zero.max_queue_depth, 0U);
  AIFC_CHECK_EQ(still_zero.max_inflight_requests, 0U);
  AIFC_CHECK_EQ(still_zero.max_retry_attempts, 0U);

  // Zero freshness and zero idle do not mean "never expires": they are raised to one tick so
  // that a policy cannot accidentally declare evidence permanently fresh.
  aifc::ResourceLimits freshness;
  freshness.default_freshness_window = 0U;
  freshness.max_session_idle_ticks = 0U;
  const aifc::ResourceLimits raised = freshness.effective();
  AIFC_CHECK_EQ(raised.default_freshness_window, 1U);
  AIFC_CHECK_EQ(raised.max_session_idle_ticks, 1U);

  // A value already inside the range is returned unchanged.
  aifc::ResourceLimits inside;
  inside.max_flows = 7U;
  inside.max_frame_payload = 1024U;
  inside.max_string_bytes = 30U;
  inside.default_freshness_window = 99U;
  const aifc::ResourceLimits untouched = inside.effective();
  AIFC_CHECK_EQ(untouched.max_flows, 7U);
  AIFC_CHECK_EQ(untouched.max_frame_payload, 1024U);
  AIFC_CHECK_EQ(untouched.max_string_bytes, 30U);
  AIFC_CHECK_EQ(untouched.default_freshness_window, 99U);

  AIFC_CHECK_EQ(aifc::product_version_string(), std::string("1.0.0"));
  // The version range is a compile time constant, so it is asserted where it is used (the
  // coordinator version negotiation surface) rather than as a constant conditional here.
  AIFC_CHECK_MSG(contains(aifc::product_banner(), "AI Flow Classifier 1.0.0"),
                 "product_banner must name the product and version, got: "
                     << aifc::product_banner());
}
