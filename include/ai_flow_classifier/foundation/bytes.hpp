// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Byte buffer primitives used by every canonical codec.
//
// Decoding rules enforced by BufferReader:
//   * every read is bounds checked against the declared length;
//   * the declared length is checked against the remaining bytes before any work
//     is done, so a hostile length cannot cause a large allocation;
//   * integer reads are fixed width little endian with no padding;
//   * finish() reports TRAILING_GARBAGE unless the caller explicitly permits it.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_BYTES_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_BYTES_HPP

#include <ostream>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

// Little endian fixed width load/store helpers.  Deliberately byte-at-a-time so
// the canonical encoding is identical on every platform regardless of host
// endianness or alignment rules.
[[nodiscard]] inline std::uint16_t load_u16_le(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                    static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8));
}
[[nodiscard]] inline std::uint32_t load_u32_le(const std::uint8_t* p) noexcept {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
[[nodiscard]] inline std::uint64_t load_u64_le(const std::uint8_t* p) noexcept {
  std::uint64_t v = 0;
  for (int i = 7; i >= 0; --i) {
    v = (v << 8) | static_cast<std::uint64_t>(p[i]);
  }
  return v;
}
inline void store_u16_le(std::uint8_t* p, std::uint16_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v & 0xFFU);
  p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
}
inline void store_u32_le(std::uint8_t* p, std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v & 0xFFU);
  p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
  p[2] = static_cast<std::uint8_t>((v >> 16) & 0xFFU);
  p[3] = static_cast<std::uint8_t>((v >> 24) & 0xFFU);
}
inline void store_u64_le(std::uint8_t* p, std::uint64_t v) noexcept {
  for (int i = 0; i < 8; ++i) {
    p[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFU);
  }
}

using ByteBuffer = std::vector<std::uint8_t>;

// Append-only canonical writer.  Every length is checked against the encoder
// bound supplied at construction.
class BufferWriter {
 public:
  explicit BufferWriter(std::uint32_t max_bytes) : max_bytes_(max_bytes) { bytes_.reserve(256); }

  [[nodiscard]] const ByteBuffer& bytes() const noexcept { return bytes_; }
  [[nodiscard]] ByteBuffer take() noexcept { return std::move(bytes_); }
  [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
  [[nodiscard]] std::uint32_t max_bytes() const noexcept { return max_bytes_; }

  Status put_u8(std::uint8_t value);
  Status put_bool(bool value);
  Status put_u16(std::uint16_t value);
  Status put_u32(std::uint32_t value);
  Status put_u64(std::uint64_t value);
  Status put_i64(std::int64_t value);
  Status put_blob(const std::uint8_t* data, std::size_t length);
  Status put_bytes(const ByteBuffer& data) { return put_blob(data.data(), data.size()); }
  Status put_raw(std::string_view data);
  Status put_string(std::string_view value);

 private:
  [[nodiscard]] Status ensure(std::size_t extra) const;

  ByteBuffer bytes_;
  std::uint32_t max_bytes_;
};

class BufferReader {
 public:
  BufferReader(const std::uint8_t* data, std::size_t size, std::uint32_t max_string_bytes)
      : data_(data), size_(size), max_string_bytes_(max_string_bytes) {}

  explicit BufferReader(const ByteBuffer& bytes, std::uint32_t max_string_bytes)
      : BufferReader(bytes.data(), bytes.size(), max_string_bytes) {}

  [[nodiscard]] std::size_t remaining() const noexcept { return size_ - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
  [[nodiscard]] bool exhausted() const noexcept { return offset_ == size_; }

  Result<std::uint8_t> get_u8();
  Result<bool> get_bool();
  Result<std::uint16_t> get_u16();
  Result<std::uint32_t> get_u32();
  Result<std::uint64_t> get_u64();
  Result<std::int64_t> get_i64();
  Result<ByteBuffer> get_blob(std::uint32_t max_length);
  Result<std::string> get_string();

  // Reads a string bounded by a caller-supplied limit rather than by the identity-string limit.  Used
  // for the fields that legitimately carry rendered text -- an explanation, a per-key status message,
  // a statistics line -- where the identity bound would be an arbitrary truncation of data this
  // runtime itself produced.
  Result<std::string> get_long_string(std::uint32_t max_length);

  // Reads a count that must not exceed max_count before the caller allocates.
  Result<std::uint32_t> get_count(std::uint32_t max_count);

  // Succeeds only when every byte has been consumed.
  Status finish() const;

  // Succeeds only when at most max_extra bytes remain, and consumes them.  Used
  // by versioned containers which reserve room for forward-compatible trailers.
  Status finish_with_trailer(std::uint32_t max_extra);

 private:
  [[nodiscard]] Status require(std::size_t count) const;

  const std::uint8_t* data_ = nullptr;
  std::size_t size_ = 0;
  std::size_t offset_ = 0;
  std::uint32_t max_string_bytes_ = 0;
};

// Constant time comparison for integrity tags and digests.
[[nodiscard]] bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b,
                                       std::size_t length) noexcept;

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_BYTES_HPP
