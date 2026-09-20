// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// SHA-256 (FIPS 180-4) and CRC-32 (IEEE 802.3), both self-contained.
//
// SHA-256 is used for content verification of evidence and for decision digests.
// CRC-32 is used as the frame integrity tag, where it detects accidental
// corruption cheaply; it is explicitly not a security primitive, and the frame
// header documents that.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_HASH_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_HASH_HPP

#include <ostream>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace aifc {

class Sha256 {
 public:
  static constexpr std::size_t kDigestBytes = 32;
  static constexpr std::size_t kBlockBytes = 64;

  Sha256() noexcept { reset(); }

  void reset() noexcept;
  void update(const std::uint8_t* data, std::size_t length) noexcept;
  void update(std::string_view text) noexcept {
    update(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
  }
  void update(const std::vector<std::uint8_t>& data) noexcept { update(data.data(), data.size()); }

  // Writes 32 bytes into out and leaves the object usable for further updates so
  // that callers can take intermediate digests.
  void finish(std::uint8_t* out) noexcept;
  [[nodiscard]] std::array<std::uint8_t, kDigestBytes> finish() noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::uint32_t state_[8] = {};
  std::uint64_t total_bytes_ = 0;
  std::uint8_t buffer_[kBlockBytes] = {};
  std::size_t buffered_ = 0;
};

[[nodiscard]] std::array<std::uint8_t, Sha256::kDigestBytes> sha256(const std::uint8_t* data,
                                                                    std::size_t length) noexcept;
[[nodiscard]] std::array<std::uint8_t, Sha256::kDigestBytes> sha256(std::string_view text) noexcept;

class Crc32 {
 public:
  Crc32() noexcept;
  void reset() noexcept { value_ = 0xFFFFFFFFU; }
  void update(const std::uint8_t* data, std::size_t length) noexcept;
  [[nodiscard]] std::uint32_t value() const noexcept { return value_ ^ 0xFFFFFFFFU; }

 private:
  std::uint32_t value_ = 0xFFFFFFFFU;
};

[[nodiscard]] std::uint32_t crc32(const std::uint8_t* data, std::size_t length) noexcept;

// 64 bit non-cryptographic mixer used for index bucketing only.  Never used to
// authorise anything.
[[nodiscard]] std::uint64_t mix64(std::uint64_t value) noexcept;

// Stable 64 bit hash of a byte range, suitable for hash maps whose iteration
// order must not affect decisions.
[[nodiscard]] std::uint64_t stable_hash_bytes(const std::uint8_t* data, std::size_t length) noexcept;
[[nodiscard]] std::uint64_t stable_hash_text(std::string_view text) noexcept;
[[nodiscard]] std::uint64_t stable_hash_combine(std::uint64_t seed, std::uint64_t value) noexcept;

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_HASH_HPP
