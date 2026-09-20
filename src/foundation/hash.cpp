// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/hash.hpp"

#include <array>
#include <cstring>

namespace aifc {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U};

constexpr std::uint32_t kSha256Initial[8] = {0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
                                             0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};

[[nodiscard]] constexpr std::uint32_t rotr32(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32U - shift));
}

std::uint32_t crc32_table[256] = {};
bool crc32_table_ready = false;

void build_crc32_table() noexcept {
  for (std::uint32_t i = 0; i < 256U; ++i) {
    std::uint32_t c = i;
    for (int k = 0; k < 8; ++k) {
      c = ((c & 1U) != 0U) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
    }
    crc32_table[i] = c;
  }
  crc32_table_ready = true;
}

// The table is built once during static initialisation of the translation unit.
// A function local static would also work, but this keeps Crc32 constexpr-friendly
// call sites free of a guarded branch.
const bool crc32_table_initialised = []() noexcept {
  build_crc32_table();
  return true;
}();

}  // namespace

// --- SHA-256 ---------------------------------------------------------------

void Sha256::reset() noexcept {
  for (std::size_t i = 0; i < 8; ++i) state_[i] = kSha256Initial[i];
  total_bytes_ = 0;
  buffered_ = 0;
  std::memset(buffer_, 0, kBlockBytes);
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::uint32_t w[64] = {};
  for (std::size_t i = 0; i < 16; ++i) {
    const std::uint8_t* p = block + i * 4;
    w[i] = (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t length) noexcept {
  if (data == nullptr || length == 0) return;
  total_bytes_ += length;
  std::size_t offset = 0;
  while (offset < length) {
    const std::size_t take = (kBlockBytes - buffered_) < (length - offset)
                                 ? (kBlockBytes - buffered_)
                                 : (length - offset);
    std::memcpy(buffer_ + buffered_, data + offset, take);
    buffered_ += take;
    offset += take;
    if (buffered_ == kBlockBytes) {
      compress(buffer_);
      buffered_ = 0;
    }
  }
}

void Sha256::finish(std::uint8_t* out) noexcept {
  // The message length in bits excludes the padding that is about to be written,
  // so it is captured before the padding bytes are appended.
  const std::uint64_t bit_length = total_bytes_ * 8ULL;

  // Padding: a single 0x80 byte, then zero bytes until the trailing 8 byte length
  // field starts at offset 56 of the final block.
  static constexpr std::uint8_t kZeroBlock[kBlockBytes] = {};
  const std::uint8_t pad = 0x80U;
  update(&pad, 1);
  const std::size_t to_fill = (buffered_ <= 56) ? (56 - buffered_) : (64 - buffered_ + 56);
  std::size_t remaining = to_fill;
  while (remaining > 0) {
    const std::size_t chunk = remaining < kBlockBytes ? remaining : kBlockBytes;
    update(kZeroBlock, chunk);
    remaining -= chunk;
  }

  std::uint8_t length_bytes[8];
  for (int i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>((bit_length >> (8 * (7 - i))) & 0xFFU);
  }
  update(length_bytes, sizeof(length_bytes));

  // The padding above places the length field so that it ends exactly on a block boundary,
  // so update() has already compressed the final block.  Compressing the buffer again here
  // would mix a second, all-zero block into the digest and produce a value that matches no
  // published SHA-256 vector.
  buffered_ = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFFU);
    out[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFFU);
    out[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFFU);
    out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFU);
  }
}

std::array<std::uint8_t, Sha256::kDigestBytes> Sha256::finish() noexcept {
  std::array<std::uint8_t, kDigestBytes> out{};
  finish(out.data());
  return out;
}

std::array<std::uint8_t, Sha256::kDigestBytes> sha256(const std::uint8_t* data,
                                                     std::size_t length) noexcept {
  Sha256 hasher;
  hasher.update(data, length);
  return hasher.finish();
}

std::array<std::uint8_t, Sha256::kDigestBytes> sha256(std::string_view text) noexcept {
  return sha256(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

// --- CRC-32 ----------------------------------------------------------------

Crc32::Crc32() noexcept {
  if (!crc32_table_ready) {
    build_crc32_table();
  }
}

void Crc32::update(const std::uint8_t* data, std::size_t length) noexcept {
  if (data == nullptr) return;
  std::uint32_t value = value_;
  for (std::size_t i = 0; i < length; ++i) {
    value = crc32_table[(value ^ data[i]) & 0xFFU] ^ (value >> 8);
  }
  value_ = value;
  (void)crc32_table_initialised;
}

std::uint32_t crc32(const std::uint8_t* data, std::size_t length) noexcept {
  Crc32 hasher;
  hasher.update(data, length);
  return hasher.value();
}

// --- Mixing ----------------------------------------------------------------

std::uint64_t mix64(std::uint64_t value) noexcept {
  value += 0x9E3779B97F4A7C15ULL;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
  return value ^ (value >> 31);
}

std::uint64_t stable_hash_bytes(const std::uint8_t* data, std::size_t length) noexcept {
  // FNV-1a 64 bit.  Byte order dependent by construction, which is what makes it
  // stable across processes given the canonical encoding.
  std::uint64_t h = 1469598103934665603ULL;
  for (std::size_t i = 0; i < length; ++i) {
    h ^= static_cast<std::uint64_t>(data[i]);
    h *= 1099511628211ULL;
  }
  return h;
}

std::uint64_t stable_hash_text(std::string_view text) noexcept {
  return stable_hash_bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

std::uint64_t stable_hash_combine(std::uint64_t seed, std::uint64_t value) noexcept {
  std::uint64_t h = seed ^ (value + 0x9E3779B97F4A7C15ULL + (seed << 6) + (seed >> 2));
  return mix64(h);
}

}  // namespace aifc
