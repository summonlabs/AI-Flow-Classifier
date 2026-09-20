// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/rng.hpp"

#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

std::uint64_t Rng::next_u64() noexcept {
  // splitmix64, with the state advanced by the golden gamma constant.
  state_ += 0x9E3779B97F4A7C15ULL;
  std::uint64_t z = state_;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

std::uint64_t Rng::next_below(std::uint64_t bound) noexcept {
  if (bound == 0) return 0;
  // Rejection sampling keeps the distribution exactly uniform, which matters for
  // seeded property tests where a biased generator would hide boundary cases.
  const std::uint64_t limit = UINT64_MAX - (UINT64_MAX % bound);
  std::uint64_t value = next_u64();
  while (value >= limit) {
    value = next_u64();
  }
  return value % bound;
}

Id128 Rng::next_id128() noexcept {
  Id128 id;
  id.hi = next_u64();
  id.lo = next_u64();
  if (id.is_zero()) {
    // A zero identity is the "absent" sentinel and must never be generated.
    id.lo = 1;
  }
  return id;
}

std::uint64_t seed_from_text(std::string_view text) noexcept {
  return mix64(stable_hash_text(text));
}

std::string format_seed(std::uint64_t seed) {
  std::string out = "seed=0x";
  for (int shift = 60; shift >= 0; shift -= 4) {
    out.push_back(kHexDigits[(seed >> shift) & 0x0FU]);
  }
  return out;
}

}  // namespace aifc
