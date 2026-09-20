// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic pseudo random generation.
//
// The runtime needs randomness in exactly two places: inventing opaque 128 bit
// flow/evidence identities, and driving seeded property tests with reproducible
// reproduction seeds.  Both use this generator.  It is deliberately not a
// cryptographic primitive and is never used to authorise anything; identities are
// uniqueness tokens, not capabilities.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_RNG_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_RNG_HPP

#include <ostream>
#include <cstdint>
#include <string>
#include <string_view>

#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

// splitmix64: full period, trivially reproducible, identical on every platform.
class Rng {
 public:
  Rng() noexcept : state_(0x9E3779B97F4A7C15ULL) {}
  explicit Rng(std::uint64_t seed) noexcept : state_(seed == 0 ? 0x9E3779B97F4A7C15ULL : seed) {}

  [[nodiscard]] std::uint64_t next_u64() noexcept;
  [[nodiscard]] std::uint32_t next_u32() noexcept {
    return static_cast<std::uint32_t>(next_u64() >> 32);
  }
  // Uniform value in [0, bound).  bound == 0 yields 0.
  [[nodiscard]] std::uint64_t next_below(std::uint64_t bound) noexcept;
  [[nodiscard]] bool next_bool() noexcept { return (next_u64() & 1U) != 0U; }
  [[nodiscard]] std::uint64_t state() const noexcept { return state_; }

  [[nodiscard]] Id128 next_id128() noexcept;

 private:
  std::uint64_t state_;
};

// Derives a deterministic seed from arbitrary text.  Used by tests so that a
// failure can be reproduced from the seed printed in the failure message.
[[nodiscard]] std::uint64_t seed_from_text(std::string_view text) noexcept;

// Formats a reproduction seed in the canonical form used by failing property
// tests, e.g. "seed=0x0123456789abcdef".
[[nodiscard]] std::string format_seed(std::uint64_t seed);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_RNG_HPP
