// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Checked arithmetic and exact fixed point confidence.
//
// Two rules hold everywhere in this runtime:
//   1. no externally supplied or accumulator-driven size reaches an allocation
//      without a checked conversion;
//   2. no confidence value is ever produced by floating point arithmetic, so a
//      confidence score is bit-for-bit reproducible from the same evidence.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_MATH_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_MATH_HPP

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

// Checked unsigned addition/multiplication.  On overflow the result is untouched
// and ARITHMETIC_OVERFLOW is returned.
[[nodiscard]] inline Status checked_add_u64(std::uint64_t a, std::uint64_t b,
                                            std::uint64_t& out) noexcept {
  if (b > std::numeric_limits<std::uint64_t>::max() - a) {
    return Status::failure(ErrorCode::ARITHMETIC_OVERFLOW, "u64 addition overflow");
  }
  out = a + b;
  return Status::success();
}

[[nodiscard]] inline Status checked_mul_u64(std::uint64_t a, std::uint64_t b,
                                            std::uint64_t& out) noexcept {
  if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
    return Status::failure(ErrorCode::ARITHMETIC_OVERFLOW, "u64 multiplication overflow");
  }
  out = a * b;
  return Status::success();
}

[[nodiscard]] inline Status checked_add_u32(std::uint32_t a, std::uint32_t b,
                                            std::uint32_t& out) noexcept {
  if (b > std::numeric_limits<std::uint32_t>::max() - a) {
    return Status::failure(ErrorCode::ARITHMETIC_OVERFLOW, "u32 addition overflow");
  }
  out = a + b;
  return Status::success();
}

[[nodiscard]] inline Status checked_mul_u32(std::uint32_t a, std::uint32_t b,
                                            std::uint32_t& out) noexcept {
  if (a != 0 && b > std::numeric_limits<std::uint32_t>::max() / a) {
    return Status::failure(ErrorCode::ARITHMETIC_OVERFLOW, "u32 multiplication overflow");
  }
  out = a * b;
  return Status::success();
}

// Narrowing conversions from untrusted 64 bit input.  A range error is reported
// as OUT_OF_RANGE rather than truncating.
[[nodiscard]] inline Result<std::uint32_t> narrow_u32(std::uint64_t value,
                                                      std::string_view what) {
  if (value > std::numeric_limits<std::uint32_t>::max()) {
    return Status::failure(ErrorCode::OUT_OF_RANGE,
                           std::string(what) + " does not fit in 32 bits");
  }
  return static_cast<std::uint32_t>(value);
}

// A monotonic counter that refuses to wrap rather than silently reusing a value.
// Every generation, sequence and epoch in this runtime is a Counter.
class Counter {
 public:
  constexpr Counter() noexcept = default;
  explicit constexpr Counter(std::uint64_t value) noexcept : value_(value) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_exhausted() const noexcept {
    return value_ == std::numeric_limits<std::uint64_t>::max();
  }

  // Returns COUNTER_EXHAUSTED instead of wrapping.
  Status next(std::uint64_t& out) noexcept {
    if (is_exhausted()) {
      return Status::failure(ErrorCode::COUNTER_EXHAUSTED, "counter exhausted; value would wrap");
    }
    ++value_;
    out = value_;
    return Status::success();
  }

  // Raises the counter to a value observed elsewhere.  Never lowers it.
  void observe(std::uint64_t value) noexcept {
    if (value > value_) value_ = value;
  }

  void force(std::uint64_t value) noexcept { value_ = value; }

 private:
  std::uint64_t value_ = 0;
};

// Exact fixed point ratio in [0, 1] with a denominator of 10000, i.e. basis
// points.  10000 means full confidence.  Rendering is always decimal with four
// fractional digits, never binary floating point.
class Confidence {
 public:
  static constexpr std::uint32_t kScale = 10000U;

  constexpr Confidence() noexcept = default;
  explicit constexpr Confidence(std::uint32_t basis_points) noexcept
      : value_(basis_points > kScale ? kScale : basis_points) {}

  [[nodiscard]] static constexpr Confidence from_basis_points(std::uint32_t bp) noexcept {
    return Confidence(bp);
  }
  [[nodiscard]] static constexpr Confidence from_percent(std::uint32_t percent) noexcept {
    return Confidence(percent > 100U ? kScale : percent * 100U);
  }
  [[nodiscard]] static constexpr Confidence none() noexcept { return Confidence(0); }
  [[nodiscard]] static constexpr Confidence full() noexcept { return Confidence(kScale); }

  [[nodiscard]] constexpr std::uint32_t basis_points() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }

  friend constexpr bool operator==(Confidence a, Confidence b) noexcept {
    return a.value_ == b.value_;
  }
  friend constexpr bool operator!=(Confidence a, Confidence b) noexcept { return !(a == b); }
  friend constexpr bool operator<(Confidence a, Confidence b) noexcept { return a.value_ < b.value_; }
  friend constexpr bool operator>(Confidence a, Confidence b) noexcept { return b < a; }
  friend constexpr bool operator<=(Confidence a, Confidence b) noexcept { return !(b < a); }
  friend constexpr bool operator>=(Confidence a, Confidence b) noexcept { return !(a < b); }

  // Saturating selection: the weaker or stronger of two confidences, never a
  // silent average.
  [[nodiscard]] static constexpr Confidence weaker(Confidence a, Confidence b) noexcept {
    return a.value_ < b.value_ ? a : b;
  }
  [[nodiscard]] static constexpr Confidence stronger(Confidence a, Confidence b) noexcept {
    return a.value_ > b.value_ ? a : b;
  }

  // Deterministic, saturating decrement used to express an explicit penalty (for
  // example a live contradiction).  Saturates at zero rather than wrapping.
  [[nodiscard]] constexpr Confidence reduced_by(std::uint32_t basis_points) const noexcept {
    return Confidence(value_ > basis_points ? value_ - basis_points : 0U);
  }

  // Canonical decimal rendering with exactly four fractional digits, so the same
  // value always renders identically: "0.9000".
  [[nodiscard]] std::string to_decimal() const;

 private:
  std::uint32_t value_ = 0;
};

// Parses a canonical decimal confidence.  Rejects anything that is not exactly
// representable: "0.9" is accepted as 0.9000, "0.90001" is refused rather than
// rounded.
[[nodiscard]] Result<Confidence> parse_confidence(std::string_view text);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_MATH_HPP
