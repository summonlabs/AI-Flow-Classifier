// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/math.hpp"

#include <string>

namespace aifc {

std::string Confidence::to_decimal() const {
  const std::uint32_t whole = value_ / kScale;
  const std::uint32_t fraction = value_ % kScale;
  std::string out = std::to_string(whole);
  out.push_back('.');
  // Exactly four fractional digits, zero padded, so equal values always render
  // identically and text comparison is exact.
  const std::uint32_t divisor[4] = {1000U, 100U, 10U, 1U};
  for (std::uint32_t d : divisor) {
    out.push_back(static_cast<char>('0' + ((fraction / d) % 10U)));
  }
  return out;
}

Result<Confidence> parse_confidence(std::string_view text) {
  if (text.empty()) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "confidence is empty");
  }
  std::size_t index = 0;
  std::uint64_t whole = 0;
  bool saw_digit = false;
  while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
    whole = whole * 10ULL + static_cast<std::uint64_t>(text[index] - '0');
    if (whole > 1ULL) {
      return Status::failure(ErrorCode::OUT_OF_RANGE, "confidence exceeds 1.0");
    }
    saw_digit = true;
    ++index;
  }
  if (!saw_digit) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "confidence has no integer part");
  }
  std::uint64_t fraction = 0;
  std::size_t fraction_digits = 0;
  if (index < text.size() && text[index] == '.') {
    ++index;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
      if (fraction_digits >= 4) {
        // More precision than the fixed point representation can hold.  Rounding
        // silently would make two different inputs render as one value, so this is
        // refused instead.
        if (text[index] != '0') {
          return Status::failure(ErrorCode::MALFORMED_INPUT,
                                 "confidence has more than 4 fractional digits");
        }
      } else {
        fraction = fraction * 10ULL + static_cast<std::uint64_t>(text[index] - '0');
        ++fraction_digits;
      }
      ++index;
    }
  }
  if (index != text.size()) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "confidence contains a non-numeric character");
  }
  while (fraction_digits < 4) {
    fraction *= 10ULL;
    ++fraction_digits;
  }
  const std::uint64_t basis_points = whole * Confidence::kScale + fraction;
  if (basis_points > Confidence::kScale) {
    return Status::failure(ErrorCode::OUT_OF_RANGE, "confidence exceeds 1.0");
  }
  return Confidence(static_cast<std::uint32_t>(basis_points));
}

}  // namespace aifc
