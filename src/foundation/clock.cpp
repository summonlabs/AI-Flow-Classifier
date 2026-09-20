// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/clock.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>

namespace aifc {

SteadyTickSource::SteadyTickSource() noexcept {
  // The origin is expressed in milliseconds since this process established the
  // source.  It is deliberately not a wall clock: a system clock adjustment must
  // never extend or shorten a freshness window.
  origin_point_ = std::chrono::steady_clock::now();
  origin_ = 1;
}

Tick SteadyTickSource::now() const noexcept {
  const auto elapsed = std::chrono::steady_clock::now() - origin_point_;
  const auto millis =
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
  if (millis < 0) return origin_;
  return origin_ + static_cast<Tick>(millis);
}

Tick ManualTickSource::advance(Tick delta) noexcept {
  Tick next = current_.load(std::memory_order_acquire);
  for (;;) {
    const Tick desired = next + delta;  // Tick is unsigned; wrap is not reachable in practice
    if (current_.compare_exchange_weak(next, desired, std::memory_order_acq_rel,
                                       std::memory_order_acquire)) {
      return desired;
    }
  }
}

Tick ManualTickSource::set(Tick value) noexcept {
  current_.store(value, std::memory_order_release);
  return value;
}

std::uint64_t wall_clock_unix_millis() noexcept {
  const auto now = std::chrono::system_clock::now();
  const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
  return static_cast<std::uint64_t>(millis.count());
}

std::string format_unix_millis_utc(std::uint64_t unix_millis) {
  const std::time_t seconds = static_cast<std::time_t>(unix_millis / 1000ULL);
  std::tm tm_value{};
#if defined(AIFC_PLATFORM_WINDOWS)
  if (gmtime_s(&tm_value, &seconds) != 0) {
    return "invalid-time";
  }
#else
  if (gmtime_r(&seconds, &tm_value) == nullptr) {
    return "invalid-time";
  }
#endif
  char buffer[32] = {};
  const std::size_t written = std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm_value);
  if (written == 0) {
    return "invalid-time";
  }
  return std::string(buffer, written);
}

}  // namespace aifc
