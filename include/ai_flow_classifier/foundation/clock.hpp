// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Time abstraction.
//
// Freshness and liveness decisions must be reproducible, so the decision engine
// never reads the wall clock.  It is given a TickSource, and every authority
// decision is expressed in terms of that source.  Tests substitute a manual
// source and therefore reach every freshness boundary deterministically.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_CLOCK_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_CLOCK_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

namespace aifc {

using Tick = std::uint64_t;
inline constexpr Tick kTickNone = 0;

// A tick that means "the caller did not supply a clock".  Authority decisions that
// depend on freshness are skipped rather than guessed when the tick is absent; the
// liveness, generation and epoch rules still apply in full.
[[nodiscard]] inline Tick tick_none() noexcept { return kTickNone; }

class TickSource {
 public:
  TickSource() = default;
  TickSource(const TickSource&) = delete;
  TickSource& operator=(const TickSource&) = delete;
  TickSource(TickSource&&) = delete;
  TickSource& operator=(TickSource&&) = delete;
  virtual ~TickSource() = default;

  [[nodiscard]] virtual Tick now() const noexcept = 0;
};

// Monotonic milliseconds since the source was constructed.  Monotonic means a
// system clock adjustment cannot move a tick backwards, so a freshness window
// cannot be extended by changing the wall clock.
class SteadyTickSource final : public TickSource {
 public:
  SteadyTickSource() noexcept;
  [[nodiscard]] Tick now() const noexcept override;
  [[nodiscard]] Tick origin() const noexcept { return origin_; }

 private:
  std::chrono::steady_clock::time_point origin_point_;
  Tick origin_;
};

// Manually advanced source for deterministic tests.  Thread safe so that
// concurrency tests can advance it from a driver thread while workers observe it.
class ManualTickSource final : public TickSource {
 public:
  explicit ManualTickSource(Tick start = 1) noexcept : current_(start) {}
  [[nodiscard]] Tick now() const noexcept override {
    return current_.load(std::memory_order_acquire);
  }
  Tick advance(Tick delta) noexcept;
  Tick set(Tick value) noexcept;

 private:
  std::atomic<Tick> current_;
};

// Wall clock rendering, used only for human-facing output and for the durable
// "written at" field of persisted state.  It never participates in an authority
// decision.
[[nodiscard]] std::string format_unix_millis_utc(std::uint64_t unix_millis);
[[nodiscard]] std::uint64_t wall_clock_unix_millis() noexcept;

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_CLOCK_HPP
