// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Structured diagnostics.
//
// The library never writes to stdout or stderr and never emits anything on its
// own initiative: a caller installs a sink, and every message is delivered
// through it.  The default state is a disabled logger, which keeps library code
// free of debug prints and keeps stdout available for machine-readable CLI
// output.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_LOG_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_LOG_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

namespace aifc {

enum class LogLevel : std::uint8_t {
  kTrace = 0,
  kDebug = 1,
  kInfo = 2,
  kWarn = 3,
  kError = 4,
  kOff = 5,
};

[[nodiscard]] std::string_view to_string(LogLevel level) noexcept;

struct LogRecord {
  LogLevel level = LogLevel::kInfo;
  // Subsystem that produced the record, for example "classifier" or "coordinator".
  std::string_view component;
  std::string_view message;
  std::uint64_t tick = 0;
  // Optional correlation token: a flow id, session id, publisher id or request id.
  std::string_view correlation;
  // Optional stable error name; empty when the record is not about a failure.
  std::string_view error;
};

using LogSink = std::function<void(const LogRecord&)>;

class Logger {
 public:
  Logger() = default;

  void set_sink(LogSink sink) { sink_ = std::move(sink); }
  void set_clock(std::function<std::uint64_t()> clock) { clock_ = std::move(clock); }
  void set_level(LogLevel level) noexcept { level_ = level; }
  void set_component(std::string component) { component_ = std::move(component); }

  [[nodiscard]] LogLevel level() const noexcept { return level_; }
  [[nodiscard]] const std::string& component() const noexcept { return component_; }
  [[nodiscard]] bool enabled(LogLevel level) const noexcept {
    return clock_ != nullptr && sink_ != nullptr && level >= level_ && level != LogLevel::kOff;
  }

  void log(LogLevel level, std::string_view message, std::string_view correlation = {},
           std::string_view error = {}) const;

  void trace(std::string_view message, std::string_view correlation = {}) const {
    log(LogLevel::kTrace, message, correlation);
  }
  void debug(std::string_view message, std::string_view correlation = {}) const {
    log(LogLevel::kDebug, message, correlation);
  }
  void info(std::string_view message, std::string_view correlation = {},
            std::string_view error = {}) const {
    log(LogLevel::kInfo, message, correlation, error);
  }
  void debug(std::string_view message, std::string_view correlation = {},
             std::string_view error = {}) const {
    log(LogLevel::kDebug, message, correlation, error);
  }
  void warn(std::string_view message, std::string_view correlation = {},
            std::string_view error = {}) const {
    log(LogLevel::kWarn, message, correlation, error);
  }
  void error(std::string_view message, std::string_view correlation = {},
             std::string_view error = {}) const {
    log(LogLevel::kError, message, correlation, error);
  }

  // A logger that shares the sink, clock and level but reports another component.
  [[nodiscard]] Logger with_component(std::string component) const;

 private:
  LogSink sink_;
  std::function<std::uint64_t()> clock_;
  LogLevel level_ = LogLevel::kInfo;
  std::string component_ = "ai_flow_classifier";
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_LOG_HPP
