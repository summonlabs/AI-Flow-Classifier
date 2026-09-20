// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/log.hpp"

namespace aifc {

std::string_view to_string(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::kTrace:
      return "TRACE";
    case LogLevel::kDebug:
      return "DEBUG";
    case LogLevel::kInfo:
      return "INFO";
    case LogLevel::kWarn:
      return "WARN";
    case LogLevel::kError:
      return "ERROR";
    case LogLevel::kOff:
      return "OFF";
  }
  return "UNKNOWN";
}

void Logger::log(LogLevel level, std::string_view message, std::string_view correlation,
                 std::string_view error) const {
  if (!enabled(level)) return;
  LogRecord record;
  record.level = level;
  record.component = component_;
  record.message = message;
  record.correlation = correlation;
  record.error = error;
  record.tick = clock_ ? clock_() : 0;
  // The sink is invoked with no internal lock held: a sink that calls back into
  // the runtime must not be able to deadlock against the logger.
  sink_(record);
}

Logger Logger::with_component(std::string component) const {
  Logger child;
  child.sink_ = sink_;
  child.clock_ = clock_;
  child.level_ = level_;
  child.component_ = std::move(component);
  return child;
}

}  // namespace aifc
