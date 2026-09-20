// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Streaming for the vocabulary and identity types.
//
// Every type in this runtime has a canonical text form, and the canonical form is what appears in
// an explanation, in the CLI and in a diagnostic.  Providing `operator<<` for those types means a
// caller never has to remember which one exposes `to_string` as a free function, as a member, or
// not at all -- and, more importantly, it means a diagnostic can never accidentally print an
// enum's numeric value instead of its name.
//
// These operators live in namespace aifc, so argument-dependent lookup finds them.  They do not
// add behaviour beyond rendering: nothing here participates in a decision.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_TEXT_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_TEXT_HPP

#include <ostream>
#include <string>
#include <string_view>

#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

inline std::ostream& operator<<(std::ostream& stream, ErrorCode value) {
  return stream << to_string(value);
}

inline std::ostream& operator<<(std::ostream& stream, ErrorClass value) {
  return stream << to_string(value);
}

inline std::ostream& operator<<(std::ostream& stream, const Status& status) {
  return stream << render_status(status);
}

template <typename T>
inline std::ostream& operator<<(std::ostream& stream, const Result<T>& result) {
  if (result) return stream << "ok";
  return stream << render_status(result.status());
}

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_TEXT_HPP
