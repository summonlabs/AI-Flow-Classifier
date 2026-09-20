// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Semantic class vocabulary.
//
// A semantic class answers exactly one question: what AI workload semantic class
// does this flow belong to now.  It is not a priority, not a routing decision and
// not a policy verdict.  The vocabulary is closed at the wire level and open at
// the extension level: unknown numeric codes decode to UNKNOWN rather than
// failing, and a legitimate extension class must be registered explicitly, which
// creates a deliberate, visible act rather than an accidental privilege.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_SEMANTIC_CLASS_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_SEMANTIC_CLASS_HPP

#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

enum class SemanticClass : std::uint16_t {
  UNKNOWN = 0,
  COLLECTIVE = 1,
  TRAINING_SYNC = 2,
  INFERENCE_REQUEST = 3,
  PREFILL_DECODE_HANDOFF = 4,
  KV_STATE_TRANSFER = 5,
  MODEL_STATE_TRANSFER = 6,
  SHUFFLE = 7,
  CHECKPOINT = 8,
  STORAGE_DATA = 9,
  CONTROL_PLANE = 10,
  TELEMETRY = 11,

  // Extension band.  Codes at or above this value exist only while a matching
  // registration is live in the process; they are never produced by decoding a
  // label that was not registered first.
  kExtensionBase = 256,
};

inline constexpr std::uint16_t kMaxExtensionClasses = 64U;

// Canonical upper snake case name, for example "KV_STATE_TRANSFER".  The name is
// part of the wire and text format and never changes for a given code.
[[nodiscard]] std::string_view to_string(SemanticClass value) noexcept;

// Strict parse: only an exactly matching canonical name is accepted.  A name that
// is merely similar, lower case, padded or novel is MALFORMED_INPUT, never a
// silent UNKNOWN, so a malformed label cannot promote a flow to a class.
[[nodiscard]] Result<SemanticClass> parse_semantic_class(std::string_view text);

// Lenient decode used only where a numeric code arrives from the wire.  A code
// that is not a built-in is UNKNOWN with ok() == true; the caller can see that
// the code was not understood, which is different from failing to parse.
[[nodiscard]] Result<SemanticClass> decode_semantic_class(std::uint16_t code) noexcept;

// True when the class is UNKNOWN.  Used by the invariant checks and by the
// decision engine to express "no authority produced a class".
[[nodiscard]] inline bool is_unknown(SemanticClass value) noexcept {
  return value == SemanticClass::UNKNOWN;
}

// Every built-in class in canonical order.  The order is stable and is used by
// the CLI to render enumerations reproducibly.
[[nodiscard]] const std::vector<SemanticClass>& all_builtin_classes();

// Rendering a class always yields its canonical name, never its numeric code.
inline std::ostream& operator<<(std::ostream& stream, SemanticClass value) {
  return stream << to_string(value);
}

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_SEMANTIC_CLASS_HPP
