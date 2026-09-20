// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/domain/semantic_class.hpp"

#include <array>
#include <string>

namespace aifc {
namespace {

struct ClassEntry {
  SemanticClass value;
  std::string_view name;
};

// Canonical names are part of the text and wire format.  They never change for a
// given code; a rename would silently reinterpret every stored classification.
constexpr std::array<ClassEntry, 12> kBuiltinClasses = {{
    {SemanticClass::UNKNOWN, "UNKNOWN"},
    {SemanticClass::COLLECTIVE, "COLLECTIVE"},
    {SemanticClass::TRAINING_SYNC, "TRAINING_SYNC"},
    {SemanticClass::INFERENCE_REQUEST, "INFERENCE_REQUEST"},
    {SemanticClass::PREFILL_DECODE_HANDOFF, "PREFILL_DECODE_HANDOFF"},
    {SemanticClass::KV_STATE_TRANSFER, "KV_STATE_TRANSFER"},
    {SemanticClass::MODEL_STATE_TRANSFER, "MODEL_STATE_TRANSFER"},
    {SemanticClass::SHUFFLE, "SHUFFLE"},
    {SemanticClass::CHECKPOINT, "CHECKPOINT"},
    {SemanticClass::STORAGE_DATA, "STORAGE_DATA"},
    {SemanticClass::CONTROL_PLANE, "CONTROL_PLANE"},
    {SemanticClass::TELEMETRY, "TELEMETRY"},
}};

}  // namespace

std::string_view to_string(SemanticClass value) noexcept {
  for (const ClassEntry& entry : kBuiltinClasses) {
    if (entry.value == value) return entry.name;
  }
  return "EXTENSION";
}

Result<SemanticClass> parse_semantic_class(std::string_view text) {
  for (const ClassEntry& entry : kBuiltinClasses) {
    if (entry.name == text) return entry.value;
  }
  // An unrecognised label is a malformed label, never a silent UNKNOWN.  A peer
  // that sends "collective " or "Collective" or a novel name has its input
  // refused; it does not receive UNKNOWN, because UNKNOWN is a legitimate
  // classification and must not be reachable by misspelling.
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised semantic class label: " + std::string(text));
}

Result<SemanticClass> decode_semantic_class(std::uint16_t code) noexcept {
  for (const ClassEntry& entry : kBuiltinClasses) {
    if (static_cast<std::uint16_t>(entry.value) == code) return entry.value;
  }
  // A numeric code from the wire that is not a built-in decodes to UNKNOWN with
  // success: the code is understood as "not a class this build knows", which is
  // exactly what UNKNOWN means.
  return SemanticClass::UNKNOWN;
}

const std::vector<SemanticClass>& all_builtin_classes() {
  static const std::vector<SemanticClass> classes = []() {
    std::vector<SemanticClass> out;
    out.reserve(kBuiltinClasses.size());
    for (const ClassEntry& entry : kBuiltinClasses) out.push_back(entry.value);
    return out;
  }();
  return classes;
}

}  // namespace aifc
