// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/domain/publisher.hpp"

#include <array>
#include <string>

namespace aifc {
namespace {

struct StateEntry {
  PublisherState value;
  std::string_view name;
};

// The state names are part of the diagnostic surface: they appear in explanations and
// in the CLI, so they are stable and canonical.
constexpr std::array<StateEntry, 4> kStates = {{
    {PublisherState::REGISTERED, "REGISTERED"},
    {PublisherState::LIVE, "LIVE"},
    {PublisherState::IDLE, "IDLE"},
    {PublisherState::DEAD, "DEAD"},
}};

}  // namespace

std::string_view to_string(PublisherState value) noexcept {
  for (const StateEntry& entry : kStates) {
    if (entry.value == value) return entry.name;
  }
  return "UNRECOGNIZED_PUBLISHER_STATE";
}

Result<PublisherState> parse_publisher_state(std::string_view text) {
  for (const StateEntry& entry : kStates) {
    if (entry.name == text) return entry.value;
  }
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised publisher state: " + std::string(text));
}

}  // namespace aifc
