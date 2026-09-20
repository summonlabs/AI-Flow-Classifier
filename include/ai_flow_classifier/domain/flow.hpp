// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Flow registration and incarnation tracking.
//
// A flow key identifies an observed flow; a flow generation identifies one incarnation
// of it.  The runtime never equates the two: a classification is bound to
// (key, generation), so a reincarnated flow does not inherit the classification of its
// predecessor, and a matching identity is never mistaken for a current generation.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_FLOW_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_FLOW_HPP

#include <cstdint>
#include <string>

#include "ai_flow_classifier/domain/flow_key.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

// A registered flow incarnation.
struct FlowRecord {
  FlowId id;
  FlowKey key;
  FlowGeneration generation;
  Seq registered_seq = 0;
  Tick registered_tick = kTickNone;
  Tick last_activity_tick = kTickNone;
  // Session that registered this incarnation.  Used to attribute authority, not to
  // grant it.
  SessionId registered_by;
  // How many times this incarnation has been renewed without a generation change.
  std::uint64_t renewals = 0;
};

// Result of registering a flow key.  Registration is idempotent for an identical
// (key, generation) pair, and a strictly larger generation implicitly fences the
// previous one.
struct FlowRegistration {
  FlowRecord record;
  // True when this call created the incarnation; false when it was an identical repeat.
  bool created = false;
  // True when this call fenced a previous, lower generation, so that the caller can see
  // that derived classifications for the previous generation were invalidated.
  bool fenced_previous = false;
  FlowGeneration previous_generation;
};

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_FLOW_HPP
