// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Convenience header.  Including this header pulls in the whole public API; a
// consumer that wants a smaller dependency should include the specific headers it
// needs instead.

#ifndef AI_FLOW_CLASSIFIER_AI_FLOW_CLASSIFIER_HPP
#define AI_FLOW_CLASSIFIER_AI_FLOW_CLASSIFIER_HPP

#include "ai_flow_classifier/classify/classifier.hpp"
#include "ai_flow_classifier/classify/decision_engine.hpp"
#include "ai_flow_classifier/codec/record_codec.hpp"
#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/publisher.hpp"
#include "ai_flow_classifier/domain/semantic_class.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/config.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"
#include "ai_flow_classifier/foundation/log.hpp"
#include "ai_flow_classifier/foundation/math.hpp"
#include "ai_flow_classifier/foundation/rng.hpp"
#include "ai_flow_classifier/foundation/text.hpp"
#include "ai_flow_classifier/io/files.hpp"
#include "ai_flow_classifier/net/channel.hpp"
#include "ai_flow_classifier/net/tcp.hpp"
#include "ai_flow_classifier/protocol/frame.hpp"
#include "ai_flow_classifier/protocol/messages.hpp"
#include "ai_flow_classifier/runtime/coordinator.hpp"
#include "ai_flow_classifier/runtime/coordinator_service.hpp"
#include "ai_flow_classifier/state/snapshot.hpp"
#include "ai_flow_classifier/store/classification_index.hpp"
#include "ai_flow_classifier/store/evidence_store.hpp"
#include "ai_flow_classifier/store/flow_registry.hpp"
#include "ai_flow_classifier/store/publisher_registry.hpp"
#include "ai_flow_classifier/store/workload_registry.hpp"

#endif  // AI_FLOW_CLASSIFIER_AI_FLOW_CLASSIFIER_HPP
