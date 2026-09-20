// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Unit proof surface: the stores.
//
// These are the structures that decide what is remembered, what is fenced and what is
// forgotten.  Every bound in this file is a bound that is enforced on insert and reported
// through stats(), never applied silently.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "test_framework.hpp"

#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/publisher.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/store/classification_index.hpp"
#include "ai_flow_classifier/store/evidence_store.hpp"
#include "ai_flow_classifier/store/flow_registry.hpp"
#include "ai_flow_classifier/store/publisher_registry.hpp"
#include "ai_flow_classifier/store/workload_registry.hpp"

#include "synthetic.hpp"

namespace {

[[nodiscard]] bool contains(const std::string& haystack, std::string_view needle) {
  return haystack.find(needle) != std::string::npos;
}

[[nodiscard]] aifc::EvidenceRecord make_evidence(const std::string& id_text, aifc::FlowId flow,
                                                 aifc::FlowGeneration generation,
                                                 aifc::SemanticClass semantic,
                                                 aifc::EvidenceSource source, aifc::Seq seq) {
  aifc::EvidenceRecord record;
  record.id = aifc::make_evidence_id(id_text);
  record.publisher = aifc::make_publisher_id("publisher-1");
  record.publisher_boot = aifc::PublisherBootId{1};
  record.session = aifc::SessionId("session-1");
  record.accepted_epoch = aifc::CoordinatorEpoch{1};
  record.accepted_boot = aifc::CoordinatorBootId{1};
  record.flow_id = flow;
  record.flow_generation = generation;
  record.generation = aifc::EvidenceGeneration{seq};
  record.accepted_seq = seq;
  record.accepted_tick = 100;
  record.fresh_until = 4196;
  record.semantic = semantic;
  record.source = source;
  record.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  record.confidence = aifc::source_confidence(source);
  record.metadata.topic = "synthetic.topic";
  record.content_digest = aifc::compute_evidence_digest(record);
  return record;
}

[[nodiscard]] aifc::Classification make_classification(aifc::FlowId flow,
                                                       aifc::FlowGeneration generation,
                                                       aifc::SemanticClass semantic) {
  aifc::Classification classification;
  classification.flow_id = flow;
  classification.flow_generation = generation;
  classification.semantic = semantic;
  classification.state = aifc::ClassificationState::CURRENT;
  classification.confidence = aifc::Confidence::from_basis_points(9000U);
  classification.selected_evidence = aifc::make_evidence_id("ev-selected");
  classification.selected_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  classification.policy_generation = aifc::ClassifierPolicyGeneration{1};
  return classification;
}

// A Digest256 is an aggregate whose bytes are not assignable from the std::array that
// sha256 returns, so the copy is explicit.
[[nodiscard]] aifc::Digest256 digest_of(std::string_view text) {
  const auto hash = aifc::sha256(text);
  aifc::Digest256 digest;
  for (std::size_t i = 0; i < aifc::Digest256::kBytes; ++i) {
    digest.bytes[i] = hash[i];
  }
  return digest;
}

[[nodiscard]] aifc::WorkloadContract make_contract(const std::string& id_text,
                                                   const std::string& workload_text,
                                                   aifc::PublisherId owner,
                                                   aifc::WorkloadGeneration generation) {
  aifc::WorkloadContract contract;
  contract.id = aifc::make_contract_id(id_text);
  contract.workload = aifc::make_workload_id(workload_text);
  contract.workload_generation = generation;
  contract.owner = owner;
  contract.declared_class = aifc::SemanticClass::COLLECTIVE;
  contract.match_any_remote_address = true;
  contract.transport = aifc::TransportProtocol::TCP;
  contract.description = "synthetic contract";
  return contract;
}

}  // namespace

// ---------------------------------------------------------------------------
// FlowRegistry
// ---------------------------------------------------------------------------

AIFC_TEST("store/flow_registry: create, idempotent repeat and generation advance (REAL)") {
  aifc::FlowRegistry registry(16U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(0U);
  const aifc::SessionId session = aifc_test::synthetic_session(0U);
  const aifc::Id128 expected_id = aifc::derive_flow_id(key);

  const auto created = registry.register_flow(key, aifc::FlowGeneration{0}, session, 100);
  AIFC_CHECK_OK(created);
  if (!created) return;
  AIFC_CHECK_EQ(created.value().created, true);
  AIFC_CHECK_EQ(created.value().fenced_previous, false);
  AIFC_CHECK_EQ(created.value().record.generation.value, 1U);
  AIFC_CHECK_EQ(created.value().record.id.to_hex(), expected_id.to_hex());
  AIFC_CHECK_EQ(created.value().record.renewals, 0U);
  AIFC_CHECK_EQ(created.value().record.registered_tick, 100U);
  AIFC_CHECK_EQ(registry.size(), std::size_t{1});
  AIFC_CHECK_EQ(registry.stats().registrations, 1U);

  // An identical repeat is idempotent: same generation, no fence, activity refreshed.  The
  // current generation is named explicitly here, because generation zero means "the next
  // incarnation" and would advance rather than repeat.
  const auto repeated = registry.register_flow(key, aifc::FlowGeneration{1}, session, 250);
  AIFC_CHECK_OK(repeated);
  if (repeated) {
    AIFC_CHECK_EQ(repeated.value().created, false);
    AIFC_CHECK_EQ(repeated.value().fenced_previous, false);
    AIFC_CHECK_EQ(repeated.value().record.generation.value, 1U);
    AIFC_CHECK_EQ(repeated.value().record.id.to_hex(), expected_id.to_hex());
    AIFC_CHECK_EQ(repeated.value().record.renewals, 1U);
    AIFC_CHECK_EQ(repeated.value().record.last_activity_tick, 250U);
    AIFC_CHECK_EQ(repeated.value().record.registered_tick, 100U);
  }
  AIFC_CHECK_EQ(registry.size(), std::size_t{1});
  AIFC_CHECK_EQ(registry.stats().repeats, 1U);
  AIFC_CHECK_EQ(registry.stats().generation_advances, 0U);

  // A strictly larger generation fences the previous incarnation and reports which one.
  const auto advanced = registry.register_flow(key, aifc::FlowGeneration{4}, session, 300);
  AIFC_CHECK_OK(advanced);
  if (advanced) {
    AIFC_CHECK_EQ(advanced.value().created, true);
    AIFC_CHECK_EQ(advanced.value().fenced_previous, true);
    AIFC_CHECK_EQ(advanced.value().previous_generation.value, 1U);
    AIFC_CHECK_EQ(advanced.value().record.generation.value, 4U);
    AIFC_CHECK_EQ(advanced.value().record.renewals, 0U);
    AIFC_CHECK_EQ(advanced.value().record.last_activity_tick, 300U);
  }
  AIFC_CHECK_EQ(registry.stats().generation_advances, 1U);

  const auto current = registry.find_by_key(key);
  AIFC_CHECK_OK(current);
  if (current) {
    AIFC_CHECK_EQ(current.value().generation.value, 4U);
    AIFC_CHECK(registry.is_current(current.value()));
  }
  // The fenced incarnation is still reachable by exact generation, and is no longer current.
  const auto fenced = registry.find_generation(expected_id, aifc::FlowGeneration{1});
  AIFC_CHECK_OK(fenced);
  if (fenced) {
    AIFC_CHECK_EQ(fenced.value().generation.value, 1U);
    AIFC_CHECK(!registry.is_current(fenced.value()));
  }
  // Two indexed lookups happened above (find_by_key and find_generation), and the counter is
  // instrumentation that only ever grows.
  AIFC_CHECK(registry.stats().lookups >= 2U);
}

AIFC_TEST("store/flow_registry: lower and reused generations are STALE_GENERATION (REAL)") {
  aifc::FlowRegistry registry(16U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(1U);
  const aifc::SessionId session = aifc_test::synthetic_session(0U);

  AIFC_CHECK_OK(registry.register_flow(key, aifc::FlowGeneration{5}, session, 10));
  AIFC_CHECK_OK(registry.register_flow(key, aifc::FlowGeneration{8}, session, 20));

  // Lower than the current incarnation.
  const auto lower = registry.register_flow(key, aifc::FlowGeneration{7}, session, 30);
  AIFC_CHECK_ERR(lower, aifc::ErrorCode::STALE_GENERATION);
  if (!lower) {
    AIFC_CHECK_MSG(contains(lower.status().message, "generation 8") &&
                       contains(lower.status().message, "7"),
                   "the refusal must name the current generation and the requested one, got: "
                       << lower.status().message);
  }
  // A generation that was already fenced and is not the current one.
  const auto fenced = registry.register_flow(key, aifc::FlowGeneration{5}, session, 30);
  AIFC_CHECK_ERR(fenced, aifc::ErrorCode::STALE_GENERATION);

  // Generation zero means "next", and next is one past the highest ever observed.
  const auto next = registry.register_flow(key, aifc::FlowGeneration{0}, session, 40);
  AIFC_CHECK_OK(next);
  if (next) {
    AIFC_CHECK_EQ(next.value().record.generation.value, 9U);
    AIFC_CHECK_EQ(next.value().fenced_previous, true);
    AIFC_CHECK_EQ(next.value().previous_generation.value, 8U);
  }

  // A retired incarnation may not be resurrected: after the current one is retired, asking for
  // any generation that has already been observed is refused, not created.
  AIFC_CHECK_OK(registry.retire_flow(aifc::derive_flow_id(key), aifc::FlowGeneration{9}, 50));
  AIFC_CHECK_EQ(registry.size(), std::size_t{0});
  const auto resurrected = registry.register_flow(key, aifc::FlowGeneration{8}, session, 60);
  AIFC_CHECK_ERR(resurrected, aifc::ErrorCode::STALE_GENERATION);
  if (!resurrected) {
    AIFC_CHECK_MSG(contains(resurrected.status().message, "superseded") ||
                       contains(resurrected.status().message, "9"),
                   "the refusal must explain the reuse, got: "
                       << resurrected.status().message);
  }
  AIFC_CHECK_EQ(registry.size(), std::size_t{0});
  // A brand new generation after retirement is legal.
  const auto fresh = registry.register_flow(key, aifc::FlowGeneration{10}, session, 70);
  AIFC_CHECK_OK(fresh);
  AIFC_CHECK_EQ(registry.size(), std::size_t{1});
}

AIFC_TEST("store/flow_registry: capacity, lookups and restore (REAL)") {
  aifc::FlowRegistry registry(2U);
  const aifc::SessionId session = aifc_test::synthetic_session(0U);
  AIFC_CHECK_OK(registry.register_flow(aifc_test::synthetic_flow_key(0U), aifc::FlowGeneration{1},
                                       session, 1));
  AIFC_CHECK_OK(registry.register_flow(aifc_test::synthetic_flow_key(1U), aifc::FlowGeneration{1},
                                       session, 1));
  const auto full = registry.register_flow(aifc_test::synthetic_flow_key(2U), aifc::FlowGeneration{1},
                                           session, 1);
  AIFC_CHECK_ERR(full, aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_EQ(registry.size(), std::size_t{2});
  AIFC_CHECK_EQ(registry.capacity(), 2U);
  AIFC_CHECK_EQ(registry.stats().capacity_rejections, 1U);
  // An existing key is still renewable while the registry is full: capacity bounds keys, not
  // renewals.
  AIFC_CHECK_OK(registry.register_flow(aifc_test::synthetic_flow_key(0U), aifc::FlowGeneration{1},
                                       session, 9));

  // A zero capacity registry refuses everything, which is "refuse every insert" and not
  // "unbounded".
  aifc::FlowRegistry none(0U);
  AIFC_CHECK_ERR(none.register_flow(aifc_test::synthetic_flow_key(0U), aifc::FlowGeneration{1},
                                    session, 1),
                 aifc::ErrorCode::CAPACITY_EXCEEDED);

  // Unknown lookups.
  const aifc::FlowKey unknown_key = aifc_test::synthetic_flow_key(99U);
  AIFC_CHECK_ERR(registry.find_by_key(unknown_key), aifc::ErrorCode::UNKNOWN_FLOW);
  AIFC_CHECK_ERR(registry.find_by_id(aifc::derive_flow_id(unknown_key)),
                 aifc::ErrorCode::UNKNOWN_FLOW);
  AIFC_CHECK_ERR(registry.find_generation(aifc::derive_flow_id(unknown_key),
                                          aifc::FlowGeneration{1}),
                 aifc::ErrorCode::UNKNOWN_FLOW);
  const auto by_id = registry.find_by_id(aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U)));
  AIFC_CHECK_OK(by_id);
  if (by_id) {
    AIFC_CHECK_EQ(by_id.value().key.to_string(),
                  aifc_test::synthetic_flow_key(0U).to_string());
  }
  const auto wrong_generation =
      registry.find_generation(aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U)),
                               aifc::FlowGeneration{7});
  AIFC_CHECK_ERR(wrong_generation, aifc::ErrorCode::UNKNOWN_FLOW);

  // Retirement of something that is not there.
  AIFC_CHECK_ERR(registry.retire_flow(aifc::derive_flow_id(unknown_key), aifc::FlowGeneration{1}, 5), aifc::ErrorCode::UNKNOWN_FLOW);
  AIFC_CHECK_ERR(registry.retire_flow(aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U)),
                                    aifc::FlowGeneration{7}, 5), aifc::ErrorCode::UNKNOWN_FLOW);

  // Snapshot and restore: a restored flow is current again (the registry holds no authority;
  // the caller decides what a restored incarnation means).
  const std::vector<aifc::FlowRecord> snapshot = registry.snapshot_flows();
  AIFC_CHECK_EQ(snapshot.size(), std::size_t{2});
  aifc::FlowRegistry restored(2U);
  for (const aifc::FlowRecord& record : snapshot) {
    AIFC_CHECK_OK(restored.restore_flow(record));
  }
  AIFC_CHECK_EQ(restored.size(), std::size_t{2});
  const auto restored_record = restored.find_by_key(aifc_test::synthetic_flow_key(0U));
  AIFC_CHECK_OK(restored_record);
  if (restored_record) {
    AIFC_CHECK_EQ(restored_record.value().generation.value, 1U);
  }
  // Restoring a record for a key at a lower generation keeps it as history rather than
  // replacing the current incarnation.
  aifc::FlowRecord old_record = snapshot[0];
  old_record.generation = aifc::FlowGeneration{1};
  const aifc::FlowKey first_key = snapshot[0].key;
  AIFC_CHECK_OK(restored.register_flow(first_key, aifc::FlowGeneration{3}, session, 10));
  AIFC_CHECK_OK(restored.restore_flow(old_record));
  const auto still_current = restored.find_by_key(first_key);
  AIFC_CHECK_OK(still_current);
  if (still_current) {
    AIFC_CHECK_EQ(still_current.value().generation.value, 3U);
  }

  registry.clear();
  AIFC_CHECK_EQ(registry.size(), std::size_t{0});
  AIFC_CHECK_EQ(registry.stats().registrations, 0U);
}

// ---------------------------------------------------------------------------
// PublisherRegistry
// ---------------------------------------------------------------------------

AIFC_TEST("store/publisher_registry: boot advance and STALE_BOOT_ID (REAL)") {
  aifc::PublisherRegistry registry(8U, 100U);
  const aifc::PublisherId publisher = aifc_test::synthetic_publisher(0U);
  const aifc::CoordinatorEpoch epoch{1};
  const aifc::CoordinatorBootId coordinator_boot{1};

  const auto first = registry.bind_session(publisher, aifc::PublisherBootId{1}, epoch,
                                           coordinator_boot,
                                           aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                           aifc_test::synthetic_session(0U), 10, "first");
  AIFC_CHECK_OK(first);
  if (first) {
    AIFC_CHECK(first.value().state == aifc::PublisherState::LIVE);
    AIFC_CHECK_EQ(first.value().boot.value, 1U);
    AIFC_CHECK_EQ(first.value().sessions_opened, 1U);
    AIFC_CHECK_EQ(first.value().highest_generation.value, 0U);
    AIFC_CHECK(first.value().max_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  }
  AIFC_CHECK(registry.is_live(publisher, aifc::PublisherBootId{1}));
  AIFC_CHECK(!registry.is_live(publisher, aifc::PublisherBootId{2}));
  AIFC_CHECK(!registry.is_live(aifc_test::synthetic_publisher(1U), aifc::PublisherBootId{1}));
  AIFC_CHECK_EQ(registry.size(), std::size_t{1});
  AIFC_CHECK_EQ(registry.stats().registrations, 1U);

  // The same boot opening a second session is legal (a reconnect) and is counted.
  const auto reconnect = registry.bind_session(publisher, aifc::PublisherBootId{1}, epoch,
                                               coordinator_boot,
                                               aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                               aifc_test::synthetic_session(1U), 20, "reconnect");
  AIFC_CHECK_OK(reconnect);
  if (reconnect) {
    AIFC_CHECK_EQ(reconnect.value().sessions_opened, 2U);
    AIFC_CHECK_EQ(reconnect.value().session.value(), std::string("session-1"));
  }
  AIFC_CHECK_EQ(registry.stats().boot_advances, 0U);
  AIFC_CHECK_EQ(registry.stats().sessions_opened, 2U);

  // A strictly larger boot id is a new incarnation and resets the generation high water mark.
  AIFC_CHECK_OK(registry.observe_evidence_generation(publisher, aifc::PublisherBootId{1},
                                                 aifc::EvidenceGeneration{5}));
  const auto restarted = registry.bind_session(publisher, aifc::PublisherBootId{3}, epoch,
                                               coordinator_boot,
                                               aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                               aifc_test::synthetic_session(2U), 30, "restart");
  AIFC_CHECK_OK(restarted);
  if (restarted) {
    AIFC_CHECK_EQ(restarted.value().boot.value, 3U);
    AIFC_CHECK_EQ(restarted.value().highest_generation.value, 0U);
  }
  AIFC_CHECK_EQ(registry.stats().boot_advances, 1U);
  AIFC_CHECK(registry.is_live(publisher, aifc::PublisherBootId{3}));
  AIFC_CHECK(!registry.is_live(publisher, aifc::PublisherBootId{1}));
  AIFC_CHECK_OK(registry.observe_evidence_generation(publisher, aifc::PublisherBootId{3},
                                                 aifc::EvidenceGeneration{1}));

  // A lower boot id has already been superseded and must be refused before any state changes.
  const auto stale = registry.bind_session(publisher, aifc::PublisherBootId{2}, epoch,
                                           coordinator_boot,
                                           aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                           aifc_test::synthetic_session(3U), 40, "stale");
  AIFC_CHECK_ERR(stale, aifc::ErrorCode::STALE_BOOT_ID);
  if (!stale) {
    AIFC_CHECK_MSG(contains(stale.status().message, "boot 2") &&
                       contains(stale.status().message, "3"),
                   "the refusal must name both boots, got: " << stale.status().message);
  }
  AIFC_CHECK_EQ(registry.stats().replay_rejections, 1U);
  AIFC_CHECK(registry.is_live(publisher, aifc::PublisherBootId{3}));

  // Boot zero is not an incarnation.
  const auto zero = registry.bind_session(publisher, aifc::PublisherBootId{0}, epoch,
                                          coordinator_boot,
                                          aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                          aifc_test::synthetic_session(4U), 50, "zero");
  AIFC_CHECK_ERR(zero, aifc::ErrorCode::INVALID_ARGUMENT);

  const auto found = registry.find(publisher);
  AIFC_CHECK_OK(found);
  AIFC_CHECK_ERR(registry.find(aifc_test::synthetic_publisher(9U)),
                 aifc::ErrorCode::UNKNOWN_PUBLISHER);

  // Capacity is enforced on insert.
  aifc::PublisherRegistry tiny(1U, 100U);
  AIFC_CHECK_OK(tiny.bind_session(aifc_test::synthetic_publisher(0U), aifc::PublisherBootId{1},
                                  epoch, coordinator_boot,
                                  aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                  aifc_test::synthetic_session(0U), 1, "one"));
  AIFC_CHECK_ERR(tiny.bind_session(aifc_test::synthetic_publisher(1U), aifc::PublisherBootId{1},
                                   epoch, coordinator_boot,
                                   aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                   aifc_test::synthetic_session(1U), 1, "two"),
                 aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_EQ(tiny.stats().capacity_rejections, 1U);
}

AIFC_TEST("store/publisher_registry: observe_evidence_generation replay detection (REAL)") {
  aifc::PublisherRegistry registry(8U, 100U);
  const aifc::PublisherId publisher = aifc_test::synthetic_publisher(2U);
  AIFC_CHECK_OK(registry.bind_session(publisher, aifc::PublisherBootId{1},
                                      aifc::CoordinatorEpoch{1}, aifc::CoordinatorBootId{1},
                                      aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                      aifc_test::synthetic_session(0U), 1, "peer"));

  AIFC_CHECK_ERR(registry.observe_evidence_generation(publisher, aifc::PublisherBootId{1},
                                                    aifc::EvidenceGeneration{0}), aifc::ErrorCode::INVALID_ARGUMENT);
  AIFC_CHECK_OK(registry.observe_evidence_generation(publisher, aifc::PublisherBootId{1},
                                                 aifc::EvidenceGeneration{1}));

  // An equal generation is a replay of an accepted publication.
  const aifc::Status equal = registry.observe_evidence_generation(
      publisher, aifc::PublisherBootId{1}, aifc::EvidenceGeneration{1});
  AIFC_CHECK_ERR(equal, aifc::ErrorCode::REPLAY_DETECTED);
  AIFC_CHECK_MSG(contains(equal.message, "1"),
                 "the replay refusal must name the generation, got: " << equal.message);

  // A strictly larger generation is accepted and raises the mark.
  AIFC_CHECK_OK(registry.observe_evidence_generation(publisher, aifc::PublisherBootId{1},
                                                 aifc::EvidenceGeneration{4}));
  const aifc::Status lower = registry.observe_evidence_generation(
      publisher, aifc::PublisherBootId{1}, aifc::EvidenceGeneration{3});
  AIFC_CHECK_ERR(lower, aifc::ErrorCode::REPLAY_DETECTED);
  AIFC_CHECK_MSG(contains(lower.message, "4"),
                 "the replay refusal must name the high water mark, got: " << lower.message);
  AIFC_CHECK_EQ(registry.stats().replay_rejections, 2U);

  // The wrong boot incarnation, and an unknown publisher, are refused before the generation is
  // considered at all.
  AIFC_CHECK_ERR(registry.observe_evidence_generation(publisher, aifc::PublisherBootId{2},
                                                    aifc::EvidenceGeneration{9}), aifc::ErrorCode::STALE_BOOT_ID);
  AIFC_CHECK_ERR(registry.observe_evidence_generation(aifc_test::synthetic_publisher(3U),
                                                    aifc::PublisherBootId{1},
                                                    aifc::EvidenceGeneration{9}), aifc::ErrorCode::UNKNOWN_PUBLISHER);

  // The durable record carries the high water mark so a restart can fence replays.
  const std::vector<aifc::PublisherRecord> records = registry.snapshot_records();
  AIFC_CHECK_EQ(records.size(), std::size_t{1});
  if (records.size() == 1U) {
    AIFC_CHECK_EQ(records[0].highest_boot.value, 1U);
    AIFC_CHECK_EQ(records[0].highest_generation.value, 4U);
  }
}

AIFC_TEST("store/publisher_registry: liveness expiry, is_live exactness and session end (REAL)") {
  aifc::PublisherRegistry registry(8U, 10U);
  const aifc::PublisherId publisher = aifc_test::synthetic_publisher(0U);
  AIFC_CHECK_OK(registry.bind_session(publisher, aifc::PublisherBootId{1},
                                      aifc::CoordinatorEpoch{1}, aifc::CoordinatorBootId{1},
                                      aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                      aifc_test::synthetic_session(0U), 100, "peer"));

  // Exactly idle_ticks is still live; one tick more expires.
  AIFC_CHECK_EQ(registry.expire_liveness(110U), 0U);
  AIFC_CHECK(registry.is_live(publisher, aifc::PublisherBootId{1}));
  AIFC_CHECK_EQ(registry.stats().liveness_expirations, 0U);
  AIFC_CHECK_EQ(registry.expire_liveness(111U), 1U);
  AIFC_CHECK(!registry.is_live(publisher, aifc::PublisherBootId{1}));
  AIFC_CHECK_EQ(registry.stats().liveness_expirations, 1U);
  const auto expired = registry.find(publisher);
  AIFC_CHECK_OK(expired);
  if (expired) {
    AIFC_CHECK(expired.value().state == aifc::PublisherState::IDLE);
  }
  // Expiring again changes nothing: IDLE is not live, so it cannot expire twice.
  AIFC_CHECK_EQ(registry.expire_liveness(1000U), 0U);
  AIFC_CHECK_EQ(registry.stats().liveness_expirations, 1U);

  // Contact refreshes liveness.  A heartbeat is not evidence and creates no authority, but it
  // does return an existing session to LIVE.
  AIFC_CHECK_OK(registry.touch(publisher, aifc::PublisherBootId{1}, 120U));
  AIFC_CHECK(registry.is_live(publisher, aifc::PublisherBootId{1}));
  AIFC_CHECK_ERR(registry.touch(publisher, aifc::PublisherBootId{2}, 130U), aifc::ErrorCode::STALE_BOOT_ID);
  AIFC_CHECK_ERR(registry.touch(aifc_test::synthetic_publisher(5U), aifc::PublisherBootId{1}, 130U), aifc::ErrorCode::UNKNOWN_PUBLISHER);

  // Ending the session is explicit, not an inference, and it is boot exact.
  AIFC_CHECK_ERR(registry.end_session(publisher, aifc::PublisherBootId{2}, 200U), aifc::ErrorCode::STALE_BOOT_ID);
  AIFC_CHECK_OK(registry.end_session(publisher, aifc::PublisherBootId{1}, 200U));
  AIFC_CHECK(!registry.is_live(publisher, aifc::PublisherBootId{1}));
  const auto dead = registry.find(publisher);
  AIFC_CHECK_OK(dead);
  if (dead) {
    AIFC_CHECK(dead.value().state == aifc::PublisherState::DEAD);
    AIFC_CHECK(dead.value().session.empty());
  }
  // A dead session cannot be refreshed back to life by contact: only a new boot can.
  AIFC_CHECK_OK(registry.touch(publisher, aifc::PublisherBootId{1}, 210U));
  AIFC_CHECK_MSG(!registry.is_live(publisher, aifc::PublisherBootId{1}),
                 "touching a dead session must not restore liveness");
  AIFC_CHECK_EQ(registry.expire_liveness(9999U), 0U);
  // Ending an already ended session is idempotent rather than an error: the boot incarnation
  // still matches the registration, so the call is a no-op and the state stays DEAD.
  AIFC_CHECK_OK(registry.end_session(publisher, aifc::PublisherBootId{1}, 220U));
  const auto still_dead = registry.find(publisher);
  AIFC_CHECK_OK(still_dead);
  if (still_dead) {
    AIFC_CHECK(still_dead.value().state == aifc::PublisherState::DEAD);
  }
  AIFC_CHECK_ERR(registry.end_session(aifc_test::synthetic_publisher(6U), aifc::PublisherBootId{1},
                                    220U), aifc::ErrorCode::UNKNOWN_PUBLISHER);

  // A strictly higher boot brings the publisher back, and the old boot stays refused.
  const auto revived = registry.bind_session(publisher, aifc::PublisherBootId{2},
                                             aifc::CoordinatorEpoch{1},
                                             aifc::CoordinatorBootId{1},
                                             aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                             aifc_test::synthetic_session(1U), 300, "restart");
  AIFC_CHECK_OK(revived);
  AIFC_CHECK(registry.is_live(publisher, aifc::PublisherBootId{2}));
  AIFC_CHECK(!registry.is_live(publisher, aifc::PublisherBootId{1}));
  // Closing the session at the old incarnation is refused: the registration is at boot 2.
  AIFC_CHECK_ERR(registry.end_session(publisher, aifc::PublisherBootId{1}, 310U),
                 aifc::ErrorCode::STALE_BOOT_ID);
  AIFC_CHECK_ERR(registry.bind_session(publisher, aifc::PublisherBootId{1},
                                       aifc::CoordinatorEpoch{1}, aifc::CoordinatorBootId{1},
                                       aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                       aifc_test::synthetic_session(2U), 310, "old boot"),
                 aifc::ErrorCode::STALE_BOOT_ID);

  // require_revalidation drops the session and the liveness claim without inventing a new boot.
  AIFC_CHECK_OK(registry.require_revalidation(publisher));
  AIFC_CHECK(!registry.is_live(publisher, aifc::PublisherBootId{2}));
  AIFC_CHECK_ERR(registry.require_revalidation(aifc_test::synthetic_publisher(7U)), aifc::ErrorCode::UNKNOWN_PUBLISHER);
}

AIFC_TEST("store/publisher_registry: restore_records produces no live session (REAL)") {
  aifc::PublisherRegistry registry(4U, 100U);
  aifc::PublisherRecord record;
  record.id = aifc_test::synthetic_publisher(0U);
  record.highest_boot = aifc::PublisherBootId{4};
  record.highest_generation = aifc::EvidenceGeneration{7};
  record.max_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  record.first_seen_tick = 10;
  record.description = "restored";
  const std::vector<aifc::PublisherRecord> records{record};

  AIFC_CHECK_OK(registry.restore_records(records, 500));
  AIFC_CHECK_EQ(registry.size(), std::size_t{1});
  const auto found = registry.find(record.id);
  AIFC_CHECK_OK(found);
  if (found) {
    // Durable identity and the generation high water mark survive; liveness deliberately does
    // not, because a restart cannot resurrect a session it does not have.
    AIFC_CHECK_EQ(found.value().boot.value, 4U);
    AIFC_CHECK_EQ(found.value().highest_generation.value, 7U);
    AIFC_CHECK(found.value().state == aifc::PublisherState::IDLE);
    AIFC_CHECK(found.value().session.empty());
    AIFC_CHECK_EQ(found.value().last_seen_tick, aifc::kTickNone);
  }
  AIFC_CHECK_MSG(!registry.is_live(record.id, aifc::PublisherBootId{4}),
                 "a restored publisher must not be live");
  AIFC_CHECK_EQ(registry.expire_liveness(100000U), 0U);
  AIFC_CHECK(!registry.is_live(record.id, aifc::PublisherBootId{4}));

  // The volatile view lists the restored publisher as IDLE, not as absent and not as LIVE.
  const std::vector<aifc::PublisherRegistration> registrations = registry.registrations();
  AIFC_CHECK_EQ(registrations.size(), std::size_t{1});
  if (registrations.size() == 1U) {
    AIFC_CHECK(registrations[0].state == aifc::PublisherState::IDLE);
    AIFC_CHECK_EQ(registrations[0].id.value(), record.id.value());
  }

  // clear_sessions returns everything to a not-live state without losing the durable record.
  registry.clear_sessions();
  AIFC_CHECK(!registry.is_live(record.id, aifc::PublisherBootId{4}));
  AIFC_CHECK_EQ(registry.snapshot_records().size(), std::size_t{1});

  // Capacity is enforced while restoring.
  aifc::PublisherRegistry tiny(1U, 100U);
  AIFC_CHECK_OK(tiny.restore_records(records, 1));
  aifc::PublisherRecord second = record;
  second.id = aifc_test::synthetic_publisher(1U);
  AIFC_CHECK_ERR(tiny.restore_records({second}, 1), aifc::ErrorCode::CAPACITY_EXCEEDED);
  // Restoring a record that is already present is an update, not a new slot.
  AIFC_CHECK_OK(tiny.restore_records(records, 2));

  registry.clear();
  AIFC_CHECK_EQ(registry.size(), std::size_t{0});
}

// ---------------------------------------------------------------------------
// WorkloadRegistry
// ---------------------------------------------------------------------------

AIFC_TEST("store/workload_registry: declare, generation advance and contract retirement (REAL)") {
  aifc::WorkloadRegistry registry(8U, 8U, 8U);
  const aifc::PublisherId owner = aifc_test::synthetic_publisher(0U);
  const aifc::WorkloadId workload = aifc_test::synthetic_workload(0U);

  std::vector<aifc::WorkloadContract> retired;
  const auto declared = registry.declare_workload(workload, owner, aifc::WorkloadGeneration{1}, 10,
                                                  "first", &retired);
  AIFC_CHECK_OK(declared);
  if (declared) {
    AIFC_CHECK(declared.value().state == aifc::WorkloadState::ACTIVE);
    AIFC_CHECK_EQ(declared.value().generation.value, 1U);
    AIFC_CHECK_EQ(declared.value().owner.value(), owner.value());
  }
  AIFC_CHECK(retired.empty());
  AIFC_CHECK_EQ(registry.stats().workloads_declared, 1U);
  AIFC_CHECK_EQ(registry.workload_count(), std::size_t{1});

  // Re-declaring the same generation is a repeat that may update the description.
  const auto repeat = registry.declare_workload(workload, owner, aifc::WorkloadGeneration{1}, 11,
                                                "updated", &retired);
  AIFC_CHECK_OK(repeat);
  if (repeat) {
    AIFC_CHECK_EQ(repeat.value().description, std::string("updated"));
  }
  AIFC_CHECK_EQ(registry.stats().workloads_declared, 1U);

  // The workload must exist, own its identity and name a real generation.
  AIFC_CHECK_ERR(registry.declare_workload(workload, aifc_test::synthetic_publisher(1U),
                                         aifc::WorkloadGeneration{1}, 12, "stolen", &retired), aifc::ErrorCode::UNAUTHORIZED);
  AIFC_CHECK_EQ(registry.stats().contract_owner_rejections, 1U);
  AIFC_CHECK_ERR(registry.declare_workload(workload, owner, aifc::WorkloadGeneration{0}, 12, "zero",
                                         &retired), aifc::ErrorCode::INVALID_ARGUMENT);
  AIFC_CHECK_ERR(registry.declare_workload(aifc::WorkloadId{}, owner, aifc::WorkloadGeneration{1}, 12,
                                         "empty", &retired), aifc::ErrorCode::INVALID_ARGUMENT);

  // A contract bound to generation 1, activated, then a workload generation advance retires it
  // and reports it so the caller can stale the derived classifications.
  aifc::WorkloadContract contract = make_contract("contract-1", "workload-0", owner,
                                                  aifc::WorkloadGeneration{1});
  const auto proposed = registry.propose_contract(contract, 20);
  AIFC_CHECK_OK(proposed);
  if (proposed) {
    AIFC_CHECK(proposed.value().state == aifc::ContractState::PENDING);
    AIFC_CHECK(!proposed.value().definition_digest.is_zero());
    AIFC_CHECK_EQ(proposed.value().definition_digest.to_hex(),
                  aifc::compute_contract_digest(proposed.value()).to_hex());
  }
  aifc::WorkloadContract replaced;
  const auto activated =
      registry.activate_contract(contract.id, owner, 21, &replaced);
  AIFC_CHECK_OK(activated);
  if (activated) {
    AIFC_CHECK(activated.value().state == aifc::ContractState::ACTIVE);
  }
  AIFC_CHECK_EQ(registry.stats().contracts_activated, 1U);
  AIFC_CHECK_EQ(registry.stats().active_contracts, std::size_t{1});

  retired.clear();
  const auto advanced = registry.declare_workload(workload, owner, aifc::WorkloadGeneration{2}, 30,
                                                  "second", &retired);
  AIFC_CHECK_OK(advanced);
  AIFC_CHECK_EQ(retired.size(), std::size_t{1});
  if (retired.size() == 1U) {
    AIFC_CHECK_EQ(retired[0].id.value(), contract.id.value());
    AIFC_CHECK(retired[0].state == aifc::ContractState::RETIRED);
    AIFC_CHECK_EQ(retired[0].retired_tick, 30U);
  }
  AIFC_CHECK_EQ(registry.stats().contracts_retired, 1U);
  const auto after_advance = registry.find_contract(contract.id);
  AIFC_CHECK_OK(after_advance);
  if (after_advance) {
    AIFC_CHECK(after_advance.value().state == aifc::ContractState::RETIRED);
  }
  AIFC_CHECK_ERR(registry.activate_contract(contract.id, owner, 31, &replaced), aifc::ErrorCode::CONTRACT_RETIRED);
  AIFC_CHECK_ERR(registry.declare_workload(workload, owner, aifc::WorkloadGeneration{1}, 32, "back",
                                           &retired),
                 aifc::ErrorCode::STALE_GENERATION);
  AIFC_CHECK_ERR(registry.find_active_contract(workload, aifc::WorkloadGeneration{1}),
                 aifc::ErrorCode::UNKNOWN_CONTRACT);
  AIFC_CHECK_ERR(registry.find_workload(aifc_test::synthetic_workload(9U)),
                 aifc::ErrorCode::UNKNOWN_WORKLOAD);

  // Retirement is generation exact.
  AIFC_CHECK_ERR(registry.retire_workload(workload, aifc::WorkloadGeneration{1}, 40), aifc::ErrorCode::STALE_GENERATION);
  AIFC_CHECK_OK(registry.retire_workload(workload, aifc::WorkloadGeneration{2}, 41));
  const auto retired_workload = registry.find_workload(workload);
  AIFC_CHECK_OK(retired_workload);
  if (retired_workload) {
    AIFC_CHECK(retired_workload.value().state == aifc::WorkloadState::RETIRED);
  }
  AIFC_CHECK_ERR(registry.declare_workload(workload, owner, aifc::WorkloadGeneration{2}, 42,
                                           "resurrect", &retired),
                 aifc::ErrorCode::STALE_GENERATION);
}

AIFC_TEST("store/workload_registry: contract proposal refusals (REAL)") {
  aifc::WorkloadRegistry registry(8U, 8U, 2U);
  const aifc::PublisherId owner = aifc_test::synthetic_publisher(0U);
  const aifc::WorkloadId workload = aifc_test::synthetic_workload(0U);
  std::vector<aifc::WorkloadContract> retired;
  AIFC_CHECK_OK(registry.declare_workload(workload, owner, aifc::WorkloadGeneration{2}, 1, "w",
                                          &retired));

  aifc::WorkloadContract unknown_class = make_contract("contract-1", "workload-0", owner,
                                                       aifc::WorkloadGeneration{2});
  unknown_class.declared_class = aifc::SemanticClass::UNKNOWN;
  const auto unknown_result = registry.propose_contract(unknown_class, 2);
  AIFC_CHECK_ERR(unknown_result, aifc::ErrorCode::INVALID_ARGUMENT);
  if (!unknown_result) {
    AIFC_CHECK_MSG(contains(unknown_result.status().message, "UNKNOWN"),
                   "the refusal must name the UNKNOWN class, got: "
                       << unknown_result.status().message);
  }

  aifc::WorkloadContract unscoped = make_contract("contract-2", "workload-0", owner,
                                                  aifc::WorkloadGeneration{2});
  unscoped.match_any_remote_address = false;
  unscoped.remote_scope.clear();
  unscoped.local_port_scope.clear();
  unscoped.remote_port = 0;
  AIFC_CHECK_ERR(registry.propose_contract(unscoped, 2), aifc::ErrorCode::INVALID_ARGUMENT);

  aifc::WorkloadContract empty_id = make_contract("", "workload-0", owner,
                                                  aifc::WorkloadGeneration{2});
  AIFC_CHECK_ERR(registry.propose_contract(empty_id, 2), aifc::ErrorCode::INVALID_ARGUMENT);

  aifc::WorkloadContract zero_generation = make_contract("contract-3", "workload-0", owner,
                                                         aifc::WorkloadGeneration{0});
  AIFC_CHECK_ERR(registry.propose_contract(zero_generation, 2),
                 aifc::ErrorCode::INVALID_ARGUMENT);

  aifc::WorkloadContract unknown_workload = make_contract("contract-4", "workload-404", owner,
                                                          aifc::WorkloadGeneration{2});
  AIFC_CHECK_ERR(registry.propose_contract(unknown_workload, 2),
                 aifc::ErrorCode::UNKNOWN_WORKLOAD);

  aifc::WorkloadContract wrong_owner = make_contract("contract-5", "workload-0",
                                                     aifc_test::synthetic_publisher(1U),
                                                     aifc::WorkloadGeneration{2});
  const auto owner_result = registry.propose_contract(wrong_owner, 2);
  AIFC_CHECK_ERR(owner_result, aifc::ErrorCode::UNAUTHORIZED);
  if (!owner_result) {
    AIFC_CHECK_MSG(contains(owner_result.status().message, "workload-0"),
                   "the refusal must name the workload, got: " << owner_result.status().message);
  }

  aifc::WorkloadContract wrong_generation = make_contract("contract-6", "workload-0", owner,
                                                          aifc::WorkloadGeneration{1});
  AIFC_CHECK_ERR(registry.propose_contract(wrong_generation, 2),
                 aifc::ErrorCode::STALE_GENERATION);

  // Two valid proposals succeed, then the pending bound refuses the third.
  const auto first = registry.propose_contract(
      make_contract("contract-7", "workload-0", owner, aifc::WorkloadGeneration{2}), 3);
  AIFC_CHECK_OK(first);
  const auto second = registry.propose_contract(
      make_contract("contract-8", "workload-0", owner, aifc::WorkloadGeneration{2}), 4);
  AIFC_CHECK_OK(second);
  AIFC_CHECK_EQ(registry.stats().contracts_proposed, 2U);
  AIFC_CHECK_EQ(registry.contract_count(), std::size_t{2});
  const auto third = registry.propose_contract(
      make_contract("contract-9", "workload-0", owner, aifc::WorkloadGeneration{2}), 5);
  AIFC_CHECK_ERR(third, aifc::ErrorCode::CAPACITY_EXCEEDED);
  if (!third) {
    AIFC_CHECK_MSG(contains(third.status().message, "2"),
                   "the pending bound refusal must name the bound, got: "
                       << third.status().message);
  }

  // A duplicate identity is refused regardless of content: the registry never rewrites an
  // accepted definition in place.
  aifc::WorkloadContract duplicate = make_contract("contract-7", "workload-0", owner,
                                                   aifc::WorkloadGeneration{2});
  duplicate.declared_class = aifc::SemanticClass::TELEMETRY;
  AIFC_CHECK_ERR(registry.propose_contract(duplicate, 6), aifc::ErrorCode::ALREADY_EXISTS);
  const auto stored = registry.find_contract(aifc::make_contract_id("contract-7"));
  AIFC_CHECK_OK(stored);
  if (stored) {
    AIFC_CHECK(stored.value().declared_class == aifc::SemanticClass::COLLECTIVE);
  }
}

AIFC_TEST("store/workload_registry: activation, ownership and immutable active contracts (REAL)") {
  aifc::WorkloadRegistry registry(8U, 8U, 8U);
  const aifc::PublisherId owner = aifc_test::synthetic_publisher(0U);
  const aifc::PublisherId intruder = aifc_test::synthetic_publisher(1U);
  const aifc::WorkloadId workload = aifc_test::synthetic_workload(0U);
  std::vector<aifc::WorkloadContract> retired;
  AIFC_CHECK_OK(registry.declare_workload(workload, owner, aifc::WorkloadGeneration{3}, 1, "w",
                                          &retired));

  const aifc::WorkloadContract first_contract =
      make_contract("contract-1", "workload-0", owner, aifc::WorkloadGeneration{3});
  const aifc::WorkloadContract second_contract =
      make_contract("contract-2", "workload-0", owner, aifc::WorkloadGeneration{3});
  AIFC_CHECK_OK(registry.propose_contract(first_contract, 2));
  AIFC_CHECK_OK(registry.propose_contract(second_contract, 3));

  // A proposal has no authority until it is activated.
  AIFC_CHECK_ERR(registry.find_active_contract(workload, aifc::WorkloadGeneration{3}),
                 aifc::ErrorCode::UNKNOWN_CONTRACT);
  AIFC_CHECK_ERR(registry.activate_contract(aifc::make_contract_id("contract-404"), owner, 4,
                                            nullptr),
                 aifc::ErrorCode::UNKNOWN_CONTRACT);
  AIFC_CHECK_ERR(registry.activate_contract(first_contract.id, intruder, 5, nullptr),
                 aifc::ErrorCode::UNAUTHORIZED);
  AIFC_CHECK_ERR(registry.retire_contract(first_contract.id, intruder, 6),
                 aifc::ErrorCode::UNAUTHORIZED);

  aifc::WorkloadContract replaced;
  const auto active = registry.activate_contract(first_contract.id, owner, 7, &replaced);
  AIFC_CHECK_OK(active);
  AIFC_CHECK(replaced.id.empty());  // nothing was displaced
  if (active) {
    AIFC_CHECK(active.value().state == aifc::ContractState::ACTIVE);
    AIFC_CHECK_EQ(active.value().activated_tick, 7U);
  }
  const auto found_active = registry.find_active_contract(workload, aifc::WorkloadGeneration{3});
  AIFC_CHECK_OK(found_active);
  if (found_active) {
    AIFC_CHECK_EQ(found_active.value().id.value(), first_contract.id.value());
  }
  // Activating the active contract again is idempotent, not an error and not a second
  // activation.
  const auto reactivated = registry.activate_contract(first_contract.id, owner, 8, &replaced);
  AIFC_CHECK_OK(reactivated);
  AIFC_CHECK_EQ(registry.stats().contracts_activated, 1U);

  // An ACTIVE contract is immutable: its definition digest cannot change, and re-proposing the
  // same identity is refused outright.
  const auto stored_active = registry.find_contract(first_contract.id);
  AIFC_CHECK_OK(stored_active);
  const auto immutable = registry.propose_contract(
      make_contract("contract-1", "workload-0", owner, aifc::WorkloadGeneration{3}), 9);
  AIFC_CHECK_ERR(immutable, aifc::ErrorCode::ALREADY_EXISTS);
  AIFC_CHECK_MSG(contains(immutable.status().message, "contract-1"),
                 "the immutability refusal must name the contract, got: "
                     << immutable.status().message);
  // The active definition is also immutable across a restore: a persisted contract whose
  // recorded digest does not match its content is refused as corrupt state.  The tampering
  // happens in a registry of its own so that this check cannot disturb the live one.
  {
    aifc::WorkloadRegistry isolated(8U, 8U, 8U);
    std::vector<aifc::WorkloadContract> ignored;
    AIFC_CHECK_OK(isolated.declare_workload(workload, owner, aifc::WorkloadGeneration{3}, 1, "w",
                                            &ignored));
    AIFC_CHECK_OK(isolated.propose_contract(first_contract, 2));
    AIFC_CHECK_OK(isolated.activate_contract(first_contract.id, owner, 3, nullptr));
    const auto stored = isolated.find_contract(first_contract.id);
    AIFC_CHECK_OK(stored);
    if (stored) {
      aifc::WorkloadContract tampered = stored.value();
      // The content changes but the recorded digest does not: this is what a corrupted or
      // maliciously edited snapshot looks like.
      tampered.declared_class = aifc::SemanticClass::CHECKPOINT;
      AIFC_CHECK_MSG(tampered.definition_digest != aifc::compute_contract_digest(tampered),
                     "the tampered definition must not match its recorded digest");
      AIFC_CHECK_ERR(isolated.restore_contract(tampered), aifc::ErrorCode::CORRUPT_STATE);
      const auto unchanged = isolated.find_contract(first_contract.id);
      AIFC_CHECK_OK(unchanged);
      if (unchanged) {
        AIFC_CHECK(unchanged.value().declared_class == aifc::SemanticClass::COLLECTIVE);
        AIFC_CHECK(unchanged.value().state == aifc::ContractState::ACTIVE);
      }
    }
  }

  // Activating a second contract for the same workload retires the first and reports it.
  replaced = aifc::WorkloadContract{};
  const auto second_active = registry.activate_contract(second_contract.id, owner, 10, &replaced);
  AIFC_CHECK_OK(second_active);
  AIFC_CHECK_EQ(replaced.id.value(), first_contract.id.value());
  AIFC_CHECK(replaced.state == aifc::ContractState::RETIRED);
  AIFC_CHECK_EQ(registry.stats().contracts_retired, 1U);
  const auto now_active = registry.find_active_contract(workload, aifc::WorkloadGeneration{3});
  AIFC_CHECK_OK(now_active);
  if (now_active) {
    AIFC_CHECK_EQ(now_active.value().id.value(), second_contract.id.value());
  }
  AIFC_CHECK_EQ(registry.active_contracts().size(), std::size_t{1});

  // A contract for a different generation is not the active contract for this one.
  AIFC_CHECK_ERR(registry.find_active_contract(workload, aifc::WorkloadGeneration{4}),
                 aifc::ErrorCode::UNKNOWN_CONTRACT);

  // Retirement is owner checked and is not reversible.
  AIFC_CHECK_ERR(registry.retire_contract(second_contract.id, intruder, 11), aifc::ErrorCode::UNAUTHORIZED);
  AIFC_CHECK_OK(registry.retire_contract(second_contract.id, owner, 12));
  AIFC_CHECK_ERR(registry.find_active_contract(workload, aifc::WorkloadGeneration{3}),
                 aifc::ErrorCode::UNKNOWN_CONTRACT);
  AIFC_CHECK_ERR(registry.activate_contract(second_contract.id, owner, 13, &replaced), aifc::ErrorCode::CONTRACT_RETIRED);

  // A contract whose workload was retired cannot be activated either.
  const aifc::WorkloadContract third_contract =
      make_contract("contract-3", "workload-0", owner, aifc::WorkloadGeneration{3});
  AIFC_CHECK_OK(registry.propose_contract(third_contract, 14));
  AIFC_CHECK_OK(registry.retire_workload(workload, aifc::WorkloadGeneration{3}, 15));
  AIFC_CHECK_ERR(registry.activate_contract(third_contract.id, owner, 16, &replaced), aifc::ErrorCode::CONTRACT_RETIRED);
}

// ---------------------------------------------------------------------------
// EvidenceStore
// ---------------------------------------------------------------------------

AIFC_TEST("store/evidence_store: insert, idempotent repeat and DUPLICATE_IDENTITY (REAL)") {
  aifc::EvidenceStore store(16U, 8U, 16U);
  const aifc::FlowId flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U));
  const aifc::EvidenceRecord record =
      make_evidence("ev-0000000000000001", flow, aifc::FlowGeneration{1},
                    aifc::SemanticClass::COLLECTIVE, aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);

  AIFC_CHECK_OK(store.insert(record));
  AIFC_CHECK_EQ(store.size(), std::size_t{1});
  AIFC_CHECK_EQ(store.stats().accepted, 1U);
  AIFC_CHECK_EQ(store.stats().records, std::size_t{1});
  AIFC_CHECK_EQ(store.stats().indexed_flows, std::size_t{1});
  const auto found = store.find(record.id);
  AIFC_CHECK_OK(found);
  if (found) {
    AIFC_CHECK_EQ(found.value().content_digest.to_hex(), record.content_digest.to_hex());
    AIFC_CHECK(found.value().state == aifc::EvidenceState::EVIDENCE_CURRENT);
  }

  // An identical repeat is idempotent: the earlier acknowledgement stands.
  AIFC_CHECK_OK(store.insert(record));
  AIFC_CHECK_EQ(store.size(), std::size_t{1});
  AIFC_CHECK_EQ(store.stats().accepted, 1U);

  // The same identity with different content is refused rather than replaced.
  aifc::EvidenceRecord different = record;
  different.semantic = aifc::SemanticClass::TELEMETRY;
  different.content_digest = aifc::compute_evidence_digest(different);
  const aifc::Status duplicate = store.insert(different);
  AIFC_CHECK_ERR(duplicate, aifc::ErrorCode::DUPLICATE_IDENTITY);
  AIFC_CHECK_MSG(contains(duplicate.message, record.id.value()),
                 "the refusal must name the identity, got: " << duplicate.message);
  AIFC_CHECK_EQ(store.stats().rejected, 1U);
  AIFC_CHECK_EQ(store.size(), std::size_t{1});
  const auto unchanged = store.find(record.id);
  AIFC_CHECK_OK(unchanged);
  if (unchanged) {
    AIFC_CHECK(unchanged.value().semantic == aifc::SemanticClass::COLLECTIVE);
  }

  // The same identity and content claimed by a different publisher is also a collision.
  aifc::EvidenceRecord other_publisher = record;
  other_publisher.publisher = aifc::make_publisher_id("publisher-2");
  AIFC_CHECK_ERR(store.insert(other_publisher), aifc::ErrorCode::DUPLICATE_IDENTITY);
  AIFC_CHECK_EQ(store.stats().rejected, 2U);

  // An empty identity is not a record.
  aifc::EvidenceRecord empty = record;
  empty.id = aifc::EvidenceId{};
  AIFC_CHECK_ERR(store.insert(empty), aifc::ErrorCode::INVALID_ARGUMENT);

  // Unknown lookups.
  AIFC_CHECK_ERR(store.find(aifc::make_evidence_id("ev-unknown")), aifc::ErrorCode::NOT_FOUND);
  const auto none = store.evidence_for_flow(aifc::derive_flow_id(aifc_test::synthetic_flow_key(9U)));
  AIFC_CHECK_OK(none);
  if (none) {
    AIFC_CHECK(none.value().empty());
  }

  // Per flow ordering is acceptance order, not insertion order.
  const aifc::EvidenceRecord later =
      make_evidence("ev-0000000000000002", flow, aifc::FlowGeneration{1},
                    aifc::SemanticClass::TELEMETRY, aifc::EvidenceSource::DECLARED_AUTHENTICATED, 2);
  const aifc::EvidenceRecord earlier =
      make_evidence("ev-0000000000000003", flow, aifc::FlowGeneration{1},
                    aifc::SemanticClass::CHECKPOINT, aifc::EvidenceSource::DECLARED_AUTHENTICATED, 0);
  AIFC_CHECK_OK(store.insert(later));
  AIFC_CHECK_OK(store.insert(earlier));
  const auto ids = store.evidence_for_flow(flow);
  AIFC_CHECK_OK(ids);
  if (ids) {
    AIFC_CHECK_EQ(ids.value().size(), std::size_t{3});
    if (ids.value().size() == 3U) {
      AIFC_CHECK_EQ(ids.value()[0].value(), std::string("ev-0000000000000003"));
      AIFC_CHECK_EQ(ids.value()[1].value(), std::string("ev-0000000000000001"));
      AIFC_CHECK_EQ(ids.value()[2].value(), std::string("ev-0000000000000002"));
    }
  }
}

AIFC_TEST("store/evidence_store: per-flow ring and global ring eviction (REAL)") {
  // The per flow ring drops the oldest id from the flow index while the record itself stays in
  // the store until the global ring reaches it.
  aifc::EvidenceStore per_flow(64U, 2U, 16U);
  const aifc::FlowId flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U));
  for (aifc::Seq seq = 1; seq <= 3U; ++seq) {
    const std::string id = "ev-000000000000000" + std::to_string(seq);
    AIFC_CHECK_OK(per_flow.insert(make_evidence(id, flow, aifc::FlowGeneration{1},
                                            aifc::SemanticClass::COLLECTIVE,
                                            aifc::EvidenceSource::DECLARED_AUTHENTICATED, seq)));
  }
  AIFC_CHECK_EQ(per_flow.size(), std::size_t{3});
  AIFC_CHECK_EQ(per_flow.stats().evicted_per_flow, 1U);
  const auto ids = per_flow.evidence_for_flow(flow);
  AIFC_CHECK_OK(ids);
  if (ids) {
    AIFC_CHECK_EQ(ids.value().size(), std::size_t{2});
    if (ids.value().size() == 2U) {
      AIFC_CHECK_EQ(ids.value()[0].value(), std::string("ev-0000000000000002"));
      AIFC_CHECK_EQ(ids.value()[1].value(), std::string("ev-0000000000000003"));
    }
  }
  // The evicted id is unreachable from its flow but still present in the store.
  AIFC_CHECK_OK(per_flow.find(aifc::make_evidence_id("ev-0000000000000001")));

  // The global ring evicts the oldest accepted record and reports it.
  aifc::EvidenceStore global(2U, 8U, 16U);
  std::vector<aifc::FlowId> flows;
  for (std::uint32_t index = 0; index < 3U; ++index) {
    flows.push_back(aifc::derive_flow_id(aifc_test::synthetic_flow_key(index)));
    const std::string id = "ev-000000000000001" + std::to_string(index);
    AIFC_CHECK_OK(global.insert(make_evidence(id, flows.back(), aifc::FlowGeneration{1},
                                          aifc::SemanticClass::COLLECTIVE,
                                          aifc::EvidenceSource::DECLARED_AUTHENTICATED, index + 1U)));
  }
  AIFC_CHECK_EQ(global.size(), std::size_t{2});
  AIFC_CHECK_EQ(global.stats().evicted_records, 1U);
  AIFC_CHECK_ERR(global.find(aifc::make_evidence_id("ev-0000000000000010")),
                 aifc::ErrorCode::NOT_FOUND);
  const auto evicted_flow = global.evidence_for_flow(flows[0]);
  AIFC_CHECK_OK(evicted_flow);
  if (evicted_flow) {
    AIFC_CHECK_MSG(evicted_flow.value().empty(),
                   "the evicted record must be removed from its flow index too");
  }
  // The surviving records are still reachable.
  AIFC_CHECK_OK(global.find(aifc::make_evidence_id("ev-0000000000000011")));
  AIFC_CHECK_OK(global.find(aifc::make_evidence_id("ev-0000000000000012")));

  // A zero capacity store refuses every insert rather than growing without bound.
  aifc::EvidenceStore none(0U, 8U, 16U);
  AIFC_CHECK_ERR(none.insert(make_evidence("ev-0000000000000001", flow, aifc::FlowGeneration{1},
                                           aifc::SemanticClass::COLLECTIVE,
                                           aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1)),
                 aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_EQ(none.stats().capacity_rejections, 1U);

  // The flow index is bounded separately, and the refusal happens before the record is stored.
  aifc::EvidenceStore indexed(64U, 8U, 1U);
  AIFC_CHECK_OK(indexed.insert(make_evidence("ev-0000000000000001", flows[0], aifc::FlowGeneration{1},
                                         aifc::SemanticClass::COLLECTIVE,
                                         aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1)));
  const aifc::Status second_flow =
      indexed.insert(make_evidence("ev-0000000000000002", flows[1], aifc::FlowGeneration{1},
                                   aifc::SemanticClass::COLLECTIVE,
                                   aifc::EvidenceSource::DECLARED_AUTHENTICATED, 2));
  AIFC_CHECK_ERR(second_flow, aifc::ErrorCode::CAPACITY_EXCEEDED);
  AIFC_CHECK_MSG(contains(second_flow.message, "1"),
                 "the flow index refusal must name the bound, got: " << second_flow.message);
  AIFC_CHECK_EQ(indexed.size(), std::size_t{1});
  AIFC_CHECK_EQ(indexed.stats().capacity_rejections, 1U);
}

AIFC_TEST("store/evidence_store: set_state, epoch staleness and restore (REAL)") {
  aifc::EvidenceStore store(16U, 8U, 16U);
  const aifc::FlowId flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U));
  const aifc::EvidenceRecord record =
      make_evidence("ev-0000000000000001", flow, aifc::FlowGeneration{1},
                    aifc::SemanticClass::COLLECTIVE, aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  AIFC_CHECK_OK(store.insert(record));

  AIFC_CHECK_ERR(store.set_state(aifc::make_evidence_id("ev-unknown"),
                               aifc::EvidenceState::EVIDENCE_STALE, "no such record", 1), aifc::ErrorCode::NOT_FOUND);

  // Setting the same state again is a no-op rather than an error.
  AIFC_CHECK_OK(store.set_state(record.id, aifc::EvidenceState::EVIDENCE_CURRENT, "still current", 2));
  AIFC_CHECK_EQ(store.stats().stale_transitions, 0U);

  AIFC_CHECK_OK(store.set_state(record.id, aifc::EvidenceState::EVIDENCE_STALE,
                            "publisher session ended", 3));
  AIFC_CHECK_EQ(store.stats().stale_transitions, 1U);
  const auto staled = store.find(record.id);
  AIFC_CHECK_OK(staled);
  if (staled) {
    AIFC_CHECK(staled.value().state == aifc::EvidenceState::EVIDENCE_STALE);
    AIFC_CHECK_EQ(staled.value().state_reason, std::string("publisher session ended"));
    // A state change never rewrites the freshness deadline.
    AIFC_CHECK_EQ(staled.value().fresh_until, record.fresh_until);
  }

  // A record may not be returned to CURRENT: re-establishing authority requires a new
  // publication with a new generation, never a state edit.
  const auto resurrect = store.set_state(record.id, aifc::EvidenceState::EVIDENCE_CURRENT,
                                         "please come back", 4);
  AIFC_CHECK_ERR(resurrect, aifc::ErrorCode::UNAUTHORIZED);
  if (!resurrect) {
    AIFC_CHECK_MSG(contains(resurrect.message, record.id.value()),
                   "the refusal must name the record, got: " << resurrect.message);
  }
  const auto still_stale = store.find(record.id);
  AIFC_CHECK_OK(still_stale);
  if (still_stale) {
    AIFC_CHECK(still_stale.value().state == aifc::EvidenceState::EVIDENCE_STALE);
  }

  AIFC_CHECK_OK(store.set_state(record.id, aifc::EvidenceState::EVIDENCE_REVOKED, "revoked", 5));
  AIFC_CHECK_EQ(store.stats().withdrawn, 1U);
  AIFC_CHECK_OK(store.set_state(record.id, aifc::EvidenceState::EVIDENCE_SUPERSEDED, "withdrawn", 6));
  AIFC_CHECK_EQ(store.stats().superseded, 1U);
  AIFC_CHECK_OK(store.set_state(record.id, aifc::EvidenceState::EVIDENCE_REVOKED, "revoked again", 7));
  AIFC_CHECK_EQ(store.stats().withdrawn, 2U);

  // Epoch advance: every record accepted in another epoch is marked stale with a reason that
  // names both epochs; a record already stale is not counted again.
  aifc::EvidenceStore epoch_store(16U, 8U, 16U);
  aifc::EvidenceRecord old_epoch =
      make_evidence("ev-0000000000000001", flow, aifc::FlowGeneration{1},
                    aifc::SemanticClass::COLLECTIVE, aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  old_epoch.accepted_epoch = aifc::CoordinatorEpoch{1};
  aifc::EvidenceRecord current_epoch = make_evidence(
      "ev-0000000000000002", flow, aifc::FlowGeneration{1}, aifc::SemanticClass::TELEMETRY,
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 2);
  current_epoch.accepted_epoch = aifc::CoordinatorEpoch{2};
  aifc::EvidenceRecord already_stale = make_evidence(
      "ev-0000000000000003", flow, aifc::FlowGeneration{1}, aifc::SemanticClass::CHECKPOINT,
      aifc::EvidenceSource::DECLARED_AUTHENTICATED, 3);
  already_stale.accepted_epoch = aifc::CoordinatorEpoch{1};
  already_stale.state = aifc::EvidenceState::EVIDENCE_STALE;
  AIFC_CHECK_OK(epoch_store.insert(old_epoch));
  AIFC_CHECK_OK(epoch_store.insert(current_epoch));
  AIFC_CHECK_OK(epoch_store.insert(already_stale));

  AIFC_CHECK_EQ(epoch_store.mark_epoch_stale(aifc::CoordinatorEpoch{2}, 10), 1U);
  AIFC_CHECK_EQ(epoch_store.stats().revalidation_transitions, 1U);
  const auto marked = epoch_store.find(old_epoch.id);
  AIFC_CHECK_OK(marked);
  if (marked) {
    AIFC_CHECK(marked.value().state == aifc::EvidenceState::EVIDENCE_STALE);
    AIFC_CHECK_MSG(contains(marked.value().state_reason, "epoch 1") &&
                       contains(marked.value().state_reason, "epoch 2"),
                   "the epoch staleness reason must name both epochs, got: "
                       << marked.value().state_reason);
  }
  const auto untouched = epoch_store.find(current_epoch.id);
  AIFC_CHECK_OK(untouched);
  if (untouched) {
    AIFC_CHECK(untouched.value().state == aifc::EvidenceState::EVIDENCE_CURRENT);
  }
  AIFC_CHECK_EQ(epoch_store.mark_epoch_stale(aifc::CoordinatorEpoch{2}, 11), 0U);

  // mark_stale_by_predicate only touches records that are still current.
  aifc::EvidenceStore predicate_store(16U, 8U, 16U);
  AIFC_CHECK_OK(predicate_store.insert(old_epoch));
  AIFC_CHECK_EQ(predicate_store.mark_stale_by_predicate(
                    [](const aifc::EvidenceRecord& candidate) {
                      return candidate.id.value() == "ev-0000000000000001";
                    },
                    "swept by predicate", 12),
                1U);
  AIFC_CHECK_EQ(predicate_store.mark_stale_by_predicate(
                    [](const aifc::EvidenceRecord&) { return true; }, "swept again", 13),
                0U);

  // Restore: currentness never survives a process boundary.
  aifc::EvidenceStore restored(16U, 8U, 16U);
  aifc::EvidenceRecord from_disk =
      make_evidence("ev-0000000000000001", flow, aifc::FlowGeneration{1},
                    aifc::SemanticClass::COLLECTIVE, aifc::EvidenceSource::DECLARED_AUTHENTICATED, 1);
  from_disk.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  AIFC_CHECK_OK(restored.restore_record(from_disk));
  const auto reloaded = restored.find(from_disk.id);
  AIFC_CHECK_OK(reloaded);
  if (reloaded) {
    AIFC_CHECK_MSG(reloaded.value().state == aifc::EvidenceState::EVIDENCE_STALE,
                   "a restored CURRENT record must become STALE, not "
                       << aifc::to_string(reloaded.value().state));
    AIFC_CHECK_MSG(contains(reloaded.value().state_reason, "durable"),
                   "the restored record must say why it is stale, got: "
                       << reloaded.value().state_reason);
  }
  // A record that was already REVOKED stays REVOKED: restoring does not weaken a denial.
  aifc::EvidenceRecord revoked_on_disk =
      make_evidence("ev-0000000000000002", flow, aifc::FlowGeneration{1},
                    aifc::SemanticClass::TELEMETRY, aifc::EvidenceSource::DECLARED_AUTHENTICATED, 2);
  revoked_on_disk.state = aifc::EvidenceState::EVIDENCE_REVOKED;
  revoked_on_disk.state_reason = "revoked before the restart";
  AIFC_CHECK_OK(restored.restore_record(revoked_on_disk));
  const auto reloaded_revoked = restored.find(revoked_on_disk.id);
  AIFC_CHECK_OK(reloaded_revoked);
  if (reloaded_revoked) {
    AIFC_CHECK(reloaded_revoked.value().state == aifc::EvidenceState::EVIDENCE_REVOKED);
    AIFC_CHECK_EQ(reloaded_revoked.value().state_reason, std::string("revoked before the restart"));
  }
  // Restoring the same identity twice is refused.
  AIFC_CHECK_ERR(restored.restore_record(from_disk), aifc::ErrorCode::DUPLICATE_IDENTITY);
  // Capacity is enforced while restoring.
  aifc::EvidenceStore tiny(1U, 8U, 16U);
  AIFC_CHECK_OK(tiny.restore_record(from_disk));
  AIFC_CHECK_ERR(tiny.restore_record(revoked_on_disk), aifc::ErrorCode::CAPACITY_EXCEEDED);
  // Snapshots are ordered by identity so two runs agree.
  const std::vector<aifc::EvidenceRecord> snapshot = restored.snapshot_records();
  AIFC_CHECK_EQ(snapshot.size(), std::size_t{2});
  if (snapshot.size() == 2U) {
    AIFC_CHECK(snapshot[0].id < snapshot[1].id);
  }
  restored.clear();
  AIFC_CHECK_EQ(restored.size(), std::size_t{0});
}

// ---------------------------------------------------------------------------
// ClassificationIndex
// ---------------------------------------------------------------------------

AIFC_TEST("store/classification_index: history is per flow and generation (REAL)") {
  aifc::ClassificationIndex index(2U, 8U, 4U, 4U, 4U);
  const aifc::FlowId flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U));
  const aifc::FlowId other_flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(1U));
  const aifc::FlowGeneration first_generation{1};
  const aifc::FlowGeneration second_generation{2};

  // A first decision has no predecessor.
  const auto no_predecessor =
      index.record(make_classification(flow, first_generation, aifc::SemanticClass::COLLECTIVE));
  AIFC_CHECK_OK(no_predecessor);
  if (no_predecessor) {
    AIFC_CHECK_MSG(no_predecessor.value().flow_id.is_zero(),
                   "the first decision for a generation must not report a predecessor");
  }
  AIFC_CHECK_EQ(index.stats().decisions_recorded, 1U);
  AIFC_CHECK_EQ(index.history_flows(), std::size_t{1});

  // The second decision for the same generation reports the first as superseded.
  const auto predecessor =
      index.record(make_classification(flow, first_generation, aifc::SemanticClass::TELEMETRY));
  AIFC_CHECK_OK(predecessor);
  if (predecessor) {
    AIFC_CHECK_EQ(predecessor.value().flow_id.to_hex(), flow.to_hex());
    AIFC_CHECK(predecessor.value().semantic == aifc::SemanticClass::COLLECTIVE);
  }

  // History is generation bound: a decision for another generation is not a predecessor and is
  // not returned as the latest for this one.
  const auto other_generation =
      index.record(make_classification(flow, second_generation, aifc::SemanticClass::CHECKPOINT));
  AIFC_CHECK_OK(other_generation);
  if (other_generation) {
    AIFC_CHECK_MSG(other_generation.value().flow_id.is_zero(),
                   "a decision for another generation must not be reported as a predecessor");
  }
  const auto latest_first = index.latest(flow, first_generation);
  AIFC_CHECK_OK(latest_first);
  if (latest_first) {
    AIFC_CHECK(latest_first.value().semantic == aifc::SemanticClass::TELEMETRY);
  }
  const auto latest_second = index.latest(flow, second_generation);
  AIFC_CHECK_OK(latest_second);
  if (latest_second) {
    AIFC_CHECK(latest_second.value().semantic == aifc::SemanticClass::CHECKPOINT);
  }
  AIFC_CHECK_ERR(index.latest(flow, aifc::FlowGeneration{9}), aifc::ErrorCode::NOT_FOUND);
  AIFC_CHECK_ERR(index.latest(other_flow, first_generation), aifc::ErrorCode::NOT_FOUND);

  // The per generation history is bounded and the eviction is counted.
  AIFC_CHECK_OK(index.record(make_classification(flow, first_generation,
                                                 aifc::SemanticClass::INFERENCE_REQUEST)));
  AIFC_CHECK_OK(index.record(make_classification(flow, first_generation,
                                                 aifc::SemanticClass::STORAGE_DATA)));
  // The bound is per flow, not per generation, so it has already evicted the oldest entries
  // each time a decision pushed the deque past two: three pushes were over the bound.
  AIFC_CHECK_EQ(index.stats().history_evictions, 3U);
  const auto bounded = index.latest(flow, first_generation);
  AIFC_CHECK_OK(bounded);
  if (bounded) {
    AIFC_CHECK(bounded.value().semantic == aifc::SemanticClass::STORAGE_DATA);
  }

  // A zero capacity history keeps nothing, which is "refuse to remember" rather than
  // "remember without bound".
  aifc::ClassificationIndex no_history(0U, 8U, 4U, 4U, 4U);
  AIFC_CHECK_OK(no_history.record(
      make_classification(flow, first_generation, aifc::SemanticClass::COLLECTIVE)));
  AIFC_CHECK_EQ(no_history.stats().history_evictions, 1U);
  AIFC_CHECK_ERR(no_history.latest(flow, first_generation), aifc::ErrorCode::NOT_FOUND);

  // Snapshots are ordered by (flow, generation) and restoring rebuilds history only.
  const std::vector<aifc::Classification> snapshot = index.snapshot_classifications();
  AIFC_CHECK_EQ(snapshot.size(), std::size_t{2});
  aifc::ClassificationIndex restored(8U, 8U, 4U, 4U, 4U);
  for (const aifc::Classification& classification : snapshot) {
    AIFC_CHECK_OK(restored.restore_classification(classification));
  }
  const auto restored_latest = restored.latest(flow, first_generation);
  AIFC_CHECK_OK(restored_latest);
  if (restored_latest) {
    AIFC_CHECK(restored_latest.value().semantic == aifc::SemanticClass::STORAGE_DATA);
  }
  AIFC_CHECK_EQ(restored.memo_entries(), std::size_t{0});
  index.clear();
  AIFC_CHECK_EQ(index.history_flows(), std::size_t{0});
  AIFC_CHECK_EQ(index.stats().decisions_recorded, 0U);
}

AIFC_TEST("store/classification_index: memo hit, miss and eviction (REAL)") {
  aifc::ClassificationIndex index(4U, 2U, 4U, 4U, 4U);
  const aifc::FlowId flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U));

  aifc::DecisionKey key;
  key.flow_id = flow;
  key.flow_generation = aifc::FlowGeneration{1};
  key.evidence_digest = digest_of("evidence-set-1");
  key.policy_generation = aifc::ClassifierPolicyGeneration{1};

  aifc::Classification out;
  AIFC_CHECK_MSG(!index.memo_lookup(key, out), "an empty memo must miss");
  AIFC_CHECK_EQ(index.stats().memo_misses, 1U);

  const aifc::Classification stored = make_classification(flow, aifc::FlowGeneration{1},
                                                          aifc::SemanticClass::COLLECTIVE);
  index.memo_store(key, stored);
  AIFC_CHECK_EQ(index.memo_entries(), std::size_t{1});
  AIFC_CHECK(index.memo_lookup(key, out));
  AIFC_CHECK_EQ(index.stats().memo_hits, 1U);
  AIFC_CHECK(out.semantic == aifc::SemanticClass::COLLECTIVE);
  AIFC_CHECK_EQ(out.selected_evidence.value(), stored.selected_evidence.value());

  // Every field of the key participates, so a memo entry can never be returned for a different
  // question.
  aifc::DecisionKey other_generation = key;
  other_generation.flow_generation = aifc::FlowGeneration{2};
  AIFC_CHECK_MSG(!index.memo_lookup(other_generation, out),
                 "a different flow generation must not hit the memo");
  aifc::DecisionKey other_digest = key;
  other_digest.evidence_digest = digest_of("evidence-set-2");
  AIFC_CHECK_MSG(!index.memo_lookup(other_digest, out),
                 "a different evidence set must not hit the memo");
  aifc::DecisionKey other_policy = key;
  other_policy.policy_generation = aifc::ClassifierPolicyGeneration{2};
  AIFC_CHECK_MSG(!index.memo_lookup(other_policy, out),
                 "a different policy generation must not hit the memo");
  aifc::DecisionKey other_flow = key;
  other_flow.flow_id = aifc::derive_flow_id(aifc_test::synthetic_flow_key(1U));
  AIFC_CHECK_MSG(!index.memo_lookup(other_flow, out), "a different flow must not hit the memo");

  // Storing an existing key updates it in place rather than growing the memo.
  index.memo_store(key, make_classification(flow, aifc::FlowGeneration{1},
                                            aifc::SemanticClass::TELEMETRY));
  AIFC_CHECK_EQ(index.memo_entries(), std::size_t{1});
  AIFC_CHECK(index.memo_lookup(key, out));
  AIFC_CHECK(out.semantic == aifc::SemanticClass::TELEMETRY);

  // Eviction is oldest-first and is counted.  The memo has no authority, so an eviction costs
  // only a recomputation.
  index.memo_store(other_generation, stored);
  AIFC_CHECK_EQ(index.memo_entries(), std::size_t{2});
  index.memo_store(other_digest, stored);
  AIFC_CHECK_EQ(index.memo_entries(), std::size_t{2});
  AIFC_CHECK_EQ(index.stats().memo_evictions, 1U);
  AIFC_CHECK_MSG(!index.memo_lookup(key, out), "the oldest memo entry must have been evicted");
  AIFC_CHECK(index.memo_lookup(other_generation, out));
  AIFC_CHECK(index.memo_lookup(other_digest, out));

  // A zero capacity memo stores nothing and always misses.
  aifc::ClassificationIndex no_memo(4U, 0U, 4U, 4U, 4U);
  no_memo.memo_store(key, stored);
  AIFC_CHECK_EQ(no_memo.memo_entries(), std::size_t{0});
  AIFC_CHECK(!no_memo.memo_lookup(key, out));
}

AIFC_TEST("store/classification_index: revocations, contradictions and supersession (REAL)") {
  aifc::ClassificationIndex index(4U, 8U, 2U, 1U, 1U);
  const aifc::FlowId flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(0U));
  const aifc::FlowId other_flow = aifc::derive_flow_id(aifc_test::synthetic_flow_key(1U));
  const aifc::FlowGeneration generation{1};

  // Contradictions recorded directly and through a classification.
  aifc::ClassificationContradiction contradiction;
  contradiction.left_id = aifc::make_evidence_id("ev-left");
  contradiction.right_id = aifc::make_evidence_id("ev-right");
  contradiction.left_class = aifc::SemanticClass::COLLECTIVE;
  contradiction.right_class = aifc::SemanticClass::TELEMETRY;
  contradiction.left_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  contradiction.right_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  contradiction.resolved_by = "synthetic";
  AIFC_CHECK_OK(index.record_contradiction(flow, contradiction, 1));
  const auto contradictions = index.contradictions_for(flow);
  AIFC_CHECK_OK(contradictions);
  if (contradictions) {
    AIFC_CHECK_EQ(contradictions.value().size(), std::size_t{1});
    if (contradictions.value().size() == 1U) {
      AIFC_CHECK_EQ(contradictions.value()[0].left_id.value(), std::string("ev-left"));
    }
  }
  const auto none_for_other = index.contradictions_for(other_flow);
  AIFC_CHECK_OK(none_for_other);
  if (none_for_other) {
    AIFC_CHECK(none_for_other.value().empty());
  }
  // The per flow contradiction bound is enforced.
  for (int repeat = 0; repeat < 4; ++repeat) {
    AIFC_CHECK_OK(index.record_contradiction(flow, contradiction, 2 + repeat));
  }
  const auto bounded = index.contradictions_for(flow);
  AIFC_CHECK_OK(bounded);
  if (bounded) {
    AIFC_CHECK_EQ(bounded.value().size(), std::size_t{2});
  }

  // A classification that carries contradictions records them in history.
  aifc::Classification with_contradiction =
      make_classification(flow, generation, aifc::SemanticClass::COLLECTIVE);
  with_contradiction.state = aifc::ClassificationState::CONTRADICTED;
  with_contradiction.contradictions.push_back(contradiction);
  AIFC_CHECK_OK(index.record(with_contradiction));
  AIFC_CHECK_EQ(index.stats().contradictions_recorded >= 5U, true);

  // A revocation that names one evidence identity is a withdrawal of that record.  The
  // incarnation is not revoked: the withdrawn evidence simply stops being current, which is a
  // different statement from "this generation was revoked".
  aifc::RevocationRecord revocation;
  revocation.flow_id = flow;
  revocation.flow_generation = generation;
  revocation.evidence_id = aifc::make_evidence_id("ev-withdrawn");
  revocation.revoked_by_session = aifc_test::synthetic_session(0U);
  revocation.revoked_by_publisher = aifc_test::synthetic_publisher(0U);
  revocation.epoch = aifc::CoordinatorEpoch{1};
  revocation.seq = 1;
  revocation.reason = "withdrawn by its publisher";
  AIFC_CHECK_OK(index.record_revocation(revocation));
  AIFC_CHECK_MSG(!index.is_revoked(flow, generation),
                 "withdrawing one record must not revoke the whole generation");
  AIFC_CHECK(!index.is_revoked(flow, aifc::FlowGeneration{2}));
  AIFC_CHECK(!index.is_revoked(other_flow, generation));
  AIFC_CHECK_EQ(index.revocations().size(), std::size_t{1});
  AIFC_CHECK_EQ(index.stats().revocations, 1U);

  // A generation level revocation names no evidence identity and does revoke the incarnation.
  aifc::RevocationRecord generation_revocation = revocation;
  generation_revocation.flow_generation = aifc::FlowGeneration{2};
  generation_revocation.evidence_id = aifc::EvidenceId{};
  generation_revocation.reason = "generation revoked by request";
  AIFC_CHECK_OK(index.record_revocation(generation_revocation));
  AIFC_CHECK_MSG(index.is_revoked(flow, aifc::FlowGeneration{2}),
                 "a generation level revocation must revoke that generation");
  AIFC_CHECK(!index.is_revoked(flow, generation));
  AIFC_CHECK(!index.is_revoked(flow, aifc::FlowGeneration{3}));
  AIFC_CHECK(!index.is_revoked(other_flow, aifc::FlowGeneration{2}));
  // The revocation bound is one, so the oldest was dropped rather than the list growing.  The
  // list is held in a local: binding a reference to an element of the temporary that
  // revocations() returns would dangle for the rest of the check.
  const std::vector<aifc::RevocationRecord> revocations = index.revocations();
  AIFC_CHECK_EQ(revocations.size(), std::size_t{1});
  if (revocations.size() == 1U) {
    AIFC_CHECK_EQ(revocations[0].reason, std::string("generation revoked by request"));
    AIFC_CHECK_EQ(revocations[0].flow_generation.value, 2U);
    AIFC_CHECK_EQ(revocations[0].evidence_id.value(), std::string());
  }

  // Supersessions are bounded the same way.
  aifc::SupersessionRecord supersession;
  supersession.previous_id = aifc::make_evidence_id("ev-previous");
  supersession.replacement_id = aifc::make_evidence_id("ev-replacement");
  supersession.previous_generation = aifc::EvidenceGeneration{1};
  supersession.replacement_generation = aifc::EvidenceGeneration{2};
  supersession.publisher = aifc_test::synthetic_publisher(0U);
  supersession.seq = 1;
  AIFC_CHECK_OK(index.record_supersession(supersession));
  AIFC_CHECK_EQ(index.supersessions().size(), std::size_t{1});
  AIFC_CHECK_EQ(index.stats().supersessions, 1U);
  AIFC_CHECK_OK(index.record_supersession(supersession));
  AIFC_CHECK_EQ(index.supersessions().size(), std::size_t{1});

  // A generation advance stales the decisions of every lower generation and reports how many
  // it changed.  The decision for the new generation itself is untouched.
  aifc::ClassificationIndex history(8U, 4U, 4U, 4U, 4U);
  AIFC_CHECK_OK(history.record(make_classification(flow, aifc::FlowGeneration{1},
                                                   aifc::SemanticClass::COLLECTIVE)));
  AIFC_CHECK_OK(history.record(make_classification(flow, aifc::FlowGeneration{2},
                                                   aifc::SemanticClass::TELEMETRY)));
  AIFC_CHECK_OK(history.record(make_classification(flow, aifc::FlowGeneration{3},
                                                   aifc::SemanticClass::CHECKPOINT)));
  AIFC_CHECK_EQ(history.supersede_generation(flow, aifc::FlowGeneration{3}, 5), 2U);
  const auto superseded_first = history.latest(flow, aifc::FlowGeneration{1});
  AIFC_CHECK_OK(superseded_first);
  if (superseded_first) {
    AIFC_CHECK_MSG(superseded_first.value().state == aifc::ClassificationState::STALE,
                   "a superseded decision must be STALE, not "
                       << aifc::to_string(superseded_first.value().state));
  }
  const auto surviving = history.latest(flow, aifc::FlowGeneration{3});
  AIFC_CHECK_OK(surviving);
  if (surviving) {
    AIFC_CHECK(surviving.value().state == aifc::ClassificationState::CURRENT);
  }
  // Superseding again changes nothing, and an unknown flow is a no-op rather than an error.
  AIFC_CHECK_EQ(history.supersede_generation(flow, aifc::FlowGeneration{3}, 6), 0U);
  AIFC_CHECK_EQ(history.supersede_generation(other_flow, aifc::FlowGeneration{3}, 6), 0U);
}
