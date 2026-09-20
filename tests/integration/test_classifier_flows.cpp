// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Integration proof surface: the classifier facade, driven through its real public API.
//
// The harness in tests/support/synthetic.hpp builds the same preamble for every integration
// surface.  The inputs are SYNTHETIC (loopback addresses and generated identities); the
// behaviour under test is REAL.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "test_framework.hpp"

#include "synthetic.hpp"

namespace {

[[nodiscard]] bool contains(const std::string& haystack, std::string_view needle) {
  return haystack.find(needle) != std::string::npos;
}

// The classifier measures freshness in ticks from its clock, and the default clock is a
// monotonic millisecond source.  A surface that is not testing freshness therefore runs with a
// window large enough that nothing can expire while it executes; the exact boundaries are pinned
// with a manual clock in the classifier/memo case, and the default window is asserted in the
// unit surfaces.
[[nodiscard]] aifc::ClassifierPolicy steady_policy() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.default_freshness_window = 1ULL << 32U;
  return policy;
}

}  // namespace

AIFC_TEST("classifier/flows: registration, an empty answer and a declared class (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(0U);
  const aifc::FlowRecord flow = harness.register_flow(peer, 0U);
  AIFC_CHECK_EQ(flow.generation.value, 1U);

  // Before any evidence the answer is UNKNOWN with no confidence, not a guess and not an error.
  const aifc::ClassificationResult empty = harness.classify(key);
  AIFC_CHECK(empty.classification.semantic == aifc::SemanticClass::UNKNOWN);
  AIFC_CHECK(empty.classification.state == aifc::ClassificationState::INSUFFICIENT);
  AIFC_CHECK_EQ(empty.classification.confidence.to_decimal(), std::string("0.0000"));
  AIFC_CHECK(empty.classification.selected_evidence.empty());
  AIFC_CHECK_EQ(empty.classification.citations.size(), std::size_t{0});
  AIFC_CHECK_EQ(empty.historical, false);

  // A declaration produces exactly the declared class.
  const aifc::EvidenceRecord published =
      harness.publish(peer, flow, aifc::SemanticClass::KV_STATE_TRANSFER, aifc::EvidenceGeneration{1});
  AIFC_CHECK_EQ(published.publisher.value(), peer.publisher.value());
  AIFC_CHECK_EQ(published.flow_generation.value, 1U);
  AIFC_CHECK(published.carries_authority());

  const aifc::ClassificationResult declared = harness.classify(key);
  AIFC_CHECK(declared.classification.semantic == aifc::SemanticClass::KV_STATE_TRANSFER);
  AIFC_CHECK(declared.classification.state == aifc::ClassificationState::CURRENT);
  AIFC_CHECK_EQ(declared.classification.confidence.to_decimal(), std::string("0.9000"));
  AIFC_CHECK(declared.classification.selected_source ==
             aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  AIFC_CHECK_EQ(declared.classification.selected_evidence.value(), published.id.value());
  AIFC_CHECK_EQ(declared.classification.corroboration_count, 0U);
  AIFC_CHECK_EQ(declared.classification.applied_penalty_basis_points, 0U);
  AIFC_CHECK_EQ(declared.classification.policy_generation.value, 1U);
  AIFC_CHECK(!declared.classification.digest.is_zero());
  AIFC_CHECK_EQ(declared.historical, false);
  AIFC_CHECK_EQ(declared.classification.citations.size(), std::size_t{1});
  if (declared.classification.citations.size() == 1U) {
    const aifc::EvidenceCitation& citation = declared.classification.citations[0];
    AIFC_CHECK(citation.disposition == aifc::EvidenceDisposition::SELECTED);
    AIFC_CHECK(citation.state == aifc::EvidenceState::EVIDENCE_CURRENT);
    AIFC_CHECK(citation.source == aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  }

  // A second identical question produces exactly the same answer.  Whether it is served from
  // the memo depends on the tick, because the tick participates in the memo key; the memo hit
  // itself is pinned deterministically by the classifier/memo case, which injects a manual clock.
  const aifc::ClassificationResult again = harness.classify(key);
  AIFC_CHECK_MSG(again.classification == declared.classification,
                 "two runs over the same evidence set produced different classifications");
  AIFC_CHECK_EQ(again.classification.digest.to_hex(), declared.classification.digest.to_hex());

  // The explanation names the flow, the class and the publisher, and it is rendered on demand.
  const aifc::ClassificationResult explained = harness.classify(key, aifc::FlowGeneration{}, true);
  AIFC_CHECK(!explained.explanation.empty());
  AIFC_CHECK_MSG(contains(explained.explanation, "KV_STATE_TRANSFER"),
                 "the explanation must name the class, got: " << explained.explanation);
  AIFC_CHECK_MSG(contains(explained.explanation, peer.publisher.value()),
                 "the explanation must name the publisher, got: " << explained.explanation);
  AIFC_CHECK_MSG(contains(explained.explanation, key.to_string()),
                 "the explanation must name the flow key, got: " << explained.explanation);

  // Asking about a flow that was never registered is an error, not an UNKNOWN answer.
  aifc::ClassificationQuery unknown_query;
  unknown_query.flow_key = aifc_test::synthetic_flow_key(99U);
  AIFC_CHECK_ERR(harness.classifier().classify(unknown_query), aifc::ErrorCode::UNKNOWN_FLOW);

  // A request that names no generation and refuses the current one is refused rather than
  // guessed at.
  aifc::ClassificationQuery no_generation;
  no_generation.flow_key = key;
  no_generation.accept_current_generation = false;
  AIFC_CHECK_ERR(harness.classifier().classify(no_generation), aifc::ErrorCode::INVALID_ARGUMENT);
}

AIFC_TEST("classifier/flows: a generation advance stales evidence and recorded classifications (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(1U);
  const aifc::FlowRecord first = harness.register_flow(peer, 1U);
  const aifc::EvidenceRecord published =
      harness.publish(peer, first, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1});

  const aifc::ClassificationResult before = harness.classify(key);
  AIFC_CHECK(before.classification.semantic == aifc::SemanticClass::COLLECTIVE);
  AIFC_CHECK(before.classification.state == aifc::ClassificationState::CURRENT);

  // The advance fences the previous incarnation and reports which one it fenced.
  const auto advanced =
      harness.classifier().register_flow(key, aifc::FlowGeneration{2}, peer.session);
  AIFC_CHECK_OK(advanced);
  if (advanced) {
    AIFC_CHECK_EQ(advanced.value().created, true);
    AIFC_CHECK_EQ(advanced.value().fenced_previous, true);
    AIFC_CHECK_EQ(advanced.value().previous_generation.value, 1U);
    AIFC_CHECK_EQ(advanced.value().record.generation.value, 2U);
  }

  // 1. Evidence bound to the previous generation stops being current, with a reason.
  const auto staled = harness.classifier().find_evidence(published.id);
  AIFC_CHECK_OK(staled);
  if (staled) {
    AIFC_CHECK_MSG(staled.value().state == aifc::EvidenceState::EVIDENCE_STALE,
                   "evidence for the fenced generation is " << aifc::to_string(staled.value().state)
                                                            << " rather than STALE");
    // The classifier stales every record of a replaced incarnation before it applies the
    // generation specific reason, so the applied reason is the incarnation one.  What matters
    // is that the reason is present and truthful; it is asserted rather than assumed.
    AIFC_CHECK_MSG(!staled.value().state_reason.empty(),
                   "a staled record must carry the reason it stopped being current");
    AIFC_CHECK_MSG(contains(staled.value().state_reason, "incarnation") ||
                       contains(staled.value().state_reason, "generation 2"),
                   "the staleness reason must explain the incarnation change, got: "
                       << staled.value().state_reason);
  }

  // 2. The recorded classification for the previous generation is marked stale in history, so
  //    history cannot report a superseded decision as the current answer.
  const auto history = harness.classifier().recorded_decision(first.id, aifc::FlowGeneration{1});
  AIFC_CHECK_OK(history);
  if (history) {
    AIFC_CHECK_MSG(history.value().state == aifc::ClassificationState::STALE,
                   "the recorded classification for generation 1 is "
                       << aifc::to_string(history.value().state) << " rather than STALE");
  }

  // The current generation has no current evidence, so no class is published: the new
  // incarnation does not inherit the previous classification.  The state is STALE rather than
  // INSUFFICIENT because the previous incarnation's record is still cited as what used to be
  // believed.
  const aifc::ClassificationResult after = harness.classify(key);
  AIFC_CHECK_MSG(after.classification.semantic == aifc::SemanticClass::UNKNOWN,
                 "the new incarnation must not inherit the class of the one it replaced, but it "
                 "reported "
                     << aifc::to_string(after.classification.semantic));
  AIFC_CHECK_MSG(after.classification.state == aifc::ClassificationState::STALE,
                 "with only stale evidence left the state must be STALE, but it was "
                     << aifc::to_string(after.classification.state));
  AIFC_CHECK_EQ(after.classification.confidence.to_decimal(), std::string("0.0000"));
  AIFC_CHECK_EQ(after.historical, false);
  AIFC_CHECK_EQ(after.classification.citations.size(), std::size_t{1});
  if (after.classification.citations.size() == 1U) {
    AIFC_CHECK(after.classification.citations[0].disposition ==
               aifc::EvidenceDisposition::STALE);
  }

  // Publishing against the new generation restores a current class.
  const aifc::FlowRecord second = harness.register_flow(peer, 1U, aifc::FlowGeneration{2});
  AIFC_CHECK_EQ(second.generation.value, 2U);
  harness.publish(peer, second, aifc::SemanticClass::TELEMETRY, aifc::EvidenceGeneration{2});
  const aifc::ClassificationResult recovered = harness.classify(key);
  AIFC_CHECK(recovered.classification.semantic == aifc::SemanticClass::TELEMETRY);
  AIFC_CHECK(recovered.classification.state == aifc::ClassificationState::CURRENT);
}

AIFC_TEST("classifier/flows: asking about a superseded generation returns a historical answer (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(2U);
  const aifc::FlowRecord first = harness.register_flow(peer, 2U);
  harness.publish(peer, first, aifc::SemanticClass::CHECKPOINT, aifc::EvidenceGeneration{1});
  AIFC_CHECK(harness.classify(key).classification.state == aifc::ClassificationState::CURRENT);

  AIFC_CHECK_OK(harness.classifier().register_flow(key, aifc::FlowGeneration{2}, peer.session));

  // The question names the superseded generation, so the answer is explicitly historical and
  // the state says the evidence behind it is no longer current.
  const aifc::ClassificationResult historical =
      harness.classify(key, aifc::FlowGeneration{1}, true);
  AIFC_CHECK_EQ(historical.historical, true);
  AIFC_CHECK(historical.classification.state == aifc::ClassificationState::STALE);
  AIFC_CHECK_MSG(historical.classification.semantic == aifc::SemanticClass::UNKNOWN,
                 "a superseded generation must not report a current class, but it reported "
                     << aifc::to_string(historical.classification.semantic));
  AIFC_CHECK_EQ(historical.classification.confidence.to_decimal(), std::string("0.0000"));
  AIFC_CHECK_EQ(historical.classification.flow_generation.value, 1U);
  AIFC_CHECK_EQ(historical.classification.citations.size(), std::size_t{1});
  if (historical.classification.citations.size() == 1U) {
    AIFC_CHECK(historical.classification.citations[0].disposition ==
               aifc::EvidenceDisposition::STALE);
  }
  AIFC_CHECK_MSG(contains(historical.explanation, "STALE"),
                 "an explained historical answer must say so, got: " << historical.explanation);

  // Asking about a generation that never existed is an error rather than a historical answer.
  aifc::ClassificationQuery never_existed;
  never_existed.flow_key = key;
  never_existed.flow_generation = aifc::FlowGeneration{7};
  AIFC_CHECK_ERR(harness.classifier().classify(never_existed), aifc::ErrorCode::UNKNOWN_FLOW);

  // Asking without a generation means the current incarnation and is not historical.
  const aifc::ClassificationResult current = harness.classify(key);
  AIFC_CHECK_EQ(current.historical, false);
  AIFC_CHECK_EQ(current.classification.flow_generation.value, 2U);
}

AIFC_TEST("classifier/flows: a superseded generation cannot be re-registered (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(3U);
  AIFC_CHECK_OK(harness.classifier().register_flow(key, aifc::FlowGeneration{1}, peer.session));
  AIFC_CHECK_OK(harness.classifier().register_flow(key, aifc::FlowGeneration{3}, peer.session));

  // Generation 1 has been fenced and generation 2 was never used: neither may be created, and
  // the refusal is an authority failure rather than a capacity failure.
  const auto reused = harness.classifier().register_flow(key, aifc::FlowGeneration{1}, peer.session);
  AIFC_CHECK_ERR(reused, aifc::ErrorCode::STALE_GENERATION);
  if (!reused) {
    AIFC_CHECK_MSG(contains(reused.status().message, "generation 3") &&
                       contains(reused.status().message, "1"),
                   "the refusal must name the current generation and the requested one, got: "
                       << reused.status().message);
    AIFC_CHECK(aifc::is_authority_failure(reused.code()));
  }
  AIFC_CHECK_ERR(harness.classifier().register_flow(key, aifc::FlowGeneration{2}, peer.session),
                 aifc::ErrorCode::STALE_GENERATION);

  // An identical repeat of the current generation is idempotent.
  const auto repeated = harness.classifier().register_flow(key, aifc::FlowGeneration{3}, peer.session);
  AIFC_CHECK_OK(repeated);
  if (repeated) {
    AIFC_CHECK_EQ(repeated.value().created, false);
    AIFC_CHECK_EQ(repeated.value().fenced_previous, false);
  }

  // Naming no generation asks for the next incarnation, which is one past the highest observed.
  const auto next = harness.classifier().register_flow(key, aifc::FlowGeneration{0}, peer.session);
  AIFC_CHECK_OK(next);
  if (next) {
    AIFC_CHECK_EQ(next.value().record.generation.value, 4U);
    AIFC_CHECK_EQ(next.value().fenced_previous, true);
  }
  AIFC_CHECK_ERR(harness.classifier().register_flow(key, aifc::FlowGeneration{3}, peer.session),
                 aifc::ErrorCode::STALE_GENERATION);

  // The current incarnation is still reachable and reports the generation that is current.
  const auto current = harness.classifier().find_flow(key);
  AIFC_CHECK_OK(current);
  if (current) {
    AIFC_CHECK_EQ(current.value().generation.value, 4U);
  }
  const auto old_generation = harness.classifier().find_flow_generation(
      aifc::derive_flow_id(key), aifc::FlowGeneration{1});
  AIFC_CHECK_OK(old_generation);
  if (old_generation) {
    AIFC_CHECK_EQ(old_generation.value().generation.value, 1U);
  }
}

AIFC_TEST("classifier/flows: batch classification reports per-key statuses and still succeeds (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey first_key = aifc_test::synthetic_flow_key(4U);
  const aifc::FlowKey second_key = aifc_test::synthetic_flow_key(5U);
  const aifc::FlowKey unregistered_key = aifc_test::synthetic_flow_key(6U);
  const aifc::FlowRecord first = harness.register_flow(peer, 4U);
  const aifc::FlowRecord second = harness.register_flow(peer, 5U);
  harness.publish(peer, first, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1});
  harness.publish(peer, second, aifc::SemanticClass::STORAGE_DATA, aifc::EvidenceGeneration{2});

  const auto query_for = [](const aifc::FlowKey& key, aifc::FlowGeneration generation) {
    aifc::ClassificationQuery query;
    query.flow_key = key;
    query.flow_generation = generation;
    return query;
  };

  std::vector<aifc::ClassificationQuery> queries;
  queries.push_back(query_for(first_key, aifc::FlowGeneration{}));
  queries.push_back(query_for(second_key, aifc::FlowGeneration{}));
  queries.push_back(query_for(unregistered_key, aifc::FlowGeneration{}));
  queries.push_back(query_for(first_key, aifc::FlowGeneration{7}));

  const auto batch = harness.classifier().classify_batch(queries);
  AIFC_CHECK_OK(batch);
  if (!batch) return;
  AIFC_CHECK_EQ(batch.value().results.size(), std::size_t{4});
  AIFC_CHECK_EQ(batch.value().statuses.size(), std::size_t{4});
  AIFC_CHECK_EQ(batch.value().succeeded, 2U);
  AIFC_CHECK_EQ(batch.value().failed, 2U);

  // The successful entries carry real answers, in the order they were asked.
  AIFC_CHECK_OK(batch.value().statuses[0]);
  AIFC_CHECK(batch.value().results[0].classification.semantic == aifc::SemanticClass::COLLECTIVE);
  AIFC_CHECK(batch.value().results[0].classification.state ==
             aifc::ClassificationState::CURRENT);
  AIFC_CHECK_OK(batch.value().statuses[1]);
  AIFC_CHECK(batch.value().results[1].classification.semantic ==
             aifc::SemanticClass::STORAGE_DATA);
  AIFC_CHECK_EQ(batch.value().results[0].classification.flow_id.to_hex(), first.id.to_hex());
  AIFC_CHECK_EQ(batch.value().results[1].classification.flow_id.to_hex(), second.id.to_hex());

  // The failures are per key and explain themselves; the batch as a whole is a success.
  AIFC_CHECK_ERR(batch.value().statuses[2], aifc::ErrorCode::UNKNOWN_FLOW);
  AIFC_CHECK_MSG(contains(batch.value().statuses[2].message, unregistered_key.to_string()),
                 "the per-key status must name the key, got: "
                     << batch.value().statuses[2].message);
  AIFC_CHECK_ERR(batch.value().statuses[3], aifc::ErrorCode::UNKNOWN_FLOW);
  AIFC_CHECK_MSG(contains(batch.value().statuses[3].message, "7"),
                 "the per-key status must name the generation, got: "
                     << batch.value().statuses[3].message);
  AIFC_CHECK(batch.value().results[2].classification.semantic == aifc::SemanticClass::UNKNOWN);
  AIFC_CHECK(batch.value().results[3].classification.semantic == aifc::SemanticClass::UNKNOWN);

  // The counters see the batch as four keys, two of which succeeded.
  const aifc::Classifier::Stats stats = harness.classifier().stats();
  AIFC_CHECK_EQ(stats.counters.batch_requests, 1U);
  AIFC_CHECK_EQ(stats.counters.batch_keys, 4U);

  // A batch larger than the configured bound is refused before any key is classified.  The
  // bound is policy, and a batch is not a way to ask for unbounded work.
  aifc::ClassifierPolicy bounded = steady_policy();
  bounded.limits.max_batch_keys = 2U;
  aifc_test::Harness small(bounded);
  const aifc_test::Harness::Peer small_peer = small.add_peer(0U);
  const aifc::FlowKey small_key = aifc_test::synthetic_flow_key(7U);
  AIFC_CHECK_OK(small.classifier().register_flow(small_key, aifc::FlowGeneration{1},
                                                 small_peer.session));
  std::vector<aifc::ClassificationQuery> three;
  three.push_back(query_for(small_key, aifc::FlowGeneration{}));
  three.push_back(query_for(small_key, aifc::FlowGeneration{}));
  three.push_back(query_for(small_key, aifc::FlowGeneration{}));
  const auto oversized = small.classifier().classify_batch(three);
  AIFC_CHECK_ERR(oversized, aifc::ErrorCode::CAPACITY_EXCEEDED);
  if (!oversized) {
    AIFC_CHECK_MSG(contains(oversized.status().message, "2"),
                   "the refusal must name the configured bound, got: "
                       << oversized.status().message);
  }
  AIFC_CHECK_EQ(small.classifier().stats().counters.classifications, 0U);

  // A batch of one is still a batch, and an empty batch is a success with nothing in it.
  std::vector<aifc::ClassificationQuery> single{query_for(small_key, aifc::FlowGeneration{})};
  const auto one = small.classifier().classify_batch(single);
  AIFC_CHECK_OK(one);
  if (one) {
    AIFC_CHECK_EQ(one.value().succeeded, 1U);
    AIFC_CHECK_EQ(one.value().failed, 0U);
  }
  const auto empty = small.classifier().classify_batch({});
  AIFC_CHECK_OK(empty);
  if (empty) {
    AIFC_CHECK_EQ(empty.value().succeeded, 0U);
    AIFC_CHECK_EQ(empty.value().failed, 0U);
    AIFC_CHECK(empty.value().results.empty());
  }
}

AIFC_TEST("classifier/policy: identical content does not renumber, changed content does (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(8U);
  const aifc::FlowRecord flow = harness.register_flow(peer, 8U);
  harness.publish(peer, flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1});
  AIFC_CHECK(harness.classify(key).classification.state == aifc::ClassificationState::CURRENT);

  // Re-installing the policy that is already in force is not a policy change: the generation
  // would otherwise renumber without the content changing, which would invalidate decisions
  // that are still correct.
  const auto unchanged = harness.classifier().set_policy(harness.classifier().policy());
  AIFC_CHECK_OK(unchanged);
  if (unchanged) {
    AIFC_CHECK_EQ(unchanged.value().value, 1U);
  }
  AIFC_CHECK_EQ(harness.classifier().stats().counters.policy_updates, 0U);

  // A content change does advance the generation, and the decision records the new generation.
  aifc::ClassifierPolicy changed = harness.classifier().policy();
  changed.contradiction_penalty = 1234U;
  const auto updated = harness.classifier().set_policy(changed);
  AIFC_CHECK_OK(updated);
  if (updated) {
    AIFC_CHECK_EQ(updated.value().value, 2U);
  }
  AIFC_CHECK_EQ(harness.classifier().stats().counters.policy_updates, 1U);
  const aifc::ClassificationResult after = harness.classify(key);
  AIFC_CHECK_EQ(after.classification.policy_generation.value, 2U);
  // The decision records the digest of the policy content that produced it, so it can never
  // be silently reinterpreted under a differently shaped policy that reuses a generation.
  AIFC_CHECK_EQ(after.classification.policy_digest.to_hex(),
                aifc::compute_policy_digest(harness.classifier().policy()).to_hex());

  // An invalid policy is refused and leaves the installed policy untouched.
  aifc::ClassifierPolicy invalid = harness.classifier().policy();
  invalid.default_freshness_window = 0U;
  AIFC_CHECK_ERR(harness.classifier().set_policy(invalid), aifc::ErrorCode::INVALID_ARGUMENT);
  AIFC_CHECK_EQ(harness.classifier().policy().generation.value, 2U);
  AIFC_CHECK_EQ(harness.classifier().stats().counters.policy_updates, 1U);
}

AIFC_TEST("classifier/stats: counters describe what actually happened (REAL)") {
  aifc_test::Harness harness(steady_policy());
  const aifc_test::Harness::Peer peer = harness.add_peer(0U);
  AIFC_CHECK_EQ(harness.classifier().epoch().value, 1U);
  AIFC_CHECK_EQ(harness.classifier().coordinator_boot().value, 1U);

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(9U);
  const aifc::FlowRecord flow = harness.register_flow(peer, 9U);
  harness.publish(peer, flow, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1});
  const aifc::ClassificationResult answer = harness.classify(key);
  AIFC_CHECK(answer.classification.state == aifc::ClassificationState::CURRENT);

  const aifc::Classifier::Stats stats = harness.classifier().stats();
  // One explicit registration plus the implicit refresh the evidence admission performs: the
  // counter counts every registration call, including the idempotent ones.
  AIFC_CHECK_EQ(stats.counters.flows_registered, 2U);
  AIFC_CHECK_EQ(stats.counters.evidence_accepted, 1U);
  AIFC_CHECK_EQ(stats.counters.evidence_refused, 0U);
  AIFC_CHECK_EQ(stats.counters.classifications, 1U);
  AIFC_CHECK_EQ(stats.flows.size, std::size_t{1});
  AIFC_CHECK_EQ(stats.publishers.publishers, std::size_t{1});
  AIFC_CHECK_EQ(stats.evidence.records, std::size_t{1});
  AIFC_CHECK_EQ(stats.evidence.accepted, 1U);
  // Exactly one decision was computed and recorded.  A first question can never be a memo hit:
  // the memo is only ever consulted for a question that has been asked before, and whether the
  // second identical question at the same tick hits is pinned in the classifier/memo case.
  AIFC_CHECK_EQ(stats.classifications.decisions_recorded, 1U);
  AIFC_CHECK_EQ(stats.classifications.memo_hits, 0U);
  AIFC_CHECK_EQ(stats.classifications.memo_misses, 1U);
  AIFC_CHECK_EQ(stats.memo_entries, std::size_t{1});
  AIFC_CHECK_EQ(stats.policy_generation.value, 1U);
  AIFC_CHECK_EQ(stats.epoch.value, 1U);
  AIFC_CHECK_EQ(stats.coordinator_boot.value, 1U);
  AIFC_CHECK_MSG(stats.next_sequence >= 1U,
                 "admitting evidence must consume a sequence number, but next_sequence is "
                     << stats.next_sequence);
  AIFC_CHECK_EQ(stats.policy_digest.to_hex(),
                aifc::compute_policy_digest(harness.classifier().policy()).to_hex());

  // A refused submission is counted as refused and leaves no record behind.
  aifc::EvidencePayload payload;
  payload.flow_key = key;
  payload.flow_generation = flow.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};  // already used: a replay
  payload.semantic = aifc::SemanticClass::COLLECTIVE;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  const auto replay = harness.classifier().submit_evidence(peer.envelope, payload);
  AIFC_CHECK_ERR(replay, aifc::ErrorCode::REPLAY_DETECTED);
  const aifc::Classifier::Stats after = harness.classifier().stats();
  AIFC_CHECK_EQ(after.counters.evidence_refused, 1U);
  AIFC_CHECK_EQ(after.counters.evidence_accepted, 1U);
  AIFC_CHECK_EQ(after.evidence.records, std::size_t{1});
}

AIFC_TEST("classifier/memo: the memo is keyed by the evidence set and the tick (REAL)") {
  // The memo exists for the batch case: the same question asked twice at the same tick.  The
  // tick participates in the key because whether a freshness window has elapsed depends on it,
  // so a manual clock is what makes a hit exactly reproducible instead of a race against the
  // monotonic default.
  aifc::ManualTickSource clock(1000U);
  aifc::ClassifierOptions options;
  options.policy = aifc::ClassifierPolicy::initial();
  options.clock = &clock;
  aifc::Classifier classifier(std::move(options));

  const aifc::PublisherId publisher = aifc_test::synthetic_publisher(0U);
  const aifc::SessionId session = aifc_test::synthetic_session(0U);
  const auto registration =
      classifier.register_publisher(publisher, aifc::PublisherBootId{1},
                                    aifc::EvidenceSource::DECLARED_AUTHENTICATED, session, "memo peer");
  AIFC_CHECK_OK(registration);
  if (!registration) return;
  const aifc::SessionEnvelope envelope =
      aifc::make_session_envelope(registration.value(), clock.now());

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(20U);
  const auto flow = classifier.register_flow(key, aifc::FlowGeneration{0}, session);
  AIFC_CHECK_OK(flow);
  if (!flow) return;

  aifc::EvidencePayload payload;
  payload.flow_key = key;
  payload.flow_generation = flow.value().record.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};
  payload.semantic = aifc::SemanticClass::COLLECTIVE;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "memo.topic";
  payload.freshness_window = 100U;
  const auto outcome = classifier.submit_evidence(envelope, payload);
  AIFC_CHECK_OK(outcome);
  if (!outcome) return;
  // The deadline is derived from the injected clock, so the test can walk onto it exactly.
  AIFC_CHECK_EQ(outcome.value().record.accepted_tick, 1000U);
  AIFC_CHECK_EQ(outcome.value().record.fresh_until, 1100U);

  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.accept_current_generation = true;

  const auto first = classifier.classify(query);
  AIFC_CHECK_OK(first);
  if (!first) return;
  AIFC_CHECK_EQ(first.value().memo_hit, false);
  AIFC_CHECK(first.value().classification.state == aifc::ClassificationState::CURRENT);

  // Same tick, same evidence, same policy: the same question, answered from the memo.
  const auto second = classifier.classify(query);
  AIFC_CHECK_OK(second);
  if (!second) return;
  AIFC_CHECK_MSG(second.value().memo_hit,
                 "an unchanged question at the same tick must be answered from the memo");
  AIFC_CHECK(first.value().classification == second.value().classification);
  AIFC_CHECK_EQ(classifier.stats().classifications.memo_hits, 1U);
  AIFC_CHECK_EQ(classifier.stats().classifications.decisions_recorded, 1U);

  // Another tick is another question: the answer is recomputed rather than reused.
  clock.advance(50U);
  const auto third = classifier.classify(query);
  AIFC_CHECK_OK(third);
  if (!third) return;
  AIFC_CHECK_MSG(!third.value().memo_hit, "a decision must not be reused at another tick");
  AIFC_CHECK(third.value().classification.state == aifc::ClassificationState::CURRENT);

  // Walking exactly onto the deadline keeps the record current; one tick past it does not, and
  // the memo cannot hide that because the tick is part of its key.
  clock.set(1100U);
  const auto at_deadline = classifier.classify(query);
  AIFC_CHECK_OK(at_deadline);
  if (at_deadline) {
    AIFC_CHECK_MSG(at_deadline.value().classification.state == aifc::ClassificationState::CURRENT,
                   "a record is current up to and including its freshness deadline, but the "
                   "state was "
                       << aifc::to_string(at_deadline.value().classification.state));
  }
  clock.set(1101U);
  const auto past_deadline = classifier.classify(query);
  AIFC_CHECK_OK(past_deadline);
  if (past_deadline) {
    AIFC_CHECK_MSG(past_deadline.value().classification.state == aifc::ClassificationState::STALE,
                   "past the freshness deadline the class must not stay current, but the state "
                   "was "
                       << aifc::to_string(past_deadline.value().classification.state));
    AIFC_CHECK_EQ(past_deadline.value().classification.confidence.to_decimal(),
                  std::string("0.0000"));
  }

  // A heartbeat keeps the incarnation live and is therefore authority relevant, so it changes
  // the memo key rather than leaving a decision that no longer describes the same facts.
  AIFC_CHECK_OK(classifier.heartbeat(publisher, aifc::PublisherBootId{1}));
  const auto after_heartbeat = classifier.classify(query);
  AIFC_CHECK_OK(after_heartbeat);
  if (after_heartbeat) {
    AIFC_CHECK_MSG(!after_heartbeat.value().memo_hit,
                   "a change to a volatile authority fact must not be answered from the memo");
  }
}
