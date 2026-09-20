// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Concurrency tests for aifc::Classifier.
//
// REAL / SYNTHETIC
// ----------------
// The evidence is SYNTHETIC (fabricated publishers, flows, classes and generations).  What
// is REAL is the concurrency: real std::thread workers, a real std::barrier start gate, and
// the shipped Classifier's own internal synchronisation.  Nothing here is a mock and
// nothing is timed out: the framework has no timeout by design, so a deadlock shows up as a
// test that does not complete, which is a defect to diagnose rather than to survive.
//
// The worker threads never call AIFC_CHECK: the failure registry is not thread safe, so
// every worker records what it observed and the main thread makes all assertions once the
// workers have been joined.  A failure therefore names the thread, the flow key, the
// generation and the exact error text.
//
// What is asserted:
//   * no crash, no deadlock (the case completes; there is no timeout anywhere);
//   * every accepted submission is visible in stats(), and counters agree exactly;
//   * every accepted evidence identity is still readable from the store;
//   * a classified flow's digest is reproducible from a single-threaded re-derivation over
//     the same evidence records;
//   * concurrent classifications of one flow generation agree with each other;
//   * ending a publisher session concurrently with classification yields either the
//     pre-end answer or the post-end answer, never a third answer.

#include <atomic>
#include <barrier>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "synthetic.hpp"
#include "test_framework.hpp"

namespace {

constexpr std::uint32_t kThreads = 8U;
constexpr std::uint32_t kSharedFlowIndex = 0U;
constexpr std::uint32_t kPrivateFlowBase = 100U;
constexpr std::uint32_t kFreshFlowBase = 200U;
constexpr std::uint32_t kFreshFlowsPerThread = 4U;
constexpr std::uint32_t kSharedRecordsPerThread = 3U;
constexpr std::uint32_t kPrivateRecordsPerThread = 2U;
constexpr std::uint32_t kConcurrentClassifyRounds = 32U;

// The freshness window is widened deliberately: a Classifier without an explicit clock
// reads a real monotonic source, and this case is about concurrency, not about the wall
// clock.  With the default 4096 tick window a record could expire mid-case on a slow or
// heavily loaded machine, which would turn a scheduling accident into a failure.  Nothing
// here asserts anything about freshness, so removing it from the inputs is the honest choice.
//
// Heuristic sessions are not used here either: heuristic admission additionally requires an
// enabled adapter and a cited port hint, and this case is about contention, not about that gate.
// Heuristic precedence is asserted at the engine level by test_precedence_properties.cpp.
[[nodiscard]] aifc::ClassifierPolicy concurrency_policy() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.default_freshness_window = 60000000ULL;
  policy.limits.default_freshness_window = 60000000ULL;
  return aifc::ClassifierPolicy::canonicalize(policy).value();
}

// One evidence-source ceiling per thread, so the generated evidence spans four source ranks and
// the shared flow is guaranteed to contain a contradiction between different ranks.
[[nodiscard]] aifc::EvidenceSource ceiling_for(std::uint32_t index) {
  switch (index % 5U) {
    case 0U:
      return aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    case 1U:
      return aifc::EvidenceSource::CONTRACT_DERIVED;
    case 2U:
      return aifc::EvidenceSource::COORDINATOR_CORRELATED;
    case 3U:
      return aifc::EvidenceSource::TOPOLOGY_CORRELATED;
    default:
      return aifc::EvidenceSource::TOPOLOGY_CORRELATED;
  }
}

[[nodiscard]] aifc::SemanticClass class_for(std::uint32_t index) {
  switch (index % 4U) {
    case 0U:
      return aifc::SemanticClass::COLLECTIVE;
    case 1U:
      return aifc::SemanticClass::INFERENCE_REQUEST;
    case 2U:
      return aifc::SemanticClass::KV_STATE_TRANSFER;
    default:
      return aifc::SemanticClass::TRAINING_SYNC;
  }
}

[[nodiscard]] aifc::ClassificationQuery make_query(const aifc::FlowKey& key,
                                                  aifc::FlowGeneration generation) {
  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.flow_generation = generation;
  query.accept_current_generation = generation.value == 0U;
  return query;
}

[[nodiscard]] std::string describe_key(const aifc::FlowKey& key, aifc::FlowGeneration generation) {
  std::string out = "flow_key=";
  out += key.to_string();
  out += " flow_generation=";
  out += generation.to_string();
  return out;
}

// Everything a worker observed.  Each thread owns exactly one element of the outcome
// vector, so the workers share no mutable state at all.
struct ThreadOutcome {
  std::uint32_t index = 0;
  std::uint32_t accepted = 0;
  std::uint32_t refused = 0;
  std::uint32_t classifications = 0;
  std::vector<std::string> refusals;
  std::vector<aifc::EvidenceId> accepted_ids;
  std::vector<aifc::Digest256> digests;
  std::vector<std::string> digest_context;
  bool batches_ok = true;
  std::string batch_problem;
  aifc::Classifier::Stats stats;
};

void submit(aifc::Classifier& classifier, const aifc_test::Harness::Peer& peer,
            const aifc::FlowKey& key, aifc::FlowGeneration flow_generation,
            aifc::EvidenceGeneration generation, aifc::SemanticClass semantic,
            const std::string& topic, ThreadOutcome& outcome) {
  aifc::EvidencePayload payload;
  payload.flow_key = key;
  payload.flow_generation = flow_generation;
  payload.evidence_generation = generation;
  payload.semantic = semantic;
  // Every worker claims the strongest source; the session ceiling reduces it.  This is the
  // claim path a real peer would take, and it exercises the clamp under concurrency.
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = topic;
  payload.metadata.reason = "synthetic concurrent evidence";
  const aifc::Result<aifc::EvidenceSubmissionOutcome> result =
      classifier.submit_evidence(peer.envelope, payload);
  if (!result) {
    outcome.refused += 1;
    outcome.refusals.push_back("thread=" + std::to_string(outcome.index) + " topic=" + topic +
                               " evidence_generation=" + generation.to_string() + " " +
                               describe_key(key, flow_generation) + " error=" +
                               aifc::render_status(result.status()));
    return;
  }
  outcome.accepted += 1;
  outcome.accepted_ids.push_back(result.value().record.id);
}

void worker(aifc::Classifier& classifier, const std::vector<aifc_test::Harness::Peer>& peers,
            const std::vector<aifc::FlowKey>& private_keys,
            const std::vector<aifc::FlowGeneration>& private_generations,
            const aifc::FlowKey& shared_key, aifc::FlowGeneration shared_generation,
            std::uint32_t index, std::barrier<>& gate, ThreadOutcome& outcome) {
  const aifc_test::Harness::Peer& peer = peers[index];
  const aifc::FlowKey& private_key = private_keys[index];
  const aifc::FlowGeneration private_generation = private_generations[index];
  // For a classification query, generation zero means "the current incarnation"; for a
  // registration it means "the next incarnation".  Both meanings are used deliberately.
  const aifc::FlowGeneration current_incarnation{0};

  gate.arrive_and_wait();

  // Evidence generations are strictly increasing per publisher incarnation, because the
  // publisher's observed high-water mark is what makes a replay detectable; a lower
  // generation after a higher one is REPLAY_DETECTED, not a second record.
  const std::string shared_topic_a = "th" + std::to_string(index) + "-a";
  const std::string shared_topic_b = "th" + std::to_string(index) + "-b";
  submit(classifier, peer, shared_key, shared_generation, aifc::EvidenceGeneration{1},
         class_for(index), shared_topic_a, outcome);
  submit(classifier, peer, shared_key, shared_generation, aifc::EvidenceGeneration{2},
         class_for(index), shared_topic_a, outcome);
  submit(classifier, peer, shared_key, shared_generation, aifc::EvidenceGeneration{3},
         class_for(index), shared_topic_b, outcome);

  // --- this thread's private flow ----------------------------------------------------
  const std::string private_topic = "pv" + std::to_string(index) + "-a";
  submit(classifier, peer, private_key, private_generation, aifc::EvidenceGeneration{4},
         aifc::SemanticClass::INFERENCE_REQUEST, private_topic, outcome);
  submit(classifier, peer, private_key, private_generation, aifc::EvidenceGeneration{5},
         aifc::SemanticClass::INFERENCE_REQUEST, private_topic, outcome);

  // --- flows registered concurrently -------------------------------------------------
  std::vector<aifc::FlowKey> fresh_keys;
  fresh_keys.reserve(kFreshFlowsPerThread);
  for (std::uint32_t slot = 0; slot < kFreshFlowsPerThread; ++slot) {
    const aifc::FlowKey key = aifc_test::synthetic_flow_key(
        kFreshFlowBase + index * kFreshFlowsPerThread + slot);
    fresh_keys.push_back(key);
    // Generation zero means "the next incarnation", so every call below names the
    // generation it means.  Naming zero here would fence the flow on every submission,
    // which is a different (and much less interesting) test.
    const aifc::Result<aifc::FlowRegistration> registration =
        classifier.register_flow(key, aifc::FlowGeneration{0}, peer.session);
    if (!registration) {
      outcome.batches_ok = false;
      outcome.batch_problem = "register_flow failed for " +
                              describe_key(key, aifc::FlowGeneration{0}) +
                              " error=" + aifc::render_status(registration.status());
      continue;
    }
    submit(classifier, peer, key, registration.value().record.generation,
           aifc::EvidenceGeneration{6U + slot},
           aifc::SemanticClass::STORAGE_DATA,
           "fresh" + std::to_string(index) + "-" + std::to_string(slot), outcome);
  }

  // Re-registering a flow that already exists at its own generation is an idempotent
  // repeat, which is the path a reconnect takes.
  const aifc::Result<aifc::FlowRegistration> shared_repeat =
      classifier.register_flow(shared_key, shared_generation, peer.session);
  const aifc::Result<aifc::FlowRegistration> private_repeat =
      classifier.register_flow(private_key, private_generation, peer.session);
  if (!shared_repeat || !private_repeat) {
    outcome.batches_ok = false;
    outcome.batch_problem = "idempotent register_flow failed for " +
                            describe_key(shared_key, shared_generation) + " / " +
                            describe_key(private_key, private_generation);
  }

  // --- classification ----------------------------------------------------------------
  const aifc::Result<aifc::ClassificationResult> shared =
      classifier.classify(make_query(shared_key, shared_generation));
  if (!shared) {
    outcome.batches_ok = false;
    outcome.batch_problem = "classify failed for " + describe_key(shared_key, shared_generation) +
                            " error=" + aifc::render_status(shared.status());
  } else {
    outcome.classifications += 1;
    outcome.digests.push_back(shared.value().classification.digest);
    outcome.digest_context.push_back("thread=" + std::to_string(index) + " classify shared " +
                                     describe_key(shared_key, shared_generation));
  }
  const aifc::Result<aifc::ClassificationResult> own =
      classifier.classify(make_query(private_key, private_generation));
  if (!own) {
    outcome.batches_ok = false;
    outcome.batch_problem = "classify failed for " + describe_key(private_key, private_generation) +
                            " error=" + aifc::render_status(own.status());
  } else {
    outcome.classifications += 1;
    outcome.digests.push_back(own.value().classification.digest);
    outcome.digest_context.push_back("thread=" + std::to_string(index) + " classify private " +
                                     describe_key(private_key, private_generation));
  }

  std::vector<aifc::ClassificationQuery> batch;
  batch.push_back(make_query(shared_key, shared_generation));
  batch.push_back(make_query(private_key, private_generation));
  batch.push_back(make_query(shared_key, shared_generation));
  const aifc::Result<aifc::Classifier::BatchOutcome> batch_result = classifier.classify_batch(batch);
  if (!batch_result) {
    outcome.batches_ok = false;
    outcome.batch_problem = "classify_batch failed for " +
                            describe_key(shared_key, shared_generation) + " / " +
                            describe_key(private_key, private_generation) + " error=" +
                            aifc::render_status(batch_result.status());
  } else {
    const aifc::Classifier::BatchOutcome& outcome_batch = batch_result.value();
    if (outcome_batch.results.size() != batch.size() || outcome_batch.statuses.size() != batch.size() ||
        outcome_batch.succeeded != batch.size() || outcome_batch.failed != 0U) {
      outcome.batches_ok = false;
      outcome.batch_problem = "classify_batch returned " + std::to_string(outcome_batch.succeeded) +
                              " succeeded / " + std::to_string(outcome_batch.failed) +
                              " failed with " + std::to_string(outcome_batch.results.size()) +
                              " results and " + std::to_string(outcome_batch.statuses.size()) +
                              " statuses for a batch of " + std::to_string(batch.size()) + " keys";
    } else {
      outcome.classifications += static_cast<std::uint32_t>(outcome_batch.succeeded);
      for (std::size_t i = 0; i < outcome_batch.results.size(); ++i) {
        outcome.digests.push_back(outcome_batch.results[i].classification.digest);
        outcome.digest_context.push_back("thread=" + std::to_string(index) + " batch[" +
                                         std::to_string(i) + "] " +
                                         describe_key(batch[i].flow_key, batch[i].flow_generation));
      }
    }
  }

  if (!fresh_keys.empty()) {
    const aifc::Result<aifc::ClassificationResult> fresh =
        classifier.classify(make_query(fresh_keys[0], current_incarnation));
    if (!fresh) {
      outcome.batches_ok = false;
      outcome.batch_problem = "classify failed for " +
                              describe_key(fresh_keys[0], current_incarnation) + " error=" +
                              aifc::render_status(fresh.status());
    } else {
      outcome.classifications += 1;
      outcome.digests.push_back(fresh.value().classification.digest);
      outcome.digest_context.push_back("thread=" + std::to_string(index) + " classify fresh " +
                                       describe_key(fresh_keys[0], current_incarnation));
    }
    std::vector<aifc::ClassificationQuery> single;
    single.push_back(make_query(fresh_keys[0], current_incarnation));
    const aifc::Result<aifc::Classifier::BatchOutcome> single_result =
        classifier.classify_batch(single);
    if (!single_result || single_result.value().succeeded != 1U) {
      outcome.batches_ok = false;
      outcome.batch_problem = "single-key classify_batch failed for " +
                              describe_key(fresh_keys[0], current_incarnation);
    } else {
      outcome.classifications += 1;
      outcome.digests.push_back(single_result.value().results[0].classification.digest);
      outcome.digest_context.push_back("thread=" + std::to_string(index) + " batch-single " +
                                       describe_key(fresh_keys[0], current_incarnation));
    }
  }

  outcome.stats = classifier.stats();
}

// The authority context the classifier builds for itself: every registered publisher that
// is LIVE at its recorded boot, and no clock.
[[nodiscard]] aifc::AuthorityContext authority_of(const aifc::Classifier& classifier) {
  aifc::AuthorityContext authority;
  authority.epoch = classifier.epoch();
  authority.coordinator_boot = classifier.coordinator_boot();
  authority.tick = aifc::kTickNone;
  // The classifier does not expose its stores, and session liveness is volatile state that is
  // deliberately absent from the durable image, so the live sessions are read one identity at a
  // time through the public registration lookup.  This case registers exactly the peer indices
  // below and nothing else.
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    const aifc::Result<aifc::PublisherRegistration> registration =
        classifier.find_publisher(aifc_test::synthetic_publisher(index));
    if (!registration) continue;
    authority.known_publishers.insert(registration.value().id.value());
    if (registration.value().state == aifc::PublisherState::LIVE) {
      authority.live_publisher_boots.insert(
          aifc::AuthorityContext::boot_key(registration.value().id, registration.value().boot));
    }
  }
  return authority;
}

// Re-derives the decision for one flow from the store, single threaded, exactly as the
// classifier's own evaluation path does.  This test declares no workload or contract, so
// the contract-derived part of the input is empty in both paths.
[[nodiscard]] aifc::Result<aifc::Classification> rederive(const aifc::Classifier& classifier,
                                                         const aifc::FlowKey& key,
                                                         aifc::FlowGeneration generation) {
  const aifc::Result<aifc::FlowRecord> flow = classifier.find_flow(key);
  if (!flow) return flow.status();
  aifc::DecisionInput input;
  input.flow = flow.value();
  if (generation.value != 0U) input.flow.generation = generation;
  input.policy = classifier.policy();
  input.authority = authority_of(classifier);
  input.generation_revoked = false;
  const aifc::Result<std::vector<aifc::EvidenceId>> ids =
      classifier.evidence_for_flow(input.flow.id);
  if (!ids) return ids.status();
  for (const aifc::EvidenceId& id : ids.value()) {
    const aifc::Result<aifc::EvidenceRecord> record = classifier.find_evidence(id);
    if (record) input.evidence.push_back(record.value());
  }
  const aifc::DecisionEngine engine;
  return engine.decide(input);
}

// ---------------------------------------------------------------------------
// Case 1: the full concurrent mix
// ---------------------------------------------------------------------------

// SYNTHETIC evidence, REAL threads.  Eight workers submit evidence, register flows, classify,
// classify in batches and read stats() against one classifier, released together by a
// barrier, and every assertion is made after they have been joined.
AIFC_TEST("concurrency.classifier.mixed_workload_is_consistent") {
  const aifc::ClassifierPolicy policy = concurrency_policy();
  aifc_test::Harness harness(policy);
  aifc::Classifier& classifier = harness.classifier();

  std::vector<aifc_test::Harness::Peer> peers;
  peers.reserve(kThreads);
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    peers.push_back(harness.add_peer(index, ceiling_for(index)));
  }

  const aifc::FlowKey shared_key = aifc_test::synthetic_flow_key(kSharedFlowIndex);
  const aifc::FlowRecord shared_flow = harness.register_flow(peers[0], kSharedFlowIndex);
  const aifc::FlowGeneration shared_generation = shared_flow.generation;

  std::vector<aifc::FlowKey> private_keys;
  private_keys.reserve(kThreads);
  std::vector<aifc::FlowGeneration> private_generations;
  private_generations.reserve(kThreads);
  std::vector<aifc::FlowRecord> private_flows;
  private_flows.reserve(kThreads);
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    const aifc::FlowKey key = aifc_test::synthetic_flow_key(kPrivateFlowBase + index);
    private_keys.push_back(key);
    private_flows.push_back(harness.register_flow(peers[index], kPrivateFlowBase + index));
    private_generations.push_back(private_flows.back().generation);
  }

  // Setup counted 1 shared + kThreads private explicit registrations.
  const std::uint32_t setup_registrations = 1U + kThreads;

  std::vector<ThreadOutcome> outcomes(kThreads);
  for (std::uint32_t index = 0; index < kThreads; ++index) outcomes[index].index = index;

  std::barrier<> gate(static_cast<std::ptrdiff_t>(kThreads));
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    workers.emplace_back([&classifier, &peers, &private_keys, &private_generations, &shared_key,
                          shared_generation, index, &gate, &outcomes]() {
      worker(classifier, peers, private_keys, private_generations, shared_key, shared_generation,
             index, gate, outcomes[index]);
    });
  }
  for (std::thread& thread : workers) thread.join();

  // --- every worker's own view of its work -------------------------------------------
  std::uint32_t accepted_total = 0;
  std::uint32_t refused_total = 0;
  std::uint32_t classifications_total = 0;
  for (const ThreadOutcome& outcome : outcomes) {
    AIFC_CHECK_MSG(outcome.refused == 0U,
                   "thread " << outcome.index << " had " << outcome.refused
                             << " refused submissions: " << outcome.refusals.front());
    AIFC_CHECK_MSG(outcome.batches_ok,
                   "thread " << outcome.index << " reported a batch/registration problem: "
                             << outcome.batch_problem);
    // A counter read concurrently never goes backwards: the snapshot a worker took after its
    // own submissions must include them.
    AIFC_CHECK_MSG(outcome.stats.counters.evidence_accepted >= outcome.accepted,
                   "thread " << outcome.index << " accepted " << outcome.accepted
                             << " submissions but its stats() snapshot reported only "
                             << outcome.stats.counters.evidence_accepted << " accepted");
    AIFC_CHECK_MSG(outcome.stats.evidence.records >= static_cast<std::size_t>(outcome.accepted),
                   "thread " << outcome.index << " accepted " << outcome.accepted
                             << " submissions but its stats() snapshot reported only "
                             << outcome.stats.evidence.records << " stored records");
    AIFC_CHECK_MSG(outcome.stats.flows.size >= static_cast<std::size_t>(1U) + kThreads,
                   "thread " << outcome.index << " saw only " << outcome.stats.flows.size
                             << " registered flows, fewer than the " << (1U + kThreads)
                             << " that existed before the workers started");
    accepted_total += outcome.accepted;
    refused_total += outcome.refused;
    classifications_total += outcome.classifications;
  }

  const std::uint32_t expected_accepted =
      kThreads * (kSharedRecordsPerThread + kPrivateRecordsPerThread + kFreshFlowsPerThread);
  AIFC_CHECK_EQ(accepted_total, expected_accepted);
  AIFC_CHECK_EQ(refused_total, 0U);
  // Per thread: one classify of the shared flow, one of its private flow, three batch keys,
  // one classify of a fresh flow and one single-key batch.
  const std::uint32_t expected_classifications = kThreads * 7U;
  AIFC_CHECK_EQ(classifications_total, expected_classifications);

  // --- the captured stats agree with what the workers observed ------------------------
  const aifc::Classifier::Stats stats = classifier.stats();
  AIFC_CHECK_MSG(stats.counters.evidence_accepted == accepted_total,
                 "stats().counters.evidence_accepted=" << stats.counters.evidence_accepted
                                                       << " but the workers accepted "
                                                       << accepted_total << " submissions");
  AIFC_CHECK_MSG(stats.counters.evidence_refused == refused_total,
                 "stats().counters.evidence_refused=" << stats.counters.evidence_refused
                                                      << " but the workers saw " << refused_total
                                                      << " refusals");
  AIFC_CHECK_MSG(stats.evidence.records == accepted_total,
                 "stats().evidence.records=" << stats.evidence.records
                                             << " but " << accepted_total
                                             << " submissions were accepted (no eviction is "
                                                "expected at this size)");
  AIFC_CHECK_MSG(stats.evidence.evicted_records == 0U && stats.evidence.evicted_per_flow == 0U,
                 "evidence was evicted: records=" << stats.evidence.evicted_records
                                                  << " per_flow=" << stats.evidence.evicted_per_flow);
  AIFC_CHECK_MSG(stats.counters.classifications == classifications_total,
                 "stats().counters.classifications=" << stats.counters.classifications
                                                      << " but the workers performed "
                                                      << classifications_total
                                                      << " single-key classifications");
  AIFC_CHECK_EQ(stats.counters.batch_requests, static_cast<std::uint64_t>(kThreads) * 2U);
  AIFC_CHECK_EQ(stats.counters.batch_keys, static_cast<std::uint64_t>(kThreads) * 4U);
  AIFC_CHECK_EQ(stats.counters.flows_registered,
                static_cast<std::uint64_t>(setup_registrations) + 2U * kThreads +
                    static_cast<std::uint64_t>(kThreads) * kFreshFlowsPerThread + accepted_total);
  AIFC_CHECK_EQ(stats.counters.supersessions, static_cast<std::uint64_t>(kThreads) * 2U);
  AIFC_CHECK_EQ(stats.flows.size,
                static_cast<std::size_t>(1U) + kThreads + static_cast<std::size_t>(kThreads) * kFreshFlowsPerThread);
  AIFC_CHECK_MSG(stats.counters.contradictions > 0U,
                 "the shared flow carried four semantic classes across five source ranks, so at "
                 "least one contradiction was expected; stats().counters.contradictions="
                     << stats.counters.contradictions);

  // --- every accepted submission is visible in the store ------------------------------
  // --- every accepted submission is visible in the store ------------------------------
  std::size_t missing = 0;
  std::string first_missing;
  for (const ThreadOutcome& outcome : outcomes) {
    for (const aifc::EvidenceId& id : outcome.accepted_ids) {
      const aifc::Result<aifc::EvidenceRecord> record = classifier.find_evidence(id);
      if (record && record.value().id == id) continue;
      ++missing;
      if (first_missing.empty()) {
        first_missing = "thread=" + std::to_string(outcome.index) + " evidence=" + id.value() +
                        " error=" + (record ? std::string("identity mismatch")
                                            : aifc::render_status(record.status()));
      }
    }
  }
  AIFC_CHECK_MSG(missing == 0U, missing << " of " << accepted_total
                                        << " accepted submissions are not readable from the "
                                           "store; first: "
                                        << first_missing);

  const aifc::Result<std::vector<aifc::EvidenceId>> shared_evidence =
      classifier.evidence_for_flow(shared_flow.id);
  AIFC_CHECK_OK(shared_evidence);
  if (shared_evidence) {
    AIFC_CHECK_EQ(shared_evidence.value().size(),
                  static_cast<std::size_t>(kThreads) * kSharedRecordsPerThread);
  }

  // --- a classified flow's digest is reproducible from a single-threaded re-derivation --
  const aifc::Result<aifc::ClassificationResult> shared_result =
      classifier.classify(make_query(shared_key, aifc::FlowGeneration{0}));
  AIFC_CHECK_OK(shared_result);
  if (shared_result) {
    const aifc::Classification& live = shared_result.value().classification;
    const aifc::Result<aifc::Classification> derived =
        rederive(classifier, shared_key, live.flow_generation);
    AIFC_CHECK_OK(derived);
    if (derived) {
      AIFC_CHECK_MSG(derived.value().digest == live.digest,
                     "the shared flow's digest is not reproducible from a single-threaded "
                     "re-derivation over the same evidence: live="
                         << live.digest.to_hex() << " derived=" << derived.value().digest.to_hex()
                         << " " << describe_key(shared_key, live.flow_generation)
                         << " live_class=" << aifc::to_string(live.semantic)
                         << " derived_class=" << aifc::to_string(derived.value().semantic)
                         << " evidence_records=" << stats.evidence.records);
      AIFC_CHECK_MSG(derived.value().selected_evidence == live.selected_evidence,
                     "the re-derivation selected a different record: live="
                         << live.selected_evidence.value()
                         << " derived=" << derived.value().selected_evidence.value() << " "
                         << describe_key(shared_key, live.flow_generation));
    }
  }

  for (std::uint32_t index = 0; index < kThreads; ++index) {
    const aifc::Result<aifc::ClassificationResult> own =
        classifier.classify(make_query(private_keys[index], aifc::FlowGeneration{0}));
    AIFC_CHECK_OK(own);
    if (!own) continue;
    const aifc::Classification& live = own.value().classification;
    const aifc::Result<aifc::Classification> derived =
        rederive(classifier, private_keys[index], live.flow_generation);
    AIFC_CHECK_OK(derived);
    if (!derived) continue;
    AIFC_CHECK_MSG(derived.value().digest == live.digest,
                   "thread " << index << " private flow digest is not reproducible: live="
                             << live.digest.to_hex() << " derived=" << derived.value().digest.to_hex()
                             << " " << describe_key(private_keys[index], live.flow_generation)
                             << " flow_id=" << private_flows[index].id.to_hex());
  }
}

// ---------------------------------------------------------------------------
// Case 2: two concurrent classifications of one flow generation agree
// ---------------------------------------------------------------------------

// SYNTHETIC evidence, REAL threads.  Every worker classifies the same flow generation at the
// same time; all answers must be the same answer, whether each one came from the memo or from
// a fresh evaluation.
AIFC_TEST("concurrency.classifier.concurrent_classifications_of_one_generation_agree") {
  const aifc::ClassifierPolicy policy = concurrency_policy();
  aifc_test::Harness harness(policy);
  aifc::Classifier& classifier = harness.classifier();

  std::vector<aifc_test::Harness::Peer> peers;
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    peers.push_back(harness.add_peer(index, ceiling_for(index)));
  }
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(kSharedFlowIndex);
  const aifc::FlowRecord flow = harness.register_flow(peers[0], kSharedFlowIndex);

  for (std::uint32_t index = 0; index < kThreads; ++index) {
    aifc::EvidencePayload payload;
    payload.flow_key = key;
    payload.flow_generation = flow.generation;
    payload.evidence_generation = aifc::EvidenceGeneration{1};
    payload.semantic = class_for(index);
    payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.topic = "ct" + std::to_string(index);
    const aifc::Result<aifc::EvidenceSubmissionOutcome> submitted =
        classifier.submit_evidence(peers[index].envelope, payload);
    AIFC_CHECK_OK(submitted);
  }

  const aifc::Result<aifc::ClassificationResult> reference =
      classifier.classify(make_query(key, flow.generation));
  AIFC_CHECK_OK(reference);
  if (!reference) return;

  std::vector<std::vector<aifc::Digest256>> observed(kThreads);
  std::barrier<> gate(static_cast<std::ptrdiff_t>(kThreads));
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    workers.emplace_back([&classifier, &key, &flow, index, &gate, &observed]() {
      gate.arrive_and_wait();
      for (std::uint32_t round = 0; round < kConcurrentClassifyRounds; ++round) {
        const aifc::Result<aifc::ClassificationResult> result =
            classifier.classify(make_query(key, flow.generation));
        if (!result) {
          observed[index].push_back(aifc::Digest256{});
          continue;
        }
        observed[index].push_back(result.value().classification.digest);
      }
    });
  }
  for (std::thread& thread : workers) thread.join();

  const aifc::Digest256 expected = reference.value().classification.digest;
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    AIFC_CHECK_EQ(observed[index].size(), static_cast<std::size_t>(kConcurrentClassifyRounds));
    for (std::size_t round = 0; round < observed[index].size(); ++round) {
      if (observed[index][round] == expected) continue;
      AIFC_CHECK_MSG(false, "thread " << index << " round " << round
                                      << " produced a different answer for the same generation: "
                                      << describe_key(key, flow.generation) << " expected="
                                      << expected.to_hex() << " observed="
                                      << observed[index][round].to_hex() << " class="
                                      << aifc::to_string(reference.value().classification.semantic)
                                      << " evidence_records=" << classifier.stats().evidence.records);
      break;
    }
  }
}

// ---------------------------------------------------------------------------
// Case 3: ending a publisher session during classification
// ---------------------------------------------------------------------------

// SYNTHETIC evidence, REAL threads.  One thread ends a publisher session while other threads
// classify the flow that publisher contributed to.  Every observed answer must be either the
// pre-end answer or the post-end answer: a classification may be early or late, but it may
// never be a mixture of the two states.
AIFC_TEST("concurrency.classifier.session_end_races_classification_without_a_third_answer") {
  const aifc::ClassifierPolicy policy = concurrency_policy();
  aifc_test::Harness harness(policy);
  aifc::Classifier& classifier = harness.classifier();

  std::vector<aifc_test::Harness::Peer> peers;
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    peers.push_back(harness.add_peer(index, ceiling_for(index)));
  }
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(kSharedFlowIndex);
  const aifc::FlowRecord flow = harness.register_flow(peers[0], kSharedFlowIndex);

  // Peer 0 is the strongest session; every peer publishes so that the flow has both a
  // declaration and other current records.
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    aifc::EvidencePayload payload;
    payload.flow_key = key;
    payload.flow_generation = flow.generation;
    payload.evidence_generation = aifc::EvidenceGeneration{1};
    payload.semantic = class_for(index);
    payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.topic = "race" + std::to_string(index);
    const aifc::Result<aifc::EvidenceSubmissionOutcome> submitted =
        classifier.submit_evidence(peers[index].envelope, payload);
    AIFC_CHECK_OK(submitted);
  }

  const aifc::Result<aifc::ClassificationResult> before =
      classifier.classify(make_query(key, flow.generation));
  AIFC_CHECK_OK(before);
  if (!before) return;
  const aifc::Digest256 pre_end = before.value().classification.digest;

  std::vector<std::vector<aifc::Digest256>> observed(kThreads);
  std::barrier<> gate(static_cast<std::ptrdiff_t>(kThreads + 1U));
  std::atomic<std::uint32_t> ender_state{0};
  aifc::Status end_status;
  std::thread ender([&classifier, &peers, &gate, &ender_state, &end_status]() {
    gate.arrive_and_wait();
    end_status = classifier.end_publisher_session(peers[0].publisher, peers[0].boot);
    ender_state.store(end_status.ok() ? 1U : 2U, std::memory_order_release);
  });

  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (std::uint32_t index = 0; index < kThreads; ++index) {
    workers.emplace_back([&classifier, &key, &flow, index, &gate, &observed]() {
      gate.arrive_and_wait();
      for (std::uint32_t round = 0; round < kConcurrentClassifyRounds; ++round) {
        const aifc::Result<aifc::ClassificationResult> result =
            classifier.classify(make_query(key, flow.generation));
        observed[index].push_back(result ? result.value().classification.digest
                                         : aifc::Digest256{});
      }
    });
  }
  ender.join();
  for (std::thread& thread : workers) thread.join();

  AIFC_CHECK_MSG(ender_state.load(std::memory_order_acquire) == 1U,
                 "end_publisher_session failed: " << aifc::render_status(end_status));

  const aifc::Result<aifc::ClassificationResult> after =
      classifier.classify(make_query(key, flow.generation));
  AIFC_CHECK_OK(after);
  if (!after) return;
  const aifc::Classification post_end = after.value().classification;
  AIFC_CHECK_MSG(post_end.digest != pre_end,
                 "the session end did not change the answer, so the race proved nothing: "
                     << describe_key(key, flow.generation) << " digest=" << pre_end.to_hex()
                     << " selected=" << post_end.selected_evidence.value() << " state="
                     << aifc::to_string(post_end.state));

  for (std::uint32_t index = 0; index < kThreads; ++index) {
    for (std::size_t round = 0; round < observed[index].size(); ++round) {
      const aifc::Digest256& digest = observed[index][round];
      if (digest == pre_end || digest == post_end.digest) continue;
      AIFC_CHECK_MSG(false, "thread " << index << " round " << round
                                      << " observed an answer that is neither the pre-end nor the "
                                         "post-end answer: "
                                      << describe_key(key, flow.generation) << " observed="
                                      << digest.to_hex() << " pre_end=" << pre_end.to_hex()
                                      << " post_end=" << post_end.digest.to_hex()
                                      << " pre_end_state="
                                      << aifc::to_string(before.value().classification.state)
                                      << " post_end_state=" << aifc::to_string(post_end.state)
                                      << " post_end_selected="
                                      << post_end.selected_evidence.value());
      break;
    }
  }
}

}  // namespace
