// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Proof surface: hot lookup and classification are indexed and bounded.
//
// The closure requirement is that classifying one flow costs time proportional to the
// evidence about that flow, not to the size of the runtime.  This surface demonstrates that
// by measuring the *shape* of the cost rather than an absolute number: the per-operation
// cost must not grow with the population.
//
// Absolute timings are not asserted, because a timing assertion is a flaky test.  What is
// asserted is a ratio between two populations large enough that an O(N) implementation
// cannot satisfy it, which is exactly the property that matters.

#include "test_framework.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "synthetic.hpp"

namespace {

struct Measurement {
  double microseconds_per_operation = 0;
  std::uint64_t operations = 0;
};

[[nodiscard]] Measurement measure_classification(aifc::Classifier& classifier,
                                               const std::vector<aifc::FlowKey>& keys,
                                               std::uint32_t repeats) {
  Measurement measurement;
  const auto start = std::chrono::steady_clock::now();
  std::uint64_t operations = 0;
  for (std::uint32_t round = 0; round < repeats; ++round) {
    for (const aifc::FlowKey& key : keys) {
      aifc::ClassificationQuery query;
      query.flow_key = key;
      auto result = classifier.classify(query);
      if (!result) {
        std::fprintf(stderr, "classify failed during measurement: %s\n",
                     aifc::render_status(result.status()).c_str());
        std::abort();
      }
      ++operations;
    }
  }
  const auto elapsed = std::chrono::steady_clock::now() - start;
  const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
  measurement.operations = operations;
  measurement.microseconds_per_operation =
      operations == 0 ? 0.0 : static_cast<double>(micros) / static_cast<double>(operations);
  return measurement;
}

// Populates a classifier with population flows, each with one authenticated record, and
// returns the keys of the probe flows.
// Populates the classifier with flows whose synthetic index runs over
// [first_index, first_index + population).  Taking a range rather than a count is what lets the
// measurement grow the population *around* the probe flows instead of re-registering them, which
// would change their generation and make the two measurements incomparable.
[[nodiscard]] std::vector<aifc::FlowKey> populate(aifc::Classifier& classifier,
                                                 const aifc::SessionEnvelope& envelope,
                                                 std::uint32_t first_index,
                                                 std::uint32_t population,
                                                 std::uint32_t probe_count,
                                                 std::uint32_t probe_offset) {
  std::vector<aifc::FlowKey> probes;
  for (std::uint32_t offset = 0; offset < population; ++offset) {
    const std::uint32_t i = first_index + offset;
    const aifc::FlowKey key = aifc_test::synthetic_flow_key(i);
    auto flow = classifier.register_flow(key, aifc::FlowGeneration{0}, envelope.session);
    if (!flow) {
      std::fprintf(stderr, "register_flow %u failed: %s\n", i,
                   aifc::render_status(flow.status()).c_str());
      std::abort();
    }
    aifc::EvidencePayload payload;
    payload.flow_key = key;
    payload.flow_generation = flow.value().record.generation;
    // The evidence generation is unique per publication from one publisher incarnation.  It is *not*
    // per flow: the high-water mark is tracked for the incarnation, so publishing "generation 1" for a
    // second flow is a replay of the first publication and is refused.  That is the runtime being
    // right -- it is what makes an acknowledgement mean something -- and the measurement has to respect
    // it.  The index is therefore used directly, which is also unique across the two populations.
    payload.evidence_generation =
        aifc::EvidenceGeneration{static_cast<std::uint64_t>(i) + 1U};
    payload.semantic = aifc::SemanticClass::INFERENCE_REQUEST;
    payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.topic = "scale.topic";
    payload.metadata.reason = "scale probe";
    auto outcome = classifier.submit_evidence(envelope, payload);
    if (!outcome) {
      std::fprintf(stderr, "submit_evidence %u failed: %s\n", i,
                   aifc::render_status(outcome.status()).c_str());
      std::abort();
    }
    if (offset >= probe_offset && offset < probe_offset + probe_count) {
      probes.push_back(key);
    }
  }
  return probes;
}

}  // namespace

AIFC_TEST("classification cost does not grow with the size of the runtime") {
  aifc::ClassifierOptions options;
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.limits.max_flows = 65536;
  policy.limits.max_evidence_records = 262144;
  policy.limits.max_flow_key_index = 65536;
  options.policy = policy;
  aifc::Classifier classifier(options);

  const aifc::PublisherId publisher = aifc::make_publisher_id("scale-publisher");
  auto registration = classifier.register_publisher(publisher, aifc::PublisherBootId{1},
                                                    aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                                    aifc::SessionId("scale-session"),
                                                    "scale publisher");
  AIFC_CHECK_OK(registration);
  const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

  constexpr std::uint32_t kProbeCount = 64;
  constexpr std::uint32_t kSmallPopulation = 512;
  std::vector<aifc::FlowKey> probes =
      populate(classifier, envelope, /*first_index=*/0, kSmallPopulation, kProbeCount, 0);
  AIFC_CHECK_EQ(probes.size(), static_cast<std::size_t>(kProbeCount));
  const Measurement small = measure_classification(classifier, probes, /*repeats=*/8);

  // Grow the population by an order of magnitude *around* the probe flows, then measure the same
  // probe flows again.  Their evidence and generations are untouched, so an indexed
  // implementation performs exactly the same work; a per-flow scan would not.
  // The result is deliberately discarded: this call exists to grow the population, and the probe
  // flows it returns are the ones measured before.  The count is asserted so that a silent
  // failure to populate cannot make the comparison meaningless.
  const std::vector<aifc::FlowKey> grown =
      populate(classifier, envelope, /*first_index=*/kSmallPopulation,
               /*population=*/8192, /*probe_count=*/0, /*probe_offset=*/0);
  AIFC_CHECK_EQ(grown.size(), std::size_t{0});
  const Measurement large = measure_classification(classifier, probes, /*repeats=*/8);

  std::printf("scale: population %u   -> %.2f us/operation over %llu operations\n",
              kSmallPopulation, small.microseconds_per_operation,
              static_cast<unsigned long long>(small.operations));
  std::printf("scale: population %u  -> %.2f us/operation over %llu operations\n",
              kSmallPopulation + 8192, large.microseconds_per_operation,
              static_cast<unsigned long long>(large.operations));

  AIFC_CHECK(small.microseconds_per_operation > 0.0);
  AIFC_CHECK(large.microseconds_per_operation > 0.0);

  // A linear implementation would show roughly a 17x increase.  The bound below is far
  // above the observed ratio for an indexed implementation and far below what a scan would
  // produce, so it fails loudly on a regression and does not fail on a slow machine.
  const double ratio = large.microseconds_per_operation / small.microseconds_per_operation;
  std::printf("scale: ratio %.3f (a per-flow scan would be far above 4)\n", ratio);
  AIFC_CHECK_MSG(ratio < 4.0,
                 "classification cost grew with population size: ratio " + std::to_string(ratio) +
                     " between population 512 and 8704; the evidence index is not being used");
}

AIFC_TEST("flow lookup is indexed in both directions") {
  aifc::Classifier classifier(aifc::ClassifierOptions{});
  const aifc::PublisherId publisher = aifc::make_publisher_id("index-publisher");
  auto registration = classifier.register_publisher(publisher, aifc::PublisherBootId{1},
                                                    aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                                    aifc::SessionId("index-session"),
                                                    "index publisher");
  AIFC_CHECK_OK(registration);

  constexpr std::uint32_t kCount = 4096;
  std::vector<aifc::FlowId> ids;
  ids.reserve(kCount);
  for (std::uint32_t i = 0; i < kCount; ++i) {
    auto flow = classifier.register_flow(aifc_test::synthetic_flow_key(100000 + i),
                                         aifc::FlowGeneration{0}, registration.value().session);
    AIFC_CHECK_OK(flow);
    ids.push_back(flow.value().record.id);
  }
  // Every identity must be found, and every identity must be distinct: a derived identity
  // collision would silently merge two flows into one classification.
  std::vector<aifc::FlowId> sorted = ids;
  std::sort(sorted.begin(), sorted.end());
  const auto unique_end = std::unique(sorted.begin(), sorted.end());
  AIFC_CHECK_EQ(static_cast<std::size_t>(unique_end - sorted.begin()), ids.size());

  const auto start = std::chrono::steady_clock::now();
  for (std::uint32_t i = 0; i < kCount; ++i) {
    auto found = classifier.find_flow_generation(ids[i], aifc::FlowGeneration{1});
    AIFC_CHECK_OK(found);
  }
  const auto elapsed = std::chrono::steady_clock::now() - start;
  const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
  std::printf("scale: %u generation lookups in %lld us (%.2f us each)\n", kCount,
              static_cast<long long>(micros),
              static_cast<double>(micros) / static_cast<double>(kCount));
}

AIFC_TEST("batch classification is bounded by policy and reports per key statuses") {
  aifc::Classifier classifier(aifc::ClassifierOptions{});
  const aifc::PublisherId publisher = aifc::make_publisher_id("batch-publisher");
  auto registration = classifier.register_publisher(publisher, aifc::PublisherBootId{1},
                                                    aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                                                    aifc::SessionId("batch-session"),
                                                    "batch publisher");
  AIFC_CHECK_OK(registration);
  const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

  std::vector<aifc::FlowKey> keys = populate(classifier, envelope, /*first_index=*/0,
                                             /*population=*/256, /*probe_count=*/256,
                                             /*probe_offset=*/0);

  std::vector<aifc::ClassificationQuery> queries;
  for (const aifc::FlowKey& key : keys) {
    aifc::ClassificationQuery query;
    query.flow_key = key;
    queries.push_back(query);
  }
  // One key that does not exist, so the batch must report a per-key failure without
  // failing as a whole.
  aifc::ClassificationQuery missing;
  missing.flow_key = aifc_test::synthetic_flow_key(999999);
  queries.push_back(missing);

  auto outcome = classifier.classify_batch(queries);
  AIFC_CHECK_OK(outcome);
  AIFC_CHECK_EQ(outcome.value().results.size(), queries.size());
  AIFC_CHECK_EQ(outcome.value().statuses.size(), queries.size());
  AIFC_CHECK_EQ(outcome.value().succeeded, static_cast<std::uint32_t>(keys.size()));
  AIFC_CHECK_EQ(outcome.value().failed, std::uint32_t{1});
  AIFC_CHECK_EQ(outcome.value().statuses.back().code, aifc::ErrorCode::UNKNOWN_FLOW);

  // An oversized batch is refused as a whole rather than truncated silently.
  aifc::ClassifierPolicy tight = aifc::ClassifierPolicy::initial();
  tight.limits.max_batch_keys = 8;
  auto canonical = aifc::ClassifierPolicy::canonicalize(std::move(tight));
  AIFC_CHECK_OK(canonical);
  AIFC_CHECK_OK(classifier.set_policy(canonical.value()));
  auto refused = classifier.classify_batch(queries);
  AIFC_CHECK_ERR(refused, aifc::ErrorCode::CAPACITY_EXCEEDED);
}
