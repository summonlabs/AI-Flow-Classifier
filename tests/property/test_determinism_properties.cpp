// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Property tests for decision determinism.
//
// REAL / SYNTHETIC
// ----------------
// The canonical evidence set is SYNTHETIC: five fabricated publishers, one fabricated flow
// and five fabricated evidence records.  Everything asserted about it is REAL runtime
// behaviour reached through the public API: aifc::Classifier submits the evidence,
// aifc::DecisionEngine produces the classification, aifc::compute_classification_digest
// covers it, and the snapshot writer/reader plus the record codec carry it to a file and
// back.
//
// What is asserted (each is a separate case):
//   (a) classifying the same evidence twice in one process yields an identical digest;
//   (b) rebuilding an equivalent classifier from scratch and feeding the same canonical
//       evidence yields the same digest;
//   (c) permuting the order in which evidence is submitted yields the same digest;
//   (d) changing one content-bearing field of one record changes the digest -- for every
//       reachable mutation, with the number of applied mutations asserted so the case
//       cannot become vacuous;
//   (e) a snapshot file round trip plus a per-record codec round trip preserves the
//       decision;
//   (f) a claim above the session ceiling is clamped, and the clamp does not change the
//       decision, because the peer cannot promote itself.
//
// Honest boundary: the classification digest is defined (domain/classification.hpp) to
// cover decision content only.  Acceptance bookkeeping (accepted_seq, accepted_tick, the
// freshness window) is deliberately excluded, so mutating those fields alone is *not*
// expected to change it; that is why (d) mutates identity, source, class, evidence
// generation and topic, which are the content-bearing fields the digest contract names.
//
// Reproduction
// ------------
//     set AIFC_TEST_SEED=0x0123456789abcdef
//     build\tests-b\bin\test_determinism_properties.exe
// Every failure message carries the seed it used and the same replay instruction.

#include <cstdint>
#include <cstdlib>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "synthetic.hpp"
#include "test_framework.hpp"

namespace {

// ---------------------------------------------------------------------------
// Seeded case driver
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint64_t parse_seed_text(const std::string& text) {
  try {
    std::size_t consumed = 0;
    const std::uint64_t value = std::stoull(text, &consumed, 0);
    if (consumed == text.size()) return value;
  } catch (const std::exception&) {
    // Not a number: fall through to the deterministic text hash below.
  }
  return aifc::seed_from_text(text);
}

[[nodiscard]] std::uint64_t resolve_seed(const std::string& name) {
  const char* override_text = std::getenv("AIFC_TEST_SEED");
  if (override_text != nullptr && *override_text != '\0') return parse_seed_text(override_text);
  return aifc::seed_from_text(name);
}

[[nodiscard]] std::string replay_hint(const std::string& name, std::uint64_t seed) {
  std::ostringstream out;
  out << "case=" << name << " " << aifc::format_seed(seed)
      << " [replay: set AIFC_TEST_SEED=" << seed << "]";
  return out.str();
}

template <typename T>
void shuffle(std::vector<T>& values, aifc::Rng& rng) {
  if (values.size() < 2) return;
  for (std::size_t i = values.size() - 1; i > 0; --i) {
    const std::size_t j = static_cast<std::size_t>(rng.next_below(i + 1U));
    const T swap = values[i];
    values[i] = values[j];
    values[j] = swap;
  }
}

// ---------------------------------------------------------------------------
// The canonical evidence set
// ---------------------------------------------------------------------------

// Peer 0..4 hold one evidence-source ceiling each, strongest first.  Peers 10..14 are
// spare identities with the same ceilings, used by the "publisher identity changed"
// mutation so that a mutation never needs to raise a ceiling.
constexpr std::uint32_t kPeerCount = 5U;
constexpr std::uint32_t kSparePeerBase = 10U;
constexpr std::uint32_t kFlowIndex = 0U;

[[nodiscard]] aifc::EvidenceSource peer_ceiling(std::uint32_t index) {
  switch (index % kPeerCount) {
    case 0U:
      return aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    case 1U:
      return aifc::EvidenceSource::CONTRACT_DERIVED;
    case 2U:
      return aifc::EvidenceSource::COORDINATOR_CORRELATED;
    case 3U:
      return aifc::EvidenceSource::TOPOLOGY_CORRELATED;
    default:
      // No peer in this file holds a HEURISTIC ceiling: a claim that has to be clamped down to
      // HEURISTIC is refused by the admission gate unless the policy declares an enabled adapter,
      // so a heuristic ceiling would make the ceiling itself untestable here.
      return aifc::EvidenceSource::TOPOLOGY_CORRELATED;
  }
}

// Heuristic admission is not exercised here.  A heuristic submission is refused unless the
// policy also declares an enabled adapter *and* the submission cites a declared port hint; that
// gate is not what this file is about, and heuristic precedence itself is asserted where it
// belongs, at the engine level, by tests/property/test_precedence_properties.cpp.
//
// The freshness window is widened deliberately.  A Classifier without an explicit clock
// reads a real monotonic source, so with the default 4096 tick window a long-running test
// process could let a record expire between two classifications, which would make this case
// depend on the wall clock.  Widening the window removes time from the inputs; the freshness
// boundary itself is exercised with aifc::ManualTickSource by the surfaces that own it.
[[nodiscard]] aifc::ClassifierPolicy canonical_policy() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.default_freshness_window = 60000000ULL;
  policy.limits.default_freshness_window = 60000000ULL;
  return aifc::ClassifierPolicy::canonicalize(policy).value();
}

[[nodiscard]] aifc::FlowKey canonical_flow_key() {
  return aifc_test::synthetic_flow_key(kFlowIndex);
}

struct RecordSpec {
  std::uint32_t peer = 0;
  aifc::SemanticClass semantic = aifc::SemanticClass::UNKNOWN;
  aifc::EvidenceGeneration generation;
  aifc::EvidenceSource claimed = aifc::EvidenceSource::HEURISTIC;
  std::string topic;
};

[[nodiscard]] std::vector<RecordSpec> canonical_specs() {
  std::vector<RecordSpec> specs;
  specs.push_back(RecordSpec{0U, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                             aifc::EvidenceSource::DECLARED_AUTHENTICATED, "topic-alpha"});
  specs.push_back(RecordSpec{1U, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                             aifc::EvidenceSource::CONTRACT_DERIVED, "topic-beta"});
  specs.push_back(RecordSpec{2U, aifc::SemanticClass::INFERENCE_REQUEST, aifc::EvidenceGeneration{1},
                             aifc::EvidenceSource::COORDINATOR_CORRELATED, "topic-gamma"});
  specs.push_back(RecordSpec{3U, aifc::SemanticClass::KV_STATE_TRANSFER, aifc::EvidenceGeneration{1},
                             aifc::EvidenceSource::TOPOLOGY_CORRELATED, "topic-delta"});
  // The fifth record agrees with the winner and duplicates the fourth record's source rank.  Two
  // records at one rank must not both contradict: the contradiction list is ordered by precedence,
  // and precedence ties are broken by the acceptance sequence, so two tied contradicting records
  // would make the list order -- and therefore the digest -- depend on the submission order.
  specs.push_back(RecordSpec{4U, aifc::SemanticClass::COLLECTIVE, aifc::EvidenceGeneration{1},
                             aifc::EvidenceSource::TOPOLOGY_CORRELATED, "topic-epsilon"});
  return specs;
}

[[nodiscard]] std::vector<std::uint32_t> canonical_peer_order() {
  return std::vector<std::uint32_t>{0U, 1U, 2U, 3U, 4U};
}

struct RunRequest {
  std::vector<std::uint32_t> peer_order;
  std::vector<RecordSpec> specs;
};

[[nodiscard]] RunRequest canonical_request() {
  RunRequest request;
  request.peer_order = canonical_peer_order();
  request.specs = canonical_specs();
  return request;
}

[[nodiscard]] std::string describe_request(const RunRequest& request) {
  std::ostringstream out;
  out << "flow_key=" << canonical_flow_key().to_string() << " generation=1 peers=[";
  for (std::size_t i = 0; i < request.peer_order.size(); ++i) {
    if (i != 0) out << ",";
    out << request.peer_order[i];
  }
  out << "] records=[";
  for (std::size_t i = 0; i < request.specs.size(); ++i) {
    const RecordSpec& spec = request.specs[i];
    if (i != 0) out << ", ";
    out << "#" << i << "{peer=" << spec.peer << " class=" << aifc::to_string(spec.semantic)
        << " claimed=" << aifc::to_string(spec.claimed)
        << " generation=" << spec.generation.to_string() << " topic=" << spec.topic << "}";
  }
  out << "]";
  return out.str();
}

// ---------------------------------------------------------------------------
// Building and classifying the canonical set
// ---------------------------------------------------------------------------

struct ClassificationPair {
  aifc::Classification first;
  aifc::Classification second;
  bool first_memo_hit = false;
  bool second_memo_hit = false;
  std::string fingerprint;
};

// Every content-bearing field of a decision, rendered.  Two classifications with equal
// fingerprints are the same decision; the digest is asserted separately, so a fingerprint
// mismatch is a diagnosis rather than the only evidence.
[[nodiscard]] std::string fingerprint(const aifc::Classification& classification) {
  std::ostringstream out;
  out << "flow=" << classification.flow_id.to_hex()
      << " generation=" << classification.flow_generation.to_string()
      << " semantic=" << aifc::to_string(classification.semantic)
      << " state=" << aifc::to_string(classification.state)
      << " confidence=" << classification.confidence.to_decimal()
      << " selected=" << classification.selected_evidence.value()
      << " selected_source=" << aifc::to_string(classification.selected_source)
      << " corroboration=" << classification.corroboration_count
      << " penalty=" << classification.applied_penalty_basis_points
      << " policy_generation=" << classification.policy_generation.to_string()
      << " policy_digest=" << classification.policy_digest.to_hex()
      << " digest=" << classification.digest.to_hex();
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    out << "\n  citation " << citation.id.value() << " publisher=" << citation.publisher.value()
        << " source=" << aifc::to_string(citation.source)
        << " state=" << aifc::to_string(citation.state)
        << " semantic=" << aifc::to_string(citation.semantic)
        << " disposition=" << aifc::to_string(citation.disposition)
        << " confidence=" << citation.confidence.to_decimal()
        << " generation=" << citation.generation.to_string();
  }
  for (const aifc::ClassificationContradiction& contradiction : classification.contradictions) {
    out << "\n  contradiction " << contradiction.left_id.value() << "("
        << aifc::to_string(contradiction.left_class) << "/"
        << aifc::to_string(contradiction.left_source) << ") vs "
        << contradiction.right_id.value() << "(" << aifc::to_string(contradiction.right_class)
        << "/" << aifc::to_string(contradiction.right_source) << ") resolved_by=\""
        << contradiction.resolved_by << "\"";
  }
  return out.str();
}

// Builds one classifier, registers the peers, registers the flow, publishes the records in
// the requested order, classifies twice, and hands the live classifier to the observer.
template <typename Observe>
void build_and_classify(const aifc::ClassifierPolicy& policy, const RunRequest& request,
                        Observe&& observe) {
  aifc_test::Harness harness(policy);
  std::map<std::uint32_t, aifc_test::Harness::Peer> peers;
  for (const std::uint32_t index : request.peer_order) {
    peers[index] = harness.add_peer(index, peer_ceiling(index));
  }
  const aifc::FlowRecord flow = harness.register_flow(peers.at(0U), kFlowIndex);

  std::vector<aifc::EvidenceRecord> records;
  records.reserve(request.specs.size());
  for (const RecordSpec& spec : request.specs) {
    records.push_back(harness.publish(peers.at(spec.peer), flow, spec.semantic, spec.generation,
                                      spec.claimed, spec.topic));
  }

  ClassificationPair pair;
  const aifc::ClassificationResult first = harness.classify(flow.key);
  pair.first = first.classification;
  pair.first_memo_hit = first.memo_hit;
  const aifc::ClassificationResult second = harness.classify(flow.key);
  pair.second = second.classification;
  pair.second_memo_hit = second.memo_hit;
  pair.fingerprint = fingerprint(pair.first);
  observe(harness, flow, records, pair);
}

[[nodiscard]] ClassificationPair classify_pair(const aifc::ClassifierPolicy& policy,
                                               const RunRequest& request) {
  ClassificationPair pair;
  build_and_classify(policy, request,
                     [&pair](aifc_test::Harness&, const aifc::FlowRecord&,
                             const std::vector<aifc::EvidenceRecord>&,
                             const ClassificationPair& produced) { pair = produced; });
  return pair;
}

// A classification query for one flow generation.  Generation zero means "the current
// incarnation"; a named generation asks about exactly that incarnation.
[[nodiscard]] aifc::ClassificationQuery make_query(const aifc::FlowKey& key,
                                                   aifc::FlowGeneration generation) {
  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.flow_generation = generation;
  query.accept_current_generation = generation.value == 0U;
  return query;
}

// The authority context the classifier itself builds: every registered publisher that is
// LIVE at its recorded boot, and no clock.
[[nodiscard]] aifc::AuthorityContext authority_of(const aifc::Classifier& classifier) {
  aifc::AuthorityContext authority;
  authority.epoch = classifier.epoch();
  authority.coordinator_boot = classifier.coordinator_boot();
  authority.tick = aifc::kTickNone;
  // The classifier no longer exposes its stores, and session liveness is volatile state that is
  // deliberately absent from the durable image, so the live sessions are read one identity at a
  // time through the public registration lookup.  The set of identities this file registers is
  // exactly the peer indices below.
  for (std::uint32_t index = 0; index < kPeerCount; ++index) {
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

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

enum class MutationKind : std::uint8_t {
  Semantic = 0,
  Source = 1,
  EvidenceGeneration = 2,
  Topic = 3,
  Publisher = 4,
};

[[nodiscard]] const char* mutation_name(MutationKind kind) {
  switch (kind) {
    case MutationKind::Semantic:
      return "semantic_class";
    case MutationKind::Source:
      return "claimed_source";
    case MutationKind::EvidenceGeneration:
      return "evidence_generation";
    case MutationKind::Topic:
      return "metadata_topic";
    default:
      return "publisher_identity";
  }
}

[[nodiscard]] aifc::SemanticClass other_class(aifc::SemanticClass current) {
  return current == aifc::SemanticClass::COLLECTIVE ? aifc::SemanticClass::TELEMETRY
                                                    : aifc::SemanticClass::COLLECTIVE;
}

[[nodiscard]] aifc::EvidenceSource weaker_source(aifc::EvidenceSource current) {
  switch (current) {
    case aifc::EvidenceSource::DECLARED_AUTHENTICATED:
      return aifc::EvidenceSource::CONTRACT_DERIVED;
    case aifc::EvidenceSource::CONTRACT_DERIVED:
      return aifc::EvidenceSource::COORDINATOR_CORRELATED;
    case aifc::EvidenceSource::COORDINATOR_CORRELATED:
      return aifc::EvidenceSource::TOPOLOGY_CORRELATED;
    default:
      // TOPOLOGY_CORRELATED is the weakest source this file submits.  The rank beneath it is
      // HEURISTIC, and a heuristic submission is refused unless the policy declares an enabled
      // adapter and the submission cites a declared hint, so there is no weaker reachable source.
      return aifc::EvidenceSource::UNKNOWN;
  }
}

// Applies one mutation to one record of the request.  Returns false when the mutation is not
// reachable through the public API: the claimed source cannot be lowered below
// TOPOLOGY_CORRELATED, because the rank beneath it is HEURISTIC and a heuristic submission needs a
// declared, enabled adapter and a cited hint.
[[nodiscard]] bool apply_mutation(RunRequest& request, std::size_t index, MutationKind kind) {
  RecordSpec& spec = request.specs[index];
  switch (kind) {
    case MutationKind::Semantic:
      spec.semantic = other_class(spec.semantic);
      return true;
    case MutationKind::Source: {
      const aifc::EvidenceSource weaker = weaker_source(peer_ceiling(spec.peer));
      if (weaker == aifc::EvidenceSource::UNKNOWN) return false;
      spec.claimed = weaker;
      return true;
    }
    case MutationKind::EvidenceGeneration:
      spec.generation = aifc::EvidenceGeneration{spec.generation.value + 1U};
      return true;
    case MutationKind::Topic:
      spec.topic += "-mutated";
      return true;
    default: {
      const std::uint32_t replacement = kSparePeerBase + spec.peer;
      spec.peer = replacement;
      request.peer_order.push_back(replacement);
      return true;
    }
  }
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

// REAL runtime, SYNTHETIC evidence.  (a) and (b): the same classifier and an independently
// rebuilt classifier agree exactly, twice over.  The canonical decision is pinned first, so
// the case cannot pass by classifying nothing.
AIFC_TEST("determinism.same_process_and_rebuilt_classifier_agree") {
  const aifc::ClassifierPolicy policy = canonical_policy();
  const ClassificationPair baseline = classify_pair(policy, canonical_request());

  // A repeated classification of an unchanged evidence set must produce the same answer.  It is
  // deliberately *not* required to be a memo hit: compute_evidence_set_digest() folds the tick
  // into the decision key, because a decision computed while a record was fresh must not be
  // reused after it expired.  With the monotonic clock a Classifier uses by default, two calls
  // are therefore normally two evaluations, which is the stronger of the two checks.  The memo
  // path itself is pinned separately by "determinism.memoised_and_fresh_evaluations_agree",
  // which walks a manual clock so that two calls really do share one tick.
  AIFC_CHECK_MSG(!baseline.first_memo_hit,
                 "the first classification of an evidence set must be a fresh evaluation");
  AIFC_CHECK_EQ(baseline.first.digest, baseline.second.digest);
  AIFC_CHECK_EQ(baseline.fingerprint, fingerprint(baseline.second));
  AIFC_CHECK_EQ(baseline.first.digest, aifc::compute_classification_digest(baseline.first));

  // The canonical set is: peer 0 declares COLLECTIVE (the winner), peers 1 and 4 corroborate it,
  // and peers 2 and 3 contradict it from two different ranks.
  AIFC_CHECK_MSG(baseline.first.semantic == aifc::SemanticClass::COLLECTIVE,
                 "canonical decision changed: " << baseline.fingerprint);
  AIFC_CHECK_MSG(baseline.first.state == aifc::ClassificationState::CONTRADICTED,
                 "canonical decision changed: " << baseline.fingerprint);
  AIFC_CHECK_MSG(baseline.first.selected_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                 "canonical decision changed: " << baseline.fingerprint);
  AIFC_CHECK_EQ(baseline.first.contradictions.size(), static_cast<std::size_t>(2));
  AIFC_CHECK_EQ(baseline.first.corroboration_count, 2U);
  AIFC_CHECK_EQ(baseline.first.citations.size(), static_cast<std::size_t>(5));

  const ClassificationPair rebuilt = classify_pair(policy, canonical_request());
  AIFC_CHECK_MSG(rebuilt.first.digest == baseline.first.digest,
                 "a classifier rebuilt from scratch produced a different digest: key="
                     << canonical_flow_key().to_string()
                     << " baseline=" << baseline.first.digest.to_hex()
                     << " rebuilt=" << rebuilt.first.digest.to_hex());
  AIFC_CHECK_MSG(rebuilt.fingerprint == baseline.fingerprint,
                 "a classifier rebuilt from scratch produced a different decision:\nbaseline="
                     << baseline.fingerprint << "\nrebuilt=" << rebuilt.fingerprint);
  AIFC_CHECK_MSG(rebuilt.second.digest == baseline.first.digest,
                 "the rebuilt classifier's second (memoised) answer differs: "
                     << rebuilt.second.digest.to_hex());
}

// REAL runtime, SYNTHETIC evidence.  The memo is a cache, not an authority: an answer that
// comes from it and an answer that was recomputed must be the same answer, and neither may be
// reused across a freshness boundary.  A manual tick source makes both halves exact instead of
// timing-dependent: two classifications at one tick share a decision key, and a classification
// after the freshness window has elapsed must not reuse the decision taken before it.
AIFC_TEST("determinism.memoised_and_fresh_evaluations_agree") {
  const aifc::ClassifierPolicy policy = canonical_policy();
  aifc::ManualTickSource clock{1};
  aifc::ClassifierOptions options;
  options.policy = policy;
  options.clock = &clock;
  aifc::Classifier classifier(options);

  const aifc::FlowKey key = canonical_flow_key();
  std::vector<aifc::SessionEnvelope> envelopes;
  for (std::uint32_t index = 0; index < kPeerCount; ++index) {
    const aifc::Result<aifc::PublisherRegistration> registration = classifier.register_publisher(
        aifc_test::synthetic_publisher(index), aifc::PublisherBootId{1}, peer_ceiling(index),
        aifc_test::synthetic_session(index), "determinism peer");
    AIFC_CHECK_OK(registration);
    if (!registration) return;
    envelopes.push_back(aifc::make_session_envelope(registration.value(), clock.now()));
  }
  const aifc::Result<aifc::FlowRegistration> flow =
      classifier.register_flow(key, aifc::FlowGeneration{0}, aifc_test::synthetic_session(0));
  AIFC_CHECK_OK(flow);
  if (!flow) return;

  for (const RecordSpec& spec : canonical_specs()) {
    aifc::EvidencePayload payload;
    payload.flow_key = key;
    payload.flow_generation = flow.value().record.generation;
    payload.evidence_generation = spec.generation;
    payload.semantic = spec.semantic;
    payload.claimed_source = spec.claimed;
    payload.metadata.topic = spec.topic;
    payload.metadata.reason = "synthetic determinism evidence";
    const aifc::Result<aifc::EvidenceSubmissionOutcome> outcome =
        classifier.submit_evidence(envelopes[spec.peer], payload);
    AIFC_CHECK_OK(outcome);
    if (!outcome) return;
  }

  const aifc::Result<aifc::ClassificationResult> first =
      classifier.classify(make_query(key, flow.value().record.generation));
  AIFC_CHECK_OK(first);
  if (!first) return;
  const aifc::Result<aifc::ClassificationResult> second =
      classifier.classify(make_query(key, flow.value().record.generation));
  AIFC_CHECK_OK(second);
  if (!second) return;

  AIFC_CHECK_MSG(!first.value().memo_hit,
                 "the first classification of an evidence set must be a fresh evaluation");
  AIFC_CHECK_MSG(second.value().memo_hit,
                 "two classifications at the same tick must share the memo: tick="
                     << clock.now() << " key=" << key.to_string());
  AIFC_CHECK_MSG(second.value().classification.digest == first.value().classification.digest,
                 "the memoised answer differs from the freshly computed one: fresh="
                     << first.value().classification.digest.to_hex()
                     << " memo=" << second.value().classification.digest.to_hex());
  AIFC_CHECK_MSG(fingerprint(second.value().classification) ==
                     fingerprint(first.value().classification),
                 "the memoised decision differs from the freshly computed one:\nfresh="
                     << fingerprint(first.value().classification)
                     << "\nmemo=" << fingerprint(second.value().classification));

  // One tick later the same evidence is still inside its freshness window, so the answer must be
  // identical even though it is now recomputed rather than memoised.
  clock.set(clock.now() + 1U);
  const aifc::Result<aifc::ClassificationResult> recomputed =
      classifier.classify(make_query(key, flow.value().record.generation));
  AIFC_CHECK_OK(recomputed);
  if (!recomputed) return;
  AIFC_CHECK_MSG(!recomputed.value().memo_hit,
                 "a classification at a later tick must not reuse a decision taken at an earlier "
                 "one: tick="
                     << clock.now());
  AIFC_CHECK_MSG(recomputed.value().classification.digest == first.value().classification.digest,
                 "recomputing one tick later produced a different answer: first="
                     << first.value().classification.digest.to_hex()
                     << " recomputed=" << recomputed.value().classification.digest.to_hex()
                     << " tick=" << clock.now());

  // Past the freshness window the same evidence must not keep reporting the old answer.
  clock.set(policy.default_freshness_window + 10U);
  const aifc::Result<aifc::ClassificationResult> expired =
      classifier.classify(make_query(key, flow.value().record.generation));
  AIFC_CHECK_OK(expired);
  if (!expired) return;
  AIFC_CHECK_MSG(expired.value().classification.digest != first.value().classification.digest,
                 "a classification past the freshness window reused the decision taken while the "
                 "evidence was fresh: tick="
                     << clock.now() << " first=" << first.value().classification.digest.to_hex()
                     << " expired=" << expired.value().classification.digest.to_hex());
  AIFC_CHECK_MSG(expired.value().classification.state == aifc::ClassificationState::STALE,
                 "past the freshness window the decision should be STALE, not "
                     << aifc::to_string(expired.value().classification.state) << ": "
                     << fingerprint(expired.value().classification));
}

// REAL runtime, SYNTHETIC evidence.  (c) Permuting the peer registration order and the
// evidence submission order must not change the decision.  The records carry distinct
// source ranks, so the precedence winner is the same record in every order; the digest
// additionally excludes the acceptance sequence, which is the only field the order changes.
AIFC_TEST("determinism.permuted_submission_order_agrees") {
  const std::string case_name = "determinism.permuted_submission_order_agrees";
  const std::uint64_t seed = resolve_seed(case_name);
  aifc::Rng rng(seed);
  const aifc::ClassifierPolicy policy = canonical_policy();
  const ClassificationPair baseline = classify_pair(policy, canonical_request());

  constexpr std::uint32_t kAttempts = 12U;
  std::uint32_t reordered = 0;
  for (std::uint32_t attempt = 0; attempt < kAttempts; ++attempt) {
    RunRequest request = canonical_request();
    shuffle(request.peer_order, rng);
    shuffle(request.specs, rng);
    if (request.peer_order != canonical_peer_order()) ++reordered;

    const ClassificationPair permuted = classify_pair(policy, request);
    if (permuted.first.digest == baseline.first.digest &&
        permuted.fingerprint == baseline.fingerprint) {
      continue;
    }
    std::ostringstream out;
    out << replay_hint(case_name, seed) << " attempt=" << attempt << " request={"
        << describe_request(request) << "}\n  baseline digest=" << baseline.first.digest.to_hex()
        << "\n  permuted digest=" << permuted.first.digest.to_hex()
        << "\n  baseline decision=" << baseline.fingerprint
        << "\n  permuted decision=" << permuted.fingerprint;
    AIFC_FAIL(out.str());
    break;
  }
  AIFC_CHECK_MSG(reordered > 0U,
                 "no attempt actually permuted the evidence order, so the case proved nothing: "
                     << replay_hint(case_name, seed));
}

// REAL runtime, SYNTHETIC evidence.  (d) Every reachable single-field mutation of every
// record changes the digest.  The count of applied mutations is asserted, so removing a
// mutation from the table cannot silently weaken the case.
AIFC_TEST("determinism.content_mutation_changes_the_digest") {
  const aifc::ClassifierPolicy policy = canonical_policy();
  const ClassificationPair baseline = classify_pair(policy, canonical_request());
  const MutationKind kinds[5] = {MutationKind::Semantic, MutationKind::Source,
                                 MutationKind::EvidenceGeneration, MutationKind::Topic,
                                 MutationKind::Publisher};

  std::uint32_t applied = 0;
  std::uint32_t unreachable = 0;
  for (std::size_t index = 0; index < canonical_specs().size(); ++index) {
    for (const MutationKind kind : kinds) {
      RunRequest mutated = canonical_request();
      if (!apply_mutation(mutated, index, kind)) {
        ++unreachable;
        continue;
      }
      ++applied;
      const ClassificationPair after = classify_pair(policy, mutated);
      if (after.first.digest != baseline.first.digest) continue;
      std::ostringstream out;
      out << "mutation " << mutation_name(kind) << " of record #" << index
          << " did not change the decision digest: key=" << canonical_flow_key().to_string()
          << " generation=1\n  request={" << describe_request(mutated)
          << "}\n  baseline digest=" << baseline.first.digest.to_hex()
          << " mutated digest=" << after.first.digest.to_hex()
          << "\n  baseline decision=" << baseline.fingerprint
          << "\n  mutated decision=" << after.fingerprint;
      AIFC_FAIL(out.str());
      break;
    }
  }
  // 5 records x 5 kinds, minus the two unreachable source mutations: the fourth and the fifth
  // peer hold a TOPOLOGY_CORRELATED ceiling and nothing weaker is submittable through this API.
  AIFC_CHECK_EQ(applied, 23U);
  AIFC_CHECK_EQ(unreachable, 2U);
}

// REAL runtime, SYNTHETIC evidence.  (f) A claim above the session ceiling is clamped down
// to the ceiling, so a peer cannot promote itself; the resulting record is identical to the
// one it would have published at the ceiling, and so is the decision.
AIFC_TEST("determinism.claim_above_the_session_ceiling_is_clamped") {
  const aifc::ClassifierPolicy policy = canonical_policy();
  const ClassificationPair baseline = classify_pair(policy, canonical_request());

  RunRequest promoted = canonical_request();
  promoted.specs[4].claimed = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  const ClassificationPair clamped = classify_pair(policy, promoted);
  AIFC_CHECK_MSG(clamped.first.digest == baseline.first.digest,
                 "a claim above the session ceiling changed the decision, which means it was "
                 "not clamped: key="
                     << canonical_flow_key().to_string()
                     << " baseline=" << baseline.first.digest.to_hex()
                     << " promoted=" << clamped.first.digest.to_hex());
  for (const aifc::EvidenceCitation& citation : clamped.first.citations) {
    AIFC_CHECK_MSG(citation.source != aifc::EvidenceSource::DECLARED_AUTHENTICATED ||
                       citation.publisher.value() != aifc_test::synthetic_publisher(4).value(),
                   "the clamped publisher appears as DECLARED_AUTHENTICATED: "
                       << citation.id.value() << " publisher=" << citation.publisher.value()
                       << " source=" << aifc::to_string(citation.source));
  }

  // The clamp is also reported to the caller, so an operator can see that a claim was
  // reduced rather than silently believed.
  aifc_test::Harness harness(policy);
  const aifc_test::Harness::Peer peer =
      harness.add_peer(4U, aifc::EvidenceSource::CONTRACT_DERIVED);
  const aifc::FlowRecord flow = harness.register_flow(peer, kFlowIndex);
  aifc::EvidencePayload payload;
  payload.flow_key = flow.key;
  payload.flow_generation = flow.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};
  payload.semantic = aifc::SemanticClass::SHUFFLE;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "topic-epsilon";
  const aifc::Result<aifc::EvidenceSubmissionOutcome> outcome =
      harness.classifier().submit_evidence(peer.envelope, payload);
  AIFC_CHECK_OK(outcome);
  if (outcome) {
    AIFC_CHECK_MSG(outcome.value().effective_source == aifc::EvidenceSource::CONTRACT_DERIVED,
                   "the effective source should have been clamped to CONTRACT_DERIVED but was "
                       << aifc::to_string(outcome.value().effective_source));
    AIFC_CHECK_MSG(outcome.value().record.source == aifc::EvidenceSource::CONTRACT_DERIVED,
                   "the recorded source should be CONTRACT_DERIVED but was "
                       << aifc::to_string(outcome.value().record.source));
    AIFC_CHECK_MSG(!outcome.value().notes.empty(),
                   "the clamp was not reported in the submission notes");
  }
}

// REAL runtime, SYNTHETIC evidence.  (e) The canonical state is written to a snapshot file
// in a scratch directory, read back, and every evidence record is additionally pushed
// through the record codec.  The decision re-derived from the decoded records must be the
// same decision, byte for byte, including the selected record and the digest.
AIFC_TEST("determinism.snapshot_and_codec_round_trip_preserve_the_decision") {
  const aifc::ClassifierPolicy policy = canonical_policy();
  aifc_test::ScratchDirectory scratch("determinism-snapshot");
  const std::string path = scratch.file("state.aifs");

  build_and_classify(
      policy, canonical_request(),
      [&path, &policy](aifc_test::Harness& harness, const aifc::FlowRecord& flow,
              const std::vector<aifc::EvidenceRecord>& published,
              const ClassificationPair& pair) {
        const aifc::Classifier& classifier = harness.classifier();

        // --- the snapshot is assembled from the classifier's durable image --------------
        //
        // One call, taken under the classifier's own lock.  Reaching through individual store
        // accessors would copy five containers without the mutex that guards them, which is a data
        // race that shows up as heap corruption rather than as a wrong answer.
        // One locked copy of everything durable: the classifier deliberately does not expose its
        // stores, because walking five containers from outside the lock would be a data race.
        const aifc::Classifier::DurableState durable = classifier.durable_state();
        aifc::StateSnapshot image;
        image.epoch = durable.epoch;
        image.boot = durable.coordinator_boot;
        image.sequence_high_water = durable.sequence_high_water;
        image.policy = durable.policy;
        image.publishers = durable.publishers;
        image.workloads = durable.workloads;
        image.contracts = durable.contracts;
        image.flows = durable.flows;
        image.evidence = durable.evidence;
        image.classifications = durable.classifications;
        image.revocations = durable.revocations;
        image.supersessions = durable.supersessions;

        AIFC_CHECK_EQ(image.evidence.size(), published.size());
        AIFC_CHECK_EQ(image.flows.size(), static_cast<std::size_t>(1));

        const aifc::SnapshotLimits limits;
        AIFC_CHECK_OK(aifc::write_snapshot_file(path, image, limits));
        const aifc::Result<aifc::StateSnapshot> read = aifc::read_snapshot_file(path, limits);
        AIFC_CHECK_OK(read);
        if (!read) return;
        const aifc::StateSnapshot& decoded = read.value();

        AIFC_CHECK_EQ(decoded.evidence.size(), image.evidence.size());
        AIFC_CHECK_EQ(decoded.flows.size(), image.flows.size());
        AIFC_CHECK_EQ(decoded.publishers.size(), image.publishers.size());
        AIFC_CHECK_EQ(decoded.classifications.size(), image.classifications.size());
        AIFC_CHECK_MSG(decoded.epoch.value == classifier.epoch().value,
                       "the snapshot epoch " << decoded.epoch.to_string()
                                             << " differs from the classifier epoch "
                                             << classifier.epoch().to_string());
        AIFC_CHECK_EQ(decoded.policy.generation.value, image.policy.generation.value);
        AIFC_CHECK_EQ(aifc::compute_policy_digest(decoded.policy),
                      aifc::compute_policy_digest(image.policy));

        // --- every evidence record is pushed through the record codec ------------------
        const aifc::CodecLimits codec = aifc::CodecLimits::from(policy.limits);
        std::vector<aifc::EvidenceRecord> round_tripped;
        round_tripped.reserve(decoded.evidence.size());
        for (std::size_t index = 0; index < decoded.evidence.size(); ++index) {
          const aifc::EvidenceRecord& record = decoded.evidence[index];
          aifc::BufferWriter writer(aifc::kMaxBlobBytes);
          AIFC_CHECK_OK(aifc::encode_evidence_record(writer, record));
          aifc::BufferReader reader(writer.bytes(), aifc::kMaxStringBytes);
          const aifc::Result<aifc::EvidenceRecord> restored =
              aifc::decode_evidence_record(reader, codec);
          AIFC_CHECK_OK(restored);
          if (!restored) continue;
          AIFC_CHECK_OK(reader.finish());
          const aifc::EvidenceRecord& back = restored.value();
          AIFC_CHECK_MSG(back.id == record.id && back.publisher == record.publisher &&
                             back.generation == record.generation &&
                             back.semantic == record.semantic && back.source == record.source &&
                             back.state == record.state &&
                             back.accepted_seq == record.accepted_seq &&
                             back.flow_id == record.flow_id &&
                             back.flow_generation == record.flow_generation &&
                             back.content_digest == record.content_digest,
                         "record #" << index << " (" << record.id.value()
                                    << ") did not survive the codec round trip: decoded {id="
                                    << back.id.value() << " publisher=" << back.publisher.value()
                                    << " source=" << aifc::to_string(back.source)
                                    << " state=" << aifc::to_string(back.state)
                                    << " semantic=" << aifc::to_string(back.semantic)
                                    << " generation=" << back.generation.to_string()
                                    << " accepted_seq=" << back.accepted_seq
                                    << " digest=" << back.content_digest.to_hex()
                                    << "} original {id=" << record.id.value()
                                    << " publisher=" << record.publisher.value()
                                    << " source=" << aifc::to_string(record.source)
                                    << " state=" << aifc::to_string(record.state)
                                    << " semantic=" << aifc::to_string(record.semantic)
                                    << " generation=" << record.generation.to_string()
                                    << " accepted_seq=" << record.accepted_seq
                                    << " digest=" << record.content_digest.to_hex() << "}");
          round_tripped.push_back(back);
        }
        AIFC_CHECK_EQ(round_tripped.size(), decoded.evidence.size());
        if (round_tripped.size() != decoded.evidence.size()) return;
        for (std::size_t index = 0; index < round_tripped.size(); ++index) {
          AIFC_CHECK_EQ(round_tripped[index].content_digest, decoded.evidence[index].content_digest);
        }

        // --- the decision is re-derived from the decoded records ----------------------
        aifc::DecisionInput input;
        input.flow = flow;
        input.policy = decoded.policy;
        input.authority = authority_of(classifier);
        input.active_contracts = decoded.contracts;
        input.workloads = decoded.workloads;
        input.generation_revoked = false;
        for (const aifc::EvidenceRecord& record : round_tripped) {
          if (record.flow_id == flow.id) input.evidence.push_back(record);
        }
        AIFC_CHECK_EQ(input.evidence.size(), published.size());

        const aifc::DecisionEngine engine;
        const aifc::Classification rederived = engine.decide(input);
        AIFC_CHECK_MSG(rederived.digest == pair.first.digest,
                       "the decoded evidence produced a different decision digest for key="
                           << flow.key.to_string() << ": live=" << pair.first.digest.to_hex()
                           << " decoded=" << rederived.digest.to_hex());
        AIFC_CHECK_MSG(rederived.selected_evidence == pair.first.selected_evidence,
                       "the decoded evidence selected a different record: live="
                           << pair.first.selected_evidence.value()
                           << " decoded=" << rederived.selected_evidence.value());
        AIFC_CHECK_MSG(fingerprint(rederived) == pair.fingerprint,
                       "the decoded evidence produced a different decision:\nlive="
                           << pair.fingerprint << "\ndecoded=" << fingerprint(rederived));

        // --- the classification itself survives the codec -----------------------------
        aifc::BufferWriter classification_writer(aifc::kMaxBlobBytes);
        AIFC_CHECK_OK(aifc::encode_classification(classification_writer, pair.first));
        aifc::BufferReader classification_reader(classification_writer.bytes(),
                                                 aifc::kMaxStringBytes);
        const aifc::Result<aifc::Classification> restored_classification =
            aifc::decode_classification(classification_reader, codec);
        AIFC_CHECK_OK(restored_classification);
        if (!restored_classification) return;
        AIFC_CHECK_OK(classification_reader.finish());
        AIFC_CHECK_EQ(restored_classification.value().digest, pair.first.digest);
        AIFC_CHECK_EQ(aifc::compute_classification_digest(restored_classification.value()),
                      pair.first.digest);
        AIFC_CHECK_EQ(restored_classification.value().citations.size(),
                      pair.first.citations.size());
        AIFC_CHECK_EQ(restored_classification.value().contradictions.size(),
                      pair.first.contradictions.size());
        AIFC_CHECK_EQ(fingerprint(restored_classification.value()), pair.fingerprint);
      });
}

}  // namespace
