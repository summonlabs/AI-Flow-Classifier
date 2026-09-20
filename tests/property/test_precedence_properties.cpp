// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Property tests for evidence precedence.
//
// REAL / SYNTHETIC
// ----------------
// Every evidence record fed to aifc::DecisionEngine::decide here is SYNTHETIC: its
// identities, publishers, classes, generations, epochs, sequences and ticks are
// fabricated by the seeded generator in this file.  What is REAL is the code under test:
// the assertions are made against the shipped decision engine through its public header
// (aifc::evidence_outranks and the aifc::Classification that decide() returns) and
// against the shipped source-rank table.
//
// The generator never invents an evidence identity twice within one set, because the
// total order the header documents is only total over records with distinct identities.
//
// Reproduction
// ------------
// Each case derives its seed from its own name.  Every failure message carries the seed
// it used and the exact replay instruction:
//
//     set AIFC_TEST_SEED=0x0123456789abcdef
//     build\tests-b\bin\test_precedence_properties.exe
//
// AIFC_TEST_SEED overrides the seed of every randomized case in this file verbatim, so a
// printed seed reproduces the failing run exactly.  An argument cannot be used for this:
// tests/support/main.cpp rejects unknown arguments with exit code 64 by design.

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

class SeededCase {
 public:
  explicit SeededCase(std::string name)
      : name_(std::move(name)), seed_(resolve_seed(name_)), rng_(seed_) {}

  [[nodiscard]] aifc::Rng& rng() noexcept { return rng_; }
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }

  [[nodiscard]] std::string where(std::uint32_t step, const std::string& detail) const {
    std::ostringstream out;
    out << "case=" << name_ << " " << aifc::format_seed(seed_) << " step=" << step;
    if (!detail.empty()) out << " -- " << detail;
    out << " [replay: set AIFC_TEST_SEED=" << seed_ << "]";
    return out.str();
  }

  void check(bool condition, std::uint32_t step, const std::string& detail) {
    if (!condition) AIFC_FAIL(where(step, detail));
  }

 private:
  [[nodiscard]] static std::uint64_t resolve_seed(const std::string& name) {
    const char* override_text = std::getenv("AIFC_TEST_SEED");
    if (override_text != nullptr && *override_text != '\0') return parse_seed_text(override_text);
    return aifc::seed_from_text(name);
  }

  std::string name_;
  std::uint64_t seed_ = 0;
  aifc::Rng rng_;
};

[[nodiscard]] std::size_t failure_count() {
  return aifc_test::Registry::instance().failures().size();
}

// ---------------------------------------------------------------------------
// Value rendering
// ---------------------------------------------------------------------------

[[nodiscard]] std::string describe(const aifc::EvidenceRecord& record) {
  std::ostringstream out;
  out << "id=" << record.id.value() << " source=" << aifc::to_string(record.source) << "(rank "
      << static_cast<unsigned>(aifc::source_rank(record.source))
      << ") class=" << aifc::to_string(record.semantic)
      << " workload_generation=" << record.workload_generation.value
      << " evidence_generation=" << record.generation.value
      << " accepted_seq=" << record.accepted_seq << " state=" << aifc::to_string(record.state)
      << " publisher=" << record.publisher.value() << "@" << record.publisher_boot.to_string()
      << " accepted_epoch=" << record.accepted_epoch.to_string()
      << " flow_generation=" << record.flow_generation.to_string()
      << " fresh_until=" << record.fresh_until;
  return out.str();
}

[[nodiscard]] std::string describe(const aifc::Classification& classification) {
  std::ostringstream out;
  out << "semantic=" << aifc::to_string(classification.semantic)
      << " state=" << aifc::to_string(classification.state)
      << " confidence=" << classification.confidence.to_decimal() << " selected="
      << (classification.selected_evidence.empty() ? std::string("<none>")
                                                   : classification.selected_evidence.value())
      << " selected_source=" << aifc::to_string(classification.selected_source)
      << " citations=" << classification.citations.size()
      << " contradictions=" << classification.contradictions.size()
      << " penalty=" << classification.applied_penalty_basis_points
      << " digest=" << classification.digest.to_hex();
  return out.str();
}

// ---------------------------------------------------------------------------
// Seeded value generation
// ---------------------------------------------------------------------------

constexpr std::size_t kClassCount = 8;
const aifc::SemanticClass kClasses[kClassCount] = {
    aifc::SemanticClass::COLLECTIVE,
    aifc::SemanticClass::TRAINING_SYNC,
    aifc::SemanticClass::INFERENCE_REQUEST,
    aifc::SemanticClass::PREFILL_DECODE_HANDOFF,
    aifc::SemanticClass::KV_STATE_TRANSFER,
    aifc::SemanticClass::SHUFFLE,
    aifc::SemanticClass::CHECKPOINT,
    aifc::SemanticClass::CONTROL_PLANE,
};

// Ascending rank, so index order is strength order.
constexpr std::size_t kSourceCount = aifc::kEvidenceSourceCount - 1U;
const aifc::EvidenceSource kSources[kSourceCount] = {
    aifc::EvidenceSource::HEURISTIC,
    aifc::EvidenceSource::TOPOLOGY_CORRELATED,
    aifc::EvidenceSource::COORDINATOR_CORRELATED,
    aifc::EvidenceSource::CONTRACT_DERIVED,
    aifc::EvidenceSource::DECLARED_AUTHENTICATED,
};

const aifc::EvidenceState kStates[6] = {
    aifc::EvidenceState::EVIDENCE_CURRENT,
    aifc::EvidenceState::EVIDENCE_CURRENT,
    aifc::EvidenceState::EVIDENCE_CURRENT,
    aifc::EvidenceState::EVIDENCE_STALE,
    aifc::EvidenceState::EVIDENCE_SUPERSEDED,
    aifc::EvidenceState::EVIDENCE_REVOKED,
};

[[nodiscard]] std::uint64_t pick_u64(aifc::Rng& rng, const std::uint64_t* values,
                                     std::size_t count) {
  return values[static_cast<std::size_t>(rng.next_below(count))];
}

[[nodiscard]] aifc::SemanticClass random_class(aifc::Rng& rng, bool allow_unknown) {
  if (allow_unknown && rng.next_below(8U) == 0U) return aifc::SemanticClass::UNKNOWN;
  return kClasses[static_cast<std::size_t>(rng.next_below(kClassCount))];
}

[[nodiscard]] aifc::EvidenceSource random_source(aifc::Rng& rng) {
  return kSources[static_cast<std::size_t>(rng.next_below(kSourceCount))];
}

[[nodiscard]] aifc::EvidenceState random_state(aifc::Rng& rng) {
  return kStates[static_cast<std::size_t>(rng.next_below(6U))];
}

[[nodiscard]] aifc::AuthorityContext make_authority(aifc::Rng& rng) {
  const std::uint64_t ticks[4] = {aifc::kTickNone, 100U, 200U, 300U};
  aifc::AuthorityContext authority;
  authority.epoch = aifc::CoordinatorEpoch{1};
  authority.coordinator_boot = aifc::CoordinatorBootId{1};
  authority.tick = pick_u64(rng, ticks, 4U);
  for (std::uint32_t index = 0; index < 5U; ++index) {
    const aifc::PublisherId publisher = aifc_test::synthetic_publisher(index);
    authority.known_publishers.insert(publisher.value());
    if (rng.next_bool()) {
      authority.live_publisher_boots.insert(
          aifc::AuthorityContext::boot_key(publisher, aifc::PublisherBootId{1}));
    }
  }
  return authority;
}

[[nodiscard]] aifc::AuthorityContext make_authority_with_live(std::uint32_t live_count) {
  aifc::AuthorityContext authority;
  authority.epoch = aifc::CoordinatorEpoch{1};
  authority.coordinator_boot = aifc::CoordinatorBootId{1};
  authority.tick = aifc::kTickNone;
  for (std::uint32_t index = 0; index < 5U; ++index) {
    const aifc::PublisherId publisher = aifc_test::synthetic_publisher(index);
    authority.known_publishers.insert(publisher.value());
    if (index < live_count) {
      authority.live_publisher_boots.insert(
          aifc::AuthorityContext::boot_key(publisher, aifc::PublisherBootId{1}));
    }
  }
  return authority;
}

[[nodiscard]] aifc::FlowRecord make_flow(aifc::Rng& rng, std::uint32_t step) {
  aifc::FlowRecord flow;
  flow.key = aifc_test::synthetic_flow_key(step);
  flow.id = aifc::derive_flow_id(flow.key);
  flow.generation = aifc::FlowGeneration{1U + rng.next_below(2U)};
  flow.registered_by = aifc_test::synthetic_session(0);
  return flow;
}

[[nodiscard]] aifc::EvidenceRecord make_record(aifc::Rng& rng, std::uint32_t index,
                                               const aifc::FlowRecord& flow,
                                               const aifc::AuthorityContext& authority) {
  const std::uint64_t accepted_ticks[3] = {10U, 20U, 30U};
  const std::uint64_t fresh_until[3] = {40U, 120U, 500U};

  aifc::EvidenceRecord record;
  record.id = aifc::make_evidence_id("ev-" + std::to_string(1000U + index));
  record.publisher = aifc_test::synthetic_publisher(index % 5U);
  record.publisher_boot = aifc::PublisherBootId{1};
  record.session = aifc_test::synthetic_session(index);
  record.accepted_epoch = rng.next_below(6U) == 0U
                              ? aifc::CoordinatorEpoch{authority.epoch.value + 1U}
                              : authority.epoch;
  record.accepted_boot = authority.coordinator_boot;
  record.workload = aifc_test::synthetic_workload(index % 3U);
  record.workload_generation = aifc::WorkloadGeneration{1U + rng.next_below(3U)};
  record.flow_id = flow.id;
  record.flow_generation = rng.next_below(10U) == 0U
                               ? aifc::FlowGeneration{flow.generation.value + 1U}
                               : flow.generation;
  record.generation = aifc::EvidenceGeneration{1U + rng.next_below(4U)};
  record.accepted_seq = 1U + rng.next_below(8U);
  record.accepted_tick = pick_u64(rng, accepted_ticks, 3U);
  record.fresh_until = pick_u64(rng, fresh_until, 3U);
  record.semantic = random_class(rng, true);
  record.source = random_source(rng);
  record.state = random_state(rng);
  record.confidence = aifc::source_confidence(record.source);
  record.metadata.topic = "topic-" + std::to_string(index);
  record.metadata.reason = "synthetic property evidence";
  record.content_digest = aifc::compute_evidence_digest(record);
  return record;
}

// ---------------------------------------------------------------------------
// Eligibility, as the engine reports it
// ---------------------------------------------------------------------------

// A citation is eligible exactly when the decision engine treated the record as a
// possible winner: CURRENT after its own currentness pass, not heuristic, and declaring a
// class (UNKNOWN is never a declaration and can never win).
[[nodiscard]] bool citation_is_eligible(const aifc::EvidenceCitation& citation) {
  return citation.state == aifc::EvidenceState::EVIDENCE_CURRENT &&
         !aifc::source_is_heuristic(citation.source) && !aifc::is_unknown(citation.semantic);
}

[[nodiscard]] std::map<std::string, const aifc::EvidenceRecord*> index_by_id(
    const std::vector<aifc::EvidenceRecord>& records) {
  std::map<std::string, const aifc::EvidenceRecord*> by_id;
  for (const aifc::EvidenceRecord& record : records) by_id[record.id.value()] = &record;
  return by_id;
}

// The maximum under aifc::evidence_outranks among the citations that could win.  Returns
// nullptr when nothing could win.
[[nodiscard]] const aifc::EvidenceRecord* eligible_maximum(
    const aifc::Classification& classification,
    const std::map<std::string, const aifc::EvidenceRecord*>& by_id) {
  const aifc::EvidenceRecord* best = nullptr;
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    if (!citation_is_eligible(citation)) continue;
    const auto found = by_id.find(citation.id.value());
    if (found == by_id.end()) continue;
    const aifc::EvidenceRecord* candidate = found->second;
    if (best == nullptr || aifc::evidence_outranks(*candidate, *best)) best = candidate;
  }
  return best;
}

[[nodiscard]] std::size_t eligible_count(const aifc::Classification& classification) {
  std::size_t count = 0;
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    if (citation_is_eligible(citation)) ++count;
  }
  return count;
}

// ---------------------------------------------------------------------------
// The generated step
// ---------------------------------------------------------------------------

struct GeneratedSet {
  aifc::FlowRecord flow;
  std::vector<aifc::EvidenceRecord> records;
  aifc::DecisionInput input;
  // The record that was rebuilt as a strictly weaker copy of another record, and the
  // record it copied.  Used by the "a stronger source can never lose" property.
  std::size_t weaker_copy = 0;
  std::size_t stronger_original = 0;
};

[[nodiscard]] GeneratedSet generate_set(SeededCase& seeded, std::uint32_t step,
                                        aifc::ClassifierPolicy& policy) {
  aifc::Rng& rng = seeded.rng();
  GeneratedSet set;
  set.flow = make_flow(rng, step);

  aifc::AuthorityContext authority = make_authority(rng);

  const std::uint64_t penalties[4] = {0U, 500U, 2000U, 4000U};
  const std::uint64_t thresholds[2] = {1U, 1000U};
  policy = aifc::ClassifierPolicy::initial();
  policy.allow_heuristic_evidence = rng.next_bool();
  policy.contradiction_penalty = static_cast<std::uint32_t>(pick_u64(rng, penalties, 4U));
  policy.minimum_publishable_confidence = static_cast<std::uint32_t>(pick_u64(rng, thresholds, 2U));

  const std::uint32_t count = 4U + static_cast<std::uint32_t>(rng.next_below(7U));
  set.records.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    set.records.push_back(make_record(rng, index, set.flow, authority));
  }

  // Rebuild one record as a copy of another with a strictly weaker source.  Everything
  // else (class, generations, sequence, ticks, flow binding) is identical, so the only
  // difference that can decide the pair is the source rank.
  const std::size_t stronger = static_cast<std::size_t>(rng.next_below(count));
  std::size_t weaker = static_cast<std::size_t>(rng.next_below(count));
  if (weaker == stronger) weaker = (weaker + 1U) % static_cast<std::size_t>(count);
  const std::size_t stronger_rank_index =
      static_cast<std::size_t>(rng.next_below(kSourceCount - 1U)) + 1U;
  const std::size_t weaker_rank_index = static_cast<std::size_t>(rng.next_below(stronger_rank_index));
  // The stronger source is installed on the original first, so that the pair really is
  // identical apart from the source rank and the identity.
  set.records[stronger].source = kSources[stronger_rank_index];
  set.records[stronger].confidence = aifc::source_confidence(set.records[stronger].source);
  set.records[stronger].content_digest = aifc::compute_evidence_digest(set.records[stronger]);
  aifc::EvidenceRecord copy = set.records[stronger];
  copy.id = set.records[weaker].id;
  copy.source = kSources[weaker_rank_index];
  copy.confidence = aifc::source_confidence(copy.source);
  copy.content_digest = aifc::compute_evidence_digest(copy);
  set.records[weaker] = copy;
  set.weaker_copy = weaker;
  set.stronger_original = stronger;

  set.input.flow = set.flow;
  set.input.evidence = set.records;
  set.input.policy = policy;
  set.input.authority = authority;
  set.input.generation_revoked = false;
  return set;
}

// ---------------------------------------------------------------------------
// Property: the total order is irreflexive, antisymmetric, transitive and total
// ---------------------------------------------------------------------------

void check_order_properties(SeededCase& seeded, std::uint32_t step,
                            const std::vector<aifc::EvidenceRecord>& records) {
  const std::size_t count = records.size();

  for (std::size_t i = 0; i < count; ++i) {
    if (aifc::evidence_outranks(records[i], records[i])) {
      seeded.check(false, step, "irreflexivity: record outranks itself: " + describe(records[i]));
      return;
    }
  }

  for (std::size_t i = 0; i < count; ++i) {
    for (std::size_t j = i + 1; j < count; ++j) {
      const bool forward = aifc::evidence_outranks(records[i], records[j]);
      const bool backward = aifc::evidence_outranks(records[j], records[i]);
      if (forward && backward) {
        seeded.check(false, step, "antisymmetry broken between i=" + std::to_string(i) + " {" +
                                      describe(records[i]) + "} and j=" + std::to_string(j) + " {" +
                                      describe(records[j]) + "}: each outranks the other");
        return;
      }
      if (forward == backward) {
        seeded.check(false, step,
                     "totality broken between i=" + std::to_string(i) + " {" + describe(records[i]) +
                         "} and j=" + std::to_string(j) + " {" + describe(records[j]) +
                         "}: neither outranks the other, so the order is not total");
        return;
      }
    }
  }

  for (std::size_t i = 0; i < count; ++i) {
    for (std::size_t j = 0; j < count; ++j) {
      if (i == j || !aifc::evidence_outranks(records[i], records[j])) continue;
      for (std::size_t k = 0; k < count; ++k) {
        if (j == k || i == k) continue;
        if (!aifc::evidence_outranks(records[j], records[k])) continue;
        if (aifc::evidence_outranks(records[i], records[k])) continue;
        seeded.check(false, step,
                     "transitivity broken: i=" + std::to_string(i) + " {" + describe(records[i]) +
                         "} outranks j=" + std::to_string(j) + " {" + describe(records[j]) +
                         "} which outranks k=" + std::to_string(k) + " {" + describe(records[k]) +
                         "}, but i does not outrank k");
        return;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Property: source rank is the first and strongest discriminator
// ---------------------------------------------------------------------------

void check_source_dominance(SeededCase& seeded, std::uint32_t step, const GeneratedSet& set) {
  const aifc::EvidenceRecord& stronger = set.records[set.stronger_original];
  const aifc::EvidenceRecord& weaker = set.records[set.weaker_copy];
  if (!aifc::evidence_outranks(stronger, weaker)) {
    seeded.check(false, step,
                 "a stronger source on an otherwise identical record did not outrank it: stronger {"
                 + describe(stronger) + "} vs weaker {" + describe(weaker) + "}");
    return;
  }
  if (aifc::evidence_outranks(weaker, stronger)) {
    seeded.check(false, step,
                 "a weaker source on an otherwise identical record also outranked the stronger: "
                 "stronger {" + describe(stronger) + "} vs weaker {" + describe(weaker) + "}");
  }
}

// ---------------------------------------------------------------------------
// Property: the selected record is the maximum under the order among eligible records
// ---------------------------------------------------------------------------

void check_selected_is_maximum(SeededCase& seeded, std::uint32_t step, const GeneratedSet& set,
                               const aifc::Classification& classification) {
  const std::map<std::string, const aifc::EvidenceRecord*> by_id = index_by_id(set.records);
  const aifc::EvidenceRecord* expected = eligible_maximum(classification, by_id);
  const std::size_t eligible = eligible_count(classification);

  if (classification.citations.size() != set.records.size()) {
    seeded.check(false, step,
                 "citation count " + std::to_string(classification.citations.size()) +
                     " does not cover every considered record (" +
                     std::to_string(set.records.size()) + "): " + describe(classification));
    return;
  }

  if (expected == nullptr) {
    if (!classification.selected_evidence.empty() || !aifc::is_unknown(classification.semantic)) {
      seeded.check(false, step,
                   "no eligible record exists (eligible=" + std::to_string(eligible) +
                       ") yet the engine selected one: " + describe(classification));
    }
    return;
  }

  if (classification.selected_evidence != expected->id) {
    seeded.check(false, step,
                 "the selected record is not the maximum of the " + std::to_string(eligible) +
                     " eligible records: expected {" + describe(*expected) + "} but the engine "
                     "reported " + describe(classification));
    return;
  }
  if (classification.semantic != expected->semantic) {
    seeded.check(false, step,
                 "the reported class is not the class of the maximum eligible record: expected " +
                     std::string(aifc::to_string(expected->semantic)) + " from {" +
                     describe(*expected) + "} but the engine reported " + describe(classification));
    return;
  }
  if (classification.selected_source != expected->source) {
    seeded.check(false, step,
                 "the reported source is not the source of the maximum eligible record: expected " +
                     std::string(aifc::to_string(expected->source)) + " but the engine reported " +
                     describe(classification));
    return;
  }

  // Every eligible record must be accounted for as agreeing or disagreeing with the
  // winner, never dropped.
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    if (!citation_is_eligible(citation)) continue;
    const bool agreeing = citation.semantic == classification.semantic;
    const bool selected = citation.disposition == aifc::EvidenceDisposition::SELECTED;
    const bool corroborating = citation.disposition == aifc::EvidenceDisposition::CORROBORATING;
    const bool contradicting = citation.disposition == aifc::EvidenceDisposition::CONTRADICTING;
    if (selected || corroborating || contradicting) {
      if (agreeing && contradicting) {
        seeded.check(false, step, "citation " + citation.id.value() +
                                      " agrees with the winner but is reported CONTRADICTING: " +
                                      describe(classification));
        return;
      }
      if (!agreeing && (corroborating || selected)) {
        seeded.check(false, step,
                     "citation " + citation.id.value() + " disagrees with the winner but is "
                     "reported " + std::string(aifc::to_string(citation.disposition)) + ": " +
                         describe(classification));
        return;
      }
      continue;
    }
    seeded.check(false, step, "eligible citation " + citation.id.value() +
                                  " was neither selected, corroborating nor contradicting: " +
                                  describe(classification));
    return;
  }
}

// ---------------------------------------------------------------------------
// Property: raising a source can never lower the winner and never unseats it
// ---------------------------------------------------------------------------

// True when the authority context holds a live session for the record's publisher
// incarnation, which is the condition under which raising the record's source cannot move it
// across the currentness boundary.  Currentness is rule 1 and source rank is rule 2, and the
// two source classes differ in what currentness requires: see
// aifc::source_requires_live_session().  Raising a CONTRACT_DERIVED record whose publisher is
// not live to an observational source adds the liveness requirement, so it goes stale -- the
// case "precedence.source_raise_and_currentness_are_separate_axes" documents that rule
// directly rather than pretending it does not exist.
[[nodiscard]] bool publisher_is_live(const aifc::AuthorityContext& authority,
                                     const aifc::EvidenceRecord& record) {
  return authority.live_publisher_boots.find(
             aifc::AuthorityContext::boot_key(record.publisher, record.publisher_boot)) !=
         authority.live_publisher_boots.end();
}

// Returns true when the property was actually exercised in this step.
[[nodiscard]] bool check_raise_never_loses(SeededCase& seeded, std::uint32_t step,
                                           const GeneratedSet& set,
                                           const aifc::Classification& baseline) {
  if (set.records.empty()) return false;
  std::vector<std::size_t> raisable;
  for (std::size_t index = 0; index < set.records.size(); ++index) {
    if (publisher_is_live(set.input.authority, set.records[index])) raisable.push_back(index);
  }
  if (raisable.empty()) return false;
  const std::size_t raised_index =
      raisable[static_cast<std::size_t>(seeded.rng().next_below(raisable.size()))];
  const aifc::EvidenceRecord before = set.records[raised_index];

  const std::map<std::string, const aifc::EvidenceRecord*> baseline_by_id = index_by_id(set.records);
  const aifc::EvidenceRecord* baseline_max = eligible_maximum(baseline, baseline_by_id);
  const unsigned baseline_rank =
      baseline_max == nullptr ? 0U : aifc::source_rank(baseline_max->source);

  aifc::DecisionInput raised = set.input;
  aifc::EvidenceRecord& target = raised.evidence[raised_index];
  target.source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  target.confidence = aifc::source_confidence(target.source);
  target.content_digest = aifc::compute_evidence_digest(target);

  aifc::DecisionEngine engine;
  const aifc::Classification after = engine.decide(raised);

  std::vector<aifc::EvidenceRecord> raised_records = set.records;
  raised_records[raised_index] = target;
  const std::map<std::string, const aifc::EvidenceRecord*> raised_by_id = index_by_id(raised_records);
  const aifc::EvidenceRecord* raised_max = eligible_maximum(after, raised_by_id);
  const unsigned raised_rank = raised_max == nullptr ? 0U : aifc::source_rank(raised_max->source);

  if (raised_rank < baseline_rank) {
    seeded.check(false, step,
                 "raising {" + describe(before) + "} to DECLARED_AUTHENTICATED lowered the winning "
                 "source rank from " + std::to_string(baseline_rank) + " to " +
                     std::to_string(raised_rank) + ": before " + describe(baseline) + " after " +
                     describe(after));
    return true;
  }
  if (baseline.selected_evidence == before.id && after.selected_evidence != before.id) {
    seeded.check(false, step,
                 "the selected record " + before.id.value() + " lost after its own source was "
                 "raised to DECLARED_AUTHENTICATED: before " + describe(baseline) + " after " +
                     describe(after));
  }
  return true;
}

// ---------------------------------------------------------------------------
// Randomized step
// ---------------------------------------------------------------------------

// Returns true when the source-raise property was exercised in this step.
[[nodiscard]] bool precedence_step(SeededCase& seeded, std::uint32_t step) {
  const std::size_t before = failure_count();

  aifc::ClassifierPolicy policy;
  const GeneratedSet set = generate_set(seeded, step, policy);

  check_order_properties(seeded, step, set.records);
  if (failure_count() != before) return false;
  check_source_dominance(seeded, step, set);
  if (failure_count() != before) return false;

  aifc::DecisionEngine engine;
  const aifc::Classification classification = engine.decide(set.input);
  check_selected_is_maximum(seeded, step, set, classification);
  if (failure_count() != before) return false;
  return check_raise_never_loses(seeded, step, set, classification);
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

// SYNTHETIC inputs, REAL engine.  Every randomized step asserts the full order algebra,
// the maximum-selection rule, the source-dominance rule and the "raising a source never
// lowers the winner" rule over one generated evidence set.
AIFC_TEST("precedence.randomized.order_and_selection") {
  SeededCase seeded("precedence.randomized.order_and_selection");
  constexpr std::uint32_t kSteps = 400;
  std::uint32_t raise_checks = 0;
  for (std::uint32_t step = 0; step < kSteps; ++step) {
    const std::size_t before = failure_count();
    if (precedence_step(seeded, step)) ++raise_checks;
    if (failure_count() != before) break;
  }
  AIFC_CHECK_MSG(raise_checks > 0U,
                 "the source-raise property was never exercised, so the case proved nothing: "
                     << seeded.where(0U, "raise_checks=0"));
}

// SYNTHETIC inputs, REAL engine.  A current heuristic record may never beat a current
// authenticated declaration, whatever its workload generation, acceptance sequence or
// identity ordering says, and whichever order the records are supplied in.
AIFC_TEST("precedence.authenticated_declaration_beats_current_heuristic") {
  SeededCase seeded("precedence.authenticated_declaration_beats_current_heuristic");
  constexpr std::uint32_t kSteps = 200;
  for (std::uint32_t step = 0; step < kSteps; ++step) {
    const std::size_t before = failure_count();

    aifc::Rng& rng = seeded.rng();
    aifc::FlowRecord flow;
    flow.key = aifc_test::synthetic_flow_key(step);
    flow.id = aifc::derive_flow_id(flow.key);
    flow.generation = aifc::FlowGeneration{1};

    const aifc::AuthorityContext authority = make_authority_with_live(1U);
    const aifc::PublisherId publisher = aifc_test::synthetic_publisher(0);

    aifc::EvidenceRecord authenticated = make_record(rng, 0, flow, authority);
    // Deliberately the weakest possible rank key: lowest workload generation, lowest
    // evidence generation, lowest acceptance sequence, and an identity that sorts after
    // the heuristic record's identity.
    authenticated.id = aifc::make_evidence_id("ev-2000");
    authenticated.publisher = publisher;
    authenticated.publisher_boot = aifc::PublisherBootId{1};
    authenticated.accepted_epoch = authority.epoch;
    authenticated.flow_id = flow.id;
    authenticated.flow_generation = flow.generation;
    authenticated.state = aifc::EvidenceState::EVIDENCE_CURRENT;
    authenticated.source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    authenticated.confidence = aifc::source_confidence(authenticated.source);
    authenticated.workload_generation = aifc::WorkloadGeneration{1};
    authenticated.generation = aifc::EvidenceGeneration{1};
    authenticated.accepted_seq = 1;
    authenticated.semantic = random_class(rng, false);
    authenticated.content_digest = aifc::compute_evidence_digest(authenticated);

    aifc::EvidenceRecord heuristic = make_record(rng, 1, flow, authority);
    // Deliberately the strongest possible rank key below the source: a huge workload
    // generation, a huge acceptance sequence and an identity that sorts first.
    heuristic.id = aifc::make_evidence_id("ev-1000");
    heuristic.publisher = aifc_test::synthetic_publisher(1);
    heuristic.publisher_boot = aifc::PublisherBootId{1};
    heuristic.accepted_epoch = authority.epoch;
    heuristic.flow_id = flow.id;
    heuristic.flow_generation = flow.generation;
    heuristic.state = aifc::EvidenceState::EVIDENCE_CURRENT;
    heuristic.source = aifc::EvidenceSource::HEURISTIC;
    heuristic.confidence = aifc::source_confidence(heuristic.source);
    heuristic.workload_generation = aifc::WorkloadGeneration{1U + rng.next_below(100000U)};
    heuristic.generation = aifc::EvidenceGeneration{1U + rng.next_below(100000U)};
    heuristic.accepted_seq = 1U + rng.next_below(1000000U);
    heuristic.semantic = rng.next_bool() ? authenticated.semantic : random_class(rng, false);
    heuristic.content_digest = aifc::compute_evidence_digest(heuristic);

    aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
    policy.allow_heuristic_evidence = true;

    const bool heuristic_first = rng.next_bool();
    aifc::DecisionInput input;
    input.flow = flow;
    input.policy = policy;
    input.authority = authority;
    if (heuristic_first) {
      input.evidence.push_back(heuristic);
      input.evidence.push_back(authenticated);
    } else {
      input.evidence.push_back(authenticated);
      input.evidence.push_back(heuristic);
    }

    aifc::DecisionEngine engine;
    const aifc::Classification classification = engine.decide(input);

    const std::string detail =
        "order=" + std::string(heuristic_first ? "heuristic-first" : "declaration-first") +
        " authenticated={" + describe(authenticated) + "} heuristic={" + describe(heuristic) +
        "} result={" + describe(classification) + "}";

    seeded.check(classification.selected_evidence == authenticated.id, step,
                 "a current authenticated declaration did not win over a current heuristic "
                 "record: " + detail);
    seeded.check(classification.selected_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                 step, "the winning source is not DECLARED_AUTHENTICATED: " + detail);
    seeded.check(classification.semantic == authenticated.semantic, step,
                 "the reported class is not the declared class: " + detail);
    seeded.check(classification.contradictions.empty(), step,
                 "a heuristic disagreement was reported as a contradiction: " + detail);

    bool heuristic_seen = false;
    bool heuristic_subordinate = false;
    for (const aifc::EvidenceCitation& citation : classification.citations) {
      if (citation.id != heuristic.id) continue;
      heuristic_seen = true;
      heuristic_subordinate = citation.disposition == aifc::EvidenceDisposition::SUBORDINATE;
    }
    seeded.check(heuristic_seen, step, "the heuristic record was not cited at all: " + detail);
    seeded.check(heuristic_subordinate, step,
                 "the heuristic record was not recorded as SUBORDINATE: " + detail);

    if (failure_count() != before) break;
  }
}

// SYNTHETIC inputs, REAL engine.  A heuristic is never sufficient on its own: a set made
// only of current heuristic records produces UNKNOWN, never the guessed class, whether or
// not the policy enables heuristics at all.
AIFC_TEST("precedence.heuristic_alone_never_promotes_a_class") {
  aifc::FlowRecord flow;
  flow.key = aifc_test::synthetic_flow_key(0);
  flow.id = aifc::derive_flow_id(flow.key);
  flow.generation = aifc::FlowGeneration{1};

  const aifc::AuthorityContext authority = make_authority_with_live(5U);

  for (const bool heuristic_allowed : {true, false}) {
    aifc::Rng rng(aifc::seed_from_text("precedence.heuristic_alone_never_promotes_a_class"));
    aifc::EvidenceRecord record = make_record(rng, 0, flow, authority);
    record.flow_id = flow.id;
    record.flow_generation = flow.generation;
    record.accepted_epoch = authority.epoch;
    record.state = aifc::EvidenceState::EVIDENCE_CURRENT;
    record.source = aifc::EvidenceSource::HEURISTIC;
    record.confidence = aifc::source_confidence(record.source);
    record.semantic = aifc::SemanticClass::COLLECTIVE;
    record.content_digest = aifc::compute_evidence_digest(record);

    aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
    policy.allow_heuristic_evidence = heuristic_allowed;

    aifc::DecisionInput input;
    input.flow = flow;
    input.policy = policy;
    input.authority = authority;
    input.evidence.push_back(record);

    aifc::DecisionEngine engine;
    const aifc::Classification classification = engine.decide(input);
    AIFC_CHECK_MSG(aifc::is_unknown(classification.semantic),
                   "heuristic_allowed=" << heuristic_allowed
                                        << " a lone current heuristic record produced class "
                                        << aifc::to_string(classification.semantic) << " -- "
                                        << describe(classification));
    AIFC_CHECK_MSG(classification.state == aifc::ClassificationState::INSUFFICIENT,
                   "heuristic_allowed=" << heuristic_allowed << " expected INSUFFICIENT state -- "
                                        << describe(classification));
    AIFC_CHECK_MSG(classification.selected_evidence.empty(),
                   "heuristic_allowed=" << heuristic_allowed
                                        << " a heuristic record was reported as selected -- "
                                        << describe(classification));
    AIFC_CHECK_MSG(classification.confidence.is_zero(),
                   "heuristic_allowed=" << heuristic_allowed << " expected zero confidence -- "
                                        << describe(classification));
  }
}

// SYNTHETIC inputs, REAL engine.  Two records identical in every field the order looks at
// except the source: the stronger source must outrank, which is the first rule stated at
// the top of decision_engine.hpp.
AIFC_TEST("precedence.identical_records_differ_only_by_source") {
  const aifc::EvidenceSource strengths[kSourceCount] = {
      aifc::EvidenceSource::HEURISTIC,
      aifc::EvidenceSource::TOPOLOGY_CORRELATED,
      aifc::EvidenceSource::COORDINATOR_CORRELATED,
      aifc::EvidenceSource::CONTRACT_DERIVED,
      aifc::EvidenceSource::DECLARED_AUTHENTICATED,
  };
  aifc::FlowRecord flow;
  flow.key = aifc_test::synthetic_flow_key(7);
  flow.id = aifc::derive_flow_id(flow.key);
  flow.generation = aifc::FlowGeneration{1};
  const aifc::AuthorityContext authority = make_authority_with_live(5U);

  for (std::size_t strong_index = 0; strong_index < kSourceCount; ++strong_index) {
    for (std::size_t weak_index = 0; weak_index < kSourceCount; ++weak_index) {
      if (aifc::source_rank(strengths[strong_index]) <= aifc::source_rank(strengths[weak_index])) {
        continue;
      }
      aifc::Rng rng(aifc::seed_from_text("precedence.identical_records_differ_only_by_source"));
      aifc::EvidenceRecord base = make_record(rng, 0, flow, authority);
      base.flow_id = flow.id;
      base.flow_generation = flow.generation;
      base.state = aifc::EvidenceState::EVIDENCE_CURRENT;
      base.accepted_epoch = authority.epoch;

      aifc::EvidenceRecord strong = base;
      strong.source = strengths[strong_index];
      strong.confidence = aifc::source_confidence(strong.source);
      strong.content_digest = aifc::compute_evidence_digest(strong);

      aifc::EvidenceRecord weak = base;
      weak.source = strengths[weak_index];
      weak.confidence = aifc::source_confidence(weak.source);
      weak.content_digest = aifc::compute_evidence_digest(weak);

      AIFC_CHECK_MSG(aifc::evidence_outranks(strong, weak),
                     "source " << aifc::to_string(strong.source) << " does not outrank "
                               << aifc::to_string(weak.source)
                               << " on otherwise identical records: " << describe(strong)
                               << " vs " << describe(weak));
      AIFC_CHECK_MSG(!aifc::evidence_outranks(weak, strong),
                     "source " << aifc::to_string(weak.source) << " also outranks "
                               << aifc::to_string(strong.source) << ": " << describe(weak) << " vs "
                               << describe(strong));
    }
  }
}

// SYNTHETIC inputs, REAL engine.  Currentness (rule 1) is evaluated before source rank
// (rule 2), and the source classes differ in what currentness requires:
// aifc::source_requires_live_session() says an observational source stands or falls with the
// publisher session that made the observation, while CONTRACT_DERIVED does not, because it is
// a statement derived from a durable contract rather than an observation by a session.
//
// The consequence, asserted here rather than glossed over, is that two records identical
// except for their source do not necessarily have the same currentness when the publisher is
// not live: the contract-derived one is still CURRENT and the declaration is STALE.  This is
// why the "a stronger source never loses" property in this file is asserted over records
// whose publisher is live, where a source change cannot cross the currentness boundary.
AIFC_TEST("precedence.source_raise_and_currentness_are_separate_axes") {
  aifc::FlowRecord flow;
  flow.key = aifc_test::synthetic_flow_key(13);
  flow.id = aifc::derive_flow_id(flow.key);
  flow.generation = aifc::FlowGeneration{1};

  // Publisher 0 is KNOWN but deliberately not live, so the liveness rule is the only thing
  // that can decide these two records.
  aifc::AuthorityContext authority;
  authority.epoch = aifc::CoordinatorEpoch{1};
  authority.coordinator_boot = aifc::CoordinatorBootId{1};
  authority.tick = aifc::kTickNone;
  authority.known_publishers.insert(aifc_test::synthetic_publisher(0).value());

  aifc::Rng rng(aifc::seed_from_text("precedence.source_raise_and_currentness"));
  aifc::EvidenceRecord base = make_record(rng, 0, flow, authority);
  base.flow_id = flow.id;
  base.flow_generation = flow.generation;
  base.publisher = aifc_test::synthetic_publisher(0);
  base.publisher_boot = aifc::PublisherBootId{1};
  base.accepted_epoch = authority.epoch;
  base.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  base.semantic = aifc::SemanticClass::COLLECTIVE;

  aifc::EvidenceRecord derived = base;
  derived.source = aifc::EvidenceSource::CONTRACT_DERIVED;
  derived.confidence = aifc::source_confidence(derived.source);
  derived.content_digest = aifc::compute_evidence_digest(derived);

  aifc::EvidenceRecord declared = base;
  declared.source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  declared.confidence = aifc::source_confidence(declared.source);
  declared.content_digest = aifc::compute_evidence_digest(declared);

  AIFC_CHECK_MSG(aifc::source_requires_live_session(aifc::EvidenceSource::DECLARED_AUTHENTICATED),
                 "the liveness rule is expected to cover an authenticated declaration");
  AIFC_CHECK_MSG(!aifc::source_requires_live_session(aifc::EvidenceSource::CONTRACT_DERIVED),
                 "the liveness rule is expected to exempt contract-derived evidence");
  AIFC_CHECK_MSG(aifc::evidence_outranks(declared, derived),
                 "the stronger source should still outrank under the total order: declared={"
                     << describe(declared) << "} derived={" << describe(derived) << "}");

  aifc::DecisionInput derived_input;
  derived_input.flow = flow;
  derived_input.policy = aifc::ClassifierPolicy::initial();
  derived_input.authority = authority;
  derived_input.evidence.push_back(derived);

  aifc::DecisionInput declared_input = derived_input;
  declared_input.evidence.clear();
  declared_input.evidence.push_back(declared);

  aifc::DecisionEngine engine;
  const aifc::Classification derived_result = engine.decide(derived_input);
  const aifc::Classification declared_result = engine.decide(declared_input);

  AIFC_CHECK_MSG(derived_result.state == aifc::ClassificationState::CURRENT &&
                     derived_result.semantic == aifc::SemanticClass::COLLECTIVE,
                 "a CONTRACT_DERIVED record whose publisher is not live should still be CURRENT: "
                     << describe(derived_result));
  AIFC_CHECK_MSG(aifc::is_unknown(declared_result.semantic) &&
                     aifc::is_unknown(declared_result.semantic),
                 "a DECLARED_AUTHENTICATED record whose publisher is not live must not be "
                 "current: "
                     << describe(declared_result));
  bool declared_stale = false;
  for (const aifc::EvidenceCitation& citation : declared_result.citations) {
    if (citation.id == declared.id) {
      declared_stale = citation.state == aifc::EvidenceState::EVIDENCE_STALE &&
                       !citation.detail.empty();
    }
  }
  AIFC_CHECK_MSG(declared_stale,
                 "the staled declaration should be cited STALE with a reason that names the "
                 "publisher: "
                     << describe(declared_result));
  AIFC_CHECK_MSG(derived_result.selected_evidence == derived.id,
                 "the contract-derived record should have selected the class: "
                     << describe(derived_result));
}

// SYNTHETIC inputs, REAL engine.  A class whose confidence is below the configured
// publishable threshold is reported as UNKNOWN/INSUFFICIENT; it is never silently
// replaced by a weaker class supported by lower-ranked evidence, and the disagreement that
// produced it is still visible in the citations.
AIFC_TEST("precedence.below_threshold_class_is_reported_unknown_not_downgraded") {
  aifc::FlowRecord flow;
  flow.key = aifc_test::synthetic_flow_key(11);
  flow.id = aifc::derive_flow_id(flow.key);
  flow.generation = aifc::FlowGeneration{1};
  const aifc::AuthorityContext authority = make_authority_with_live(5U);

  aifc::Rng rng(aifc::seed_from_text("precedence.below_threshold"));
  aifc::EvidenceRecord declared = make_record(rng, 0, flow, authority);
  declared.flow_id = flow.id;
  declared.flow_generation = flow.generation;
  declared.publisher = aifc_test::synthetic_publisher(0);
  declared.accepted_epoch = authority.epoch;
  declared.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  declared.source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  declared.confidence = aifc::source_confidence(declared.source);
  declared.semantic = aifc::SemanticClass::COLLECTIVE;
  declared.content_digest = aifc::compute_evidence_digest(declared);

  aifc::EvidenceRecord weaker = make_record(rng, 1, flow, authority);
  weaker.flow_id = flow.id;
  weaker.flow_generation = flow.generation;
  weaker.publisher = aifc_test::synthetic_publisher(1);
  weaker.accepted_epoch = authority.epoch;
  weaker.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  weaker.source = aifc::EvidenceSource::TOPOLOGY_CORRELATED;
  weaker.confidence = aifc::source_confidence(weaker.source);
  weaker.semantic = aifc::SemanticClass::INFERENCE_REQUEST;
  weaker.content_digest = aifc::compute_evidence_digest(weaker);

  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.minimum_publishable_confidence = 9500U;  // above every source confidence in the tree

  aifc::DecisionInput input;
  input.flow = flow;
  input.policy = policy;
  input.authority = authority;
  input.evidence.push_back(declared);
  input.evidence.push_back(weaker);

  aifc::DecisionEngine engine;
  const aifc::Classification classification = engine.decide(input);

  AIFC_CHECK_MSG(aifc::is_unknown(classification.semantic),
                 "threshold=9500 expected UNKNOWN but the engine reported "
                     << aifc::to_string(classification.semantic) << " -- "
                     << describe(classification));
  AIFC_CHECK_MSG(classification.state == aifc::ClassificationState::INSUFFICIENT,
                 "threshold=9500 expected INSUFFICIENT -- " << describe(classification));
  AIFC_CHECK_MSG(classification.confidence.is_zero(),
                 "threshold=9500 expected zero confidence -- " << describe(classification));
  AIFC_CHECK_MSG(classification.selected_evidence.empty(),
                 "threshold=9500 expected no selected evidence -- " << describe(classification));
  AIFC_CHECK_MSG(classification.applied_penalty_basis_points == 0U,
                 "threshold=9500 expected no applied penalty -- " << describe(classification));

  bool declared_below_threshold = false;
  bool weaker_contradicting = false;
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    if (citation.id == declared.id) {
      declared_below_threshold = citation.disposition == aifc::EvidenceDisposition::BELOW_THRESHOLD;
    }
    if (citation.id == weaker.id) {
      weaker_contradicting = citation.disposition == aifc::EvidenceDisposition::CONTRADICTING;
    }
  }
  AIFC_CHECK_MSG(declared_below_threshold,
                 "the sub-threshold record was not cited BELOW_THRESHOLD -- "
                     << describe(classification));
  AIFC_CHECK_MSG(weaker_contradicting,
                 "the sub-threshold decision hid the disagreement: the lower-ranked record was "
                 "not cited CONTRADICTING -- "
                     << describe(classification));

  // Raising the threshold above 9000 is what suppresses the answer; at the default
  // threshold the same evidence set reports the declaration.
  policy.minimum_publishable_confidence = 1000U;
  input.policy = policy;
  const aifc::Classification published = engine.decide(input);
  AIFC_CHECK_MSG(published.semantic == aifc::SemanticClass::COLLECTIVE,
                 "threshold=1000 expected the declared class COLLECTIVE -- " << describe(published));
  AIFC_CHECK_MSG(published.selected_evidence == declared.id,
                 "threshold=1000 expected the declaration to be selected -- "
                     << describe(published));
}

}  // namespace
