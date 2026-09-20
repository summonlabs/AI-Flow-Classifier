// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/classify/decision_engine.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

// A candidate is a record that has been evaluated for currentness and is eligible to
// win.  Records that are not eligible still produce a citation, so an explanation is
// exhaustive over the evidence the engine looked at.
struct Candidate {
  EvidenceRecord record;
  EvidenceDisposition disposition = EvidenceDisposition::SELECTED;
  std::string detail;
};

struct RankKey {
  std::uint8_t source = 0;
  std::uint64_t workload_generation = 0;
  Seq accepted_seq = 0;
  std::string id;
};

[[nodiscard]] bool ranks_above(const RankKey& left, const RankKey& right) {
  if (left.source != right.source) return left.source > right.source;
  if (left.workload_generation != right.workload_generation) {
    return left.workload_generation > right.workload_generation;
  }
  if (left.accepted_seq != right.accepted_seq) return left.accepted_seq > right.accepted_seq;
  return left.id < right.id;
}

[[nodiscard]] RankKey rank_of(const EvidenceRecord& record) {
  RankKey key;
  key.source = source_rank(record.source);
  key.workload_generation = record.workload_generation.value;
  key.accepted_seq = record.accepted_seq;
  key.id = record.id.value();
  return key;
}

[[nodiscard]] EvidenceDisposition disposition_for_state(EvidenceState state) {
  switch (state) {
    case EvidenceState::EVIDENCE_CURRENT:
      return EvidenceDisposition::CORROBORATING;
    case EvidenceState::EVIDENCE_STALE:
      return EvidenceDisposition::STALE;
    case EvidenceState::EVIDENCE_SUPERSEDED:
      return EvidenceDisposition::WITHDRAWN;
    case EvidenceState::EVIDENCE_REVOKED:
      return EvidenceDisposition::REVOKED;
    case EvidenceState::EVIDENCE_INSUFFICIENT:
      return EvidenceDisposition::BELOW_THRESHOLD;
    case EvidenceState::EVIDENCE_REJECTED:
      return EvidenceDisposition::REJECTED;
    case EvidenceState::EVIDENCE_NONE:
      return EvidenceDisposition::REJECTED;
  }
  return EvidenceDisposition::REJECTED;
}

// Synthesises the contract-derived evidence for one contract and one flow.  The id
// is derived from the contract and the flow generation, so the same contract applied
// to the same incarnation always yields the same identity — which is what makes the
// decision digest reproducible across processes.
[[nodiscard]] EvidenceRecord derive_contract_evidence(const WorkloadContract& contract,
                                                      const FlowRecord& flow, Tick tick,
                                                      std::uint64_t freshness_window,
                                                      CoordinatorEpoch epoch) {
  BufferWriter writer(256);
  Status status = writer.put_string("contract-evidence");
  if (status) status = writer.put_string(contract.id.value());
  if (status) status = writer.put_u64(contract.workload_generation.value);
  if (status) status = writer.put_u64(flow.id.hi);
  if (status) status = writer.put_u64(flow.id.lo);
  if (status) status = writer.put_u64(flow.generation.value);
  if (status) status = writer.put_blob(contract.definition_digest.bytes, Digest256::kBytes);

  EvidenceRecord record;
  if (status) {
    const auto digest = sha256(writer.bytes().data(), writer.bytes().size());
    std::string id_text = "ctr-";
    id_text.reserve(4 + 32);
    static constexpr char kHex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < 16; ++i) {
      id_text.push_back(kHex[(digest[i] >> 4) & 0x0FU]);
      id_text.push_back(kHex[digest[i] & 0x0FU]);
    }
    record.id = make_evidence_id(id_text);
  }
  record.publisher = contract.owner;
  record.publisher_boot = PublisherBootId{};
  record.workload = contract.workload;
  record.workload_generation = contract.workload_generation;
  record.contract = contract.id;
  record.flow_id = flow.id;
  record.flow_generation = flow.generation;
  record.generation = EvidenceGeneration{contract.workload_generation.value};
  // The record is derived by the coordinator that is running right now, so it carries the
  // current epoch.  Leaving the epoch empty would make the engine report it as stale for a
  // reason that is not true, and a denial reason that is not true is worse than no reason.
  record.accepted_epoch = epoch;
  record.accepted_seq = 0;
  record.accepted_tick = tick;
  record.fresh_until = tick == kTickNone ? kTickNone : tick + freshness_window;
  record.semantic = contract.declared_class;
  record.source = contract.derived_source;
  record.state = EvidenceState::EVIDENCE_CURRENT;
  record.confidence = source_confidence(contract.derived_source);
  record.metadata.topic = "contract";
  record.metadata.contract = contract.id;
  record.metadata.reason = "derived from active contract " + contract.id.value();
  record.content_digest = compute_evidence_digest(record);
  return record;
}

[[nodiscard]] bool record_matches_flow(const EvidenceRecord& record, const FlowRecord& flow) {
  return record.flow_id == flow.id && record.flow_generation == flow.generation;
}

}  // namespace

bool evidence_outranks(const EvidenceRecord& left, const EvidenceRecord& right) {
  return ranks_above(rank_of(left), rank_of(right));
}

Digest256 compute_evidence_set_digest(const DecisionInput& input) {
  BufferWriter writer(kMaxBlobBytes);
  Status status = writer.put_u8(1U);
  if (status) status = writer.put_u64(input.flow.id.hi);
  if (status) status = writer.put_u64(input.flow.id.lo);
  if (status) status = writer.put_u64(input.flow.generation.value);
  if (status) status = writer.put_u64(input.policy.generation.value);
  // Every input that can change the answer participates in the digest, including the ones that are
  // not part of any record:
  //
  //   * the authority sequence, because liveness and the epoch decide whether a record is current
  //     and neither of them is stored inside the record;
  //   * the tick, because whether a freshness window has elapsed depends on it.  Leaving the tick
  //     out would let a decision computed while a record was still fresh be reused after it
  //     expired, which is silently reporting the past as the present.
  //
  // The consequence is deliberate: the memo only produces hits for decisions at the same tick,
  // which is exactly the batch case it exists for.
  if (status) status = writer.put_u64(input.authority.authority_sequence);
  if (status) status = writer.put_u64(input.authority.epoch.value);
  if (status) status = writer.put_u64(input.authority.coordinator_boot.value);
  if (status) status = writer.put_u64(input.authority.tick);

  // Records are folded in a canonical order so that the digest does not depend on
  // the order the store happened to hand them over in.
  std::vector<const EvidenceRecord*> records;
  records.reserve(input.evidence.size());
  for (const EvidenceRecord& record : input.evidence) records.push_back(&record);
  std::sort(records.begin(), records.end(),
            [](const EvidenceRecord* a, const EvidenceRecord* b) { return a->id < b->id; });

  if (status) status = writer.put_u32(static_cast<std::uint32_t>(records.size()));
  for (const EvidenceRecord* record : records) {
    if (!status) break;
    status = writer.put_blob(record->content_digest.bytes, Digest256::kBytes);
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(record->state));
    if (status) status = writer.put_u64(record->fresh_until);
  }

  std::vector<const WorkloadContract*> contracts;
  contracts.reserve(input.active_contracts.size());
  for (const WorkloadContract& contract : input.active_contracts) contracts.push_back(&contract);
  std::sort(contracts.begin(), contracts.end(),
            [](const WorkloadContract* a, const WorkloadContract* b) { return a->id < b->id; });
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(contracts.size()));
  for (const WorkloadContract* contract : contracts) {
    if (!status) break;
    status = writer.put_blob(contract->definition_digest.bytes, Digest256::kBytes);
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(contract->state));
  }

  if (status) status = writer.put_bool(input.generation_revoked);

  Digest256 digest;
  if (!status) return digest;
  Sha256 hasher;
  hasher.update(writer.bytes());
  hasher.finish(digest.bytes);
  return digest;
}

Classification DecisionEngine::decide(const DecisionInput& input) const {
  const ClassifierPolicy& policy = input.policy;
  const Tick tick = input.authority.tick;
  const std::uint64_t freshness_window =
      policy.default_freshness_window == 0 ? 1 : policy.default_freshness_window;

  Classification result;
  result.flow_id = input.flow.id;
  result.flow_generation = input.flow.generation;
  result.policy_generation = policy.generation;
  result.policy_digest = compute_policy_digest(policy);
  result.coordinator_epoch = input.authority.epoch;
  result.coordinator_boot = input.authority.coordinator_boot;
  result.decided_tick = tick;

  // ---- 1. assemble the candidate pool ------------------------------------
  std::vector<Candidate> candidates;
  std::unordered_set<std::string> seen_ids;

  for (const EvidenceRecord& record : input.evidence) {
    Candidate candidate;
    candidate.record = record;
    if (seen_ids.find(record.id.value()) != seen_ids.end()) {
      // Two different records with one identity would make "the evidence set" ill
      // defined.  The store refuses this too; the engine refuses to guess.
      candidate.disposition = EvidenceDisposition::REJECTED;
      candidate.detail = "duplicate evidence identity in the considered set";
      candidates.push_back(std::move(candidate));
      continue;
    }
    seen_ids.insert(record.id.value());
    candidates.push_back(std::move(candidate));
  }

  // Contract-derived evidence is synthesised for contracts that are active, owned by
  // a workload whose current generation matches, and whose scope covers the flow.
  for (const WorkloadContract& contract : input.active_contracts) {
    if (contract.state != ContractState::ACTIVE) continue;
    if (!contract_covers(contract, input.flow.key)) continue;

    bool workload_matches = false;
    WorkloadGeneration current_generation{};
    for (const WorkloadRecord& workload : input.workloads) {
      if (workload.id == contract.workload) {
        workload_matches = true;
        current_generation = workload.generation;
        break;
      }
    }
    if (!workload_matches) continue;
    // Generation fencing: a contract bound to an older workload generation is not a
    // current statement about that workload, so it produces nothing.
    if (contract.workload_generation != current_generation) continue;

    EvidenceRecord derived = derive_contract_evidence(contract, input.flow, tick, freshness_window,
                                                       input.authority.epoch);
    if (seen_ids.find(derived.id.value()) != seen_ids.end()) continue;
    seen_ids.insert(derived.id.value());
    Candidate candidate;
    candidate.record = std::move(derived);
    candidates.push_back(std::move(candidate));
  }

  // ---- 2. evaluate currentness -------------------------------------------
  for (Candidate& candidate : candidates) {
    if (candidate.disposition == EvidenceDisposition::REJECTED) continue;
    EvidenceRecord& record = candidate.record;

    if (!record_matches_flow(record, input.flow)) {
      // Evidence about another incarnation of the flow, or about another flow.  It
      // is not wrong, it is simply not about this question.
      record.state = EvidenceState::EVIDENCE_STALE;
      record.state_reason = "evidence is bound to a different flow generation";
      candidate.disposition = EvidenceDisposition::STALE;
      candidate.detail = "bound to flow generation " + record.flow_generation.to_string() +
                         " rather than " + input.flow.generation.to_string();
      continue;
    }

    if (record.state == EvidenceState::EVIDENCE_CURRENT) {
      if (record.accepted_epoch != input.authority.epoch) {
        record.state = EvidenceState::EVIDENCE_STALE;
        record.state_reason = "accepted in coordinator epoch " + record.accepted_epoch.to_string() +
                              " rather than " + input.authority.epoch.to_string();
      } else if (!record.carries_authority()) {
        record.state = EvidenceState::EVIDENCE_STALE;
        record.state_reason = "record no longer carries authority";
      } else if (record.source == EvidenceSource::HEURISTIC && !policy.allow_heuristic_evidence) {
        record.state = EvidenceState::EVIDENCE_REJECTED;
        record.state_reason =
            "policy does not permit heuristic evidence; heuristic adapters are disabled";
      } else if (source_requires_live_session(record.source) && !input.authority.is_live(record)) {
        // The liveness rule.  A record whose publisher is not live at the exact boot
        // that published it is not current, whatever the record itself records.  This
        // is the mechanism that makes "dead publisher evidence loses current
        // authority" true without any mutable flag inside the record.
        record.state = EvidenceState::EVIDENCE_STALE;
        record.state_reason = input.authority.is_known(record)
                                  ? "publisher " + record.publisher.value() + " boot " +
                                        record.publisher_boot.to_string() +
                                        " is not live in the current coordinator epoch"
                                  : "publisher " + record.publisher.value() +
                                        " is no longer registered";
      } else if (tick != kTickNone && record.fresh_until != kTickNone && tick > record.fresh_until) {
        record.state = EvidenceState::EVIDENCE_STALE;
        record.state_reason = "freshness window expired at tick " + std::to_string(record.fresh_until);
      }
    }

    if (record.state != EvidenceState::EVIDENCE_CURRENT) {
      if (candidate.disposition == EvidenceDisposition::SELECTED) {
        candidate.disposition = disposition_for_state(record.state);
      }
      if (candidate.detail.empty()) {
        candidate.detail = record.state_reason;
      }
      continue;
    }

    // Current.  A heuristic record is noted but is never decisive and never
    // contradicts: it is subordinate by construction.
    if (source_is_heuristic(record.source)) {
      candidate.disposition = EvidenceDisposition::SUBORDINATE;
      candidate.detail = "heuristic source: never decisive, never a contradiction";
    }
  }

  // ---- 3. choose the winner ----------------------------------------------
  // Sorting the candidates makes the whole remainder independent of input order.
  std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
    const bool a_eligible = a.disposition == EvidenceDisposition::SELECTED;
    const bool b_eligible = b.disposition == EvidenceDisposition::SELECTED;
    if (a_eligible != b_eligible) return a_eligible;
    return ranks_above(rank_of(a.record), rank_of(b.record));
  });

  const Candidate* winner = nullptr;
  if (input.generation_revoked) {
    result.state = ClassificationState::REVOKED;
    result.semantic = SemanticClass::UNKNOWN;
    result.confidence = Confidence::none();
    result.selected_source = EvidenceSource::UNKNOWN;
  } else {
    for (const Candidate& candidate : candidates) {
      if (candidate.disposition != EvidenceDisposition::SELECTED) continue;
      if (is_unknown(candidate.record.semantic)) continue;  // UNKNOWN cannot be a winner
      winner = &candidate;
      break;
    }
  }

  // ---- 4. build citations and detect contradictions -----------------------
  std::uint32_t corroboration = 0;

  for (const Candidate& candidate : candidates) {
    EvidenceCitation citation;
    citation.id = candidate.record.id;
    citation.publisher = candidate.record.publisher;
    citation.source = candidate.record.source;
    citation.state = candidate.record.state;
    citation.semantic = candidate.record.semantic;
    citation.confidence = candidate.record.confidence;
    citation.generation = candidate.record.generation;
    citation.accepted_seq = candidate.record.accepted_seq;
    citation.accepted_tick = candidate.record.accepted_tick;
    citation.fresh_until = candidate.record.fresh_until;
    citation.detail = candidate.detail;

    EvidenceDisposition disposition = candidate.disposition;
    if (winner != nullptr && &candidate == winner) {
      disposition = EvidenceDisposition::SELECTED;
    } else if (candidate.record.state == EvidenceState::EVIDENCE_CURRENT) {
      if (source_is_heuristic(candidate.record.source)) {
        // A heuristic record is noted and nothing more.  It is never corroboration
        // and never a contradiction, so it can neither strengthen nor block a class.
        disposition = EvidenceDisposition::SUBORDINATE;
      } else if (winner == nullptr) {
        // There is no winner, so this record did not select anything.  It stays
        // visible as a considered record without claiming to corroborate.
        disposition = EvidenceDisposition::SUBORDINATE;
      } else if (candidate.record.semantic == winner->record.semantic) {
        disposition = EvidenceDisposition::CORROBORATING;
        ++corroboration;
      } else if (is_unknown(candidate.record.semantic)) {
        disposition = EvidenceDisposition::SUBORDINATE;
      } else {
        disposition = EvidenceDisposition::CONTRADICTING;
      }
    }
    citation.disposition = disposition;
    result.citations.push_back(std::move(citation));
  }

  // Stable citation order: by (disposition, evidence id).  This is what makes the
  // rendered explanation identical for identical evidence sets.
  std::sort(result.citations.begin(), result.citations.end(),
            [](const EvidenceCitation& a, const EvidenceCitation& b) {
              if (a.disposition != b.disposition) return a.disposition < b.disposition;
              return a.id < b.id;
            });

  if (winner != nullptr) {
    result.semantic = winner->record.semantic;
    result.selected_evidence = winner->record.id;
    result.selected_source = winner->record.source;
    result.confidence = Confidence::weaker(winner->record.confidence,
                                           source_confidence(winner->record.source));
    result.corroboration_count = corroboration;

    // A contradiction is a disagreement between two current, authoritative records
    // about the same flow generation.  It is reported, never resolved silently, and
    // it carries an explicit, configured penalty.
    std::vector<const Candidate*> contradicting;
    for (const Candidate& candidate : candidates) {
      if (candidate.record.state != EvidenceState::EVIDENCE_CURRENT) continue;
      if (source_is_heuristic(candidate.record.source)) continue;
      if (candidate.record.semantic == winner->record.semantic) continue;
      if (is_unknown(candidate.record.semantic)) continue;
      contradicting.push_back(&candidate);
    }
    std::sort(contradicting.begin(), contradicting.end(),
              [](const Candidate* a, const Candidate* b) {
                return ranks_above(rank_of(a->record), rank_of(b->record));
              });
    for (const Candidate* candidate : contradicting) {
      ClassificationContradiction contradiction;
      contradiction.left_id = winner->record.id;
      contradiction.left_class = winner->record.semantic;
      contradiction.left_source = winner->record.source;
      contradiction.right_id = candidate->record.id;
      contradiction.right_class = candidate->record.semantic;
      contradiction.right_source = candidate->record.source;
      contradiction.resolved_by =
          "evidence precedence: source rank " +
          std::to_string(static_cast<unsigned>(source_rank(winner->record.source))) + " outranks " +
          std::to_string(static_cast<unsigned>(source_rank(candidate->record.source)));
      result.contradictions.push_back(std::move(contradiction));
    }

    if (!result.contradictions.empty()) {
      result.applied_penalty_basis_points = policy.contradiction_penalty;
      result.confidence = result.confidence.reduced_by(policy.contradiction_penalty);
      result.state = ClassificationState::CONTRADICTED;
    } else if (corroboration > 0) {
      result.state = ClassificationState::CORROBORATED;
    } else {
      result.state = ClassificationState::CURRENT;
    }

    // The publishable threshold.  A class that cannot be published does not become a
    // weaker class and does not become UNKNOWN-by-accident: it becomes UNKNOWN with
    // INSUFFICIENT state, and the candidate that fell short is still cited.
    if (result.confidence.basis_points() < policy.minimum_publishable_confidence) {
      for (EvidenceCitation& citation : result.citations) {
        if (citation.id == winner->record.id) {
          citation.disposition = EvidenceDisposition::BELOW_THRESHOLD;
          citation.detail = "confidence below the publishable threshold; class reported as UNKNOWN";
        }
      }
      result.semantic = SemanticClass::UNKNOWN;
      result.state = ClassificationState::INSUFFICIENT;
      result.confidence = Confidence::none();
      result.selected_evidence = EvidenceId{};
      result.selected_source = EvidenceSource::UNKNOWN;
      result.corroboration_count = 0;
      result.contradictions.clear();
      result.applied_penalty_basis_points = 0;
    }
  } else {
    // No eligible winner at all.
    if (!input.generation_revoked) {
      const bool any_current = std::any_of(
          candidates.begin(), candidates.end(), [](const Candidate& candidate) {
            return candidate.record.state == EvidenceState::EVIDENCE_CURRENT;
          });
      const bool any_stale = std::any_of(
          candidates.begin(), candidates.end(), [](const Candidate& candidate) {
            return candidate.record.state == EvidenceState::EVIDENCE_STALE ||
                   candidate.record.state == EvidenceState::EVIDENCE_SUPERSEDED;
          });
      if (any_current) {
        // Only heuristics are current.  A heuristic is never sufficient on its own,
        // by policy, so the answer is UNKNOWN.
        result.state = ClassificationState::INSUFFICIENT;
      } else if (any_stale) {
        result.state = ClassificationState::STALE;
      } else {
        result.state = ClassificationState::INSUFFICIENT;
      }
      result.semantic = SemanticClass::UNKNOWN;
      result.confidence = Confidence::none();
      result.selected_evidence = EvidenceId{};
      result.selected_source = EvidenceSource::UNKNOWN;
    }
  }

  // ---- 5. consideration cap ----------------------------------------------
  {
    const auto is_decisive = [](const EvidenceCitation& citation) {
      return citation.disposition == EvidenceDisposition::SELECTED ||
             citation.disposition == EvidenceDisposition::CONTRADICTING ||
             citation.disposition == EvidenceDisposition::CORROBORATING;
    };
    std::vector<EvidenceCitation> kept;
    std::vector<EvidenceCitation> dropped;
    kept.reserve(result.citations.size());
    for (EvidenceCitation& citation : result.citations) {
      // Decisive citations are never dropped: shrinking a display bound must not
      // remove the reason for the answer.  Everything else is dropped from the end so
      // that the cap itself stays deterministic.
      if (is_decisive(citation)) {
        kept.push_back(std::move(citation));
      } else {
        dropped.push_back(std::move(citation));
      }
    }
    const std::size_t budget =
        result.citations.size() > static_cast<std::size_t>(policy.max_evidence_considered)
            ? (static_cast<std::size_t>(policy.max_evidence_considered) > kept.size()
                   ? static_cast<std::size_t>(policy.max_evidence_considered) - kept.size()
                   : 0U)
            : dropped.size();
    const std::size_t keep_dropped = dropped.size() < budget ? dropped.size() : budget;
    for (std::size_t i = 0; i < keep_dropped; ++i) {
      kept.push_back(std::move(dropped[i]));
    }
    for (std::size_t i = keep_dropped; i < dropped.size(); ++i) {
      dropped[i].disposition = EvidenceDisposition::EXCLUDED_BY_LIMIT;
      dropped[i].detail = "excluded by the policy consideration cap of " +
                          std::to_string(policy.max_evidence_considered) + " citations";
      kept.push_back(std::move(dropped[i]));
    }
    result.citations = std::move(kept);
    std::sort(result.citations.begin(), result.citations.end(),
              [](const EvidenceCitation& a, const EvidenceCitation& b) {
                if (a.disposition != b.disposition) return a.disposition < b.disposition;
                return a.id < b.id;
              });
  }

  // ---- 6. invariants ------------------------------------------------------
  // UNKNOWN never becomes a stronger class because data is missing.  This is
  // asserted here, not merely intended: the engine refuses to return a class it
  // cannot justify with a cited, current record.
  if (result.semantic != SemanticClass::UNKNOWN && result.state != ClassificationState::REVOKED) {
    const bool justified = std::any_of(
        result.citations.begin(), result.citations.end(), [&](const EvidenceCitation& citation) {
          return citation.disposition == EvidenceDisposition::SELECTED &&
                 citation.state == EvidenceState::EVIDENCE_CURRENT &&
                 citation.semantic == result.semantic;
        });
    if (!justified) {
      result.semantic = SemanticClass::UNKNOWN;
      result.state = ClassificationState::INSUFFICIENT;
      result.confidence = Confidence::none();
      result.selected_evidence = EvidenceId{};
      result.selected_source = EvidenceSource::UNKNOWN;
    }
  }

  result.digest = compute_classification_digest(result);
  return result;
}

std::string DecisionEngine::render_explanation(const Classification& classification,
                                               const DecisionInput& input) {
  std::string out;
  out += "flow ";
  out += classification.flow_id.to_hex();
  out += " generation ";
  out += classification.flow_generation.to_string();
  out += "\n  key ";
  out += input.flow.key.to_string();
  out += "\n  semantic_class ";
  out += to_string(classification.semantic);
  out += "\n  state ";
  out += to_string(classification.state);
  out += "\n  confidence ";
  out += classification.confidence.to_decimal();
  out += "\n  selected_evidence ";
  out += classification.selected_evidence.empty() ? std::string("<none>")
                                                  : classification.selected_evidence.value();
  out += "\n  selected_source ";
  out += to_string(classification.selected_source);
  out += "\n  policy_generation ";
  out += classification.policy_generation.to_string();
  out += "\n  policy_digest ";
  out += classification.policy_digest.to_hex();
  out += "\n  coordinator_epoch ";
  out += classification.coordinator_epoch.to_string();
  out += "\n  corroboration_count ";
  out += std::to_string(classification.corroboration_count);
  out += "\n  applied_penalty ";
  out += std::to_string(classification.applied_penalty_basis_points);
  out += "\n  decision_digest ";
  out += classification.digest.to_hex();
  out += "\n  evidence_considered ";
  out += std::to_string(classification.citations.size());
  for (const EvidenceCitation& citation : classification.citations) {
    out += "\n    - ";
    out += citation.id.value();
    out += " [";
    out += to_string(citation.disposition);
    out += "] source=";
    out += to_string(citation.source);
    out += " state=";
    out += to_string(citation.state);
    out += " class=";
    out += to_string(citation.semantic);
    out += " publisher=";
    out += citation.publisher.value();
    out += " generation=";
    out += citation.generation.to_string();
    out += " confidence=";
    out += citation.confidence.to_decimal();
    if (!citation.detail.empty()) {
      out += " detail=\"";
      out += citation.detail;
      out += "\"";
    }
  }
  if (!classification.contradictions.empty()) {
    out += "\n  contradictions ";
    out += std::to_string(classification.contradictions.size());
    for (const ClassificationContradiction& contradiction : classification.contradictions) {
      out += "\n    - ";
      out += contradiction.left_id.value();
      out += "(";
      out += to_string(contradiction.left_class);
      out += "/";
      out += to_string(contradiction.left_source);
      out += ") conflicts with ";
      out += contradiction.right_id.value();
      out += "(";
      out += to_string(contradiction.right_class);
      out += "/";
      out += to_string(contradiction.right_source);
      out += "); ";
      out += contradiction.resolved_by;
    }
  }
  if (classification.state == ClassificationState::REVOKED) {
    out += "\n  revoked_reason \"";
    out += input.revocation_reason;
    out += "\"";
  }
  return out;
}

}  // namespace aifc
