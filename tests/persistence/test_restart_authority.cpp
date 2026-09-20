// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// The closure requirement: persistence is not currentness.
//
// Capability labels
// -----------------
//   REAL        Coordinator::start on a real state file written by a real coordinator, with
//               a real epoch advance, a real restore and a real re-publication.
//   SYNTHETIC   every publisher, workload, flow and payload.
//   UNSUPPORTED nothing is stubbed or skipped.
//
// The chain these cases prove, in order:
//
//   1. a live, current, authenticated declaration exists and decides a flow;
//   2. the process is replaced and the durable state is read back;
//   3. the epoch advanced and the boot incarnation advanced with it;
//   4. every session is gone, and the pre-restart envelope is refused;
//   5. the restored evidence is not current, and the class it used to decide is not
//      reported as current;
//   6. the explanation says why -- the reload, not something incidental;
//   7. the pre-restart decision is still recorded in history, as a historical fact;
//   8. authority can be recovered, but only by a real act: a new session, a new
//      publication and a strictly larger generation.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "ai_flow_classifier/foundation/text.hpp"
#include "synthetic.hpp"
#include "test_framework.hpp"

namespace {

using aifc::ClassificationResult;
using aifc::ErrorCode;
using aifc::EvidenceSource;
using aifc::SemanticClass;
using aifc::Status;
// The port a synthetic heuristic submission cites, and the value that travels in the record's
// opaque binding field as (transport << 16) | port.  It must match a hint the policy declares.
constexpr std::uint16_t kHeuristicPort = 8443U;

[[nodiscard]] std::string describe(const ClassificationResult& result) {
  std::string out;
  out += "class=";
  out += aifc::to_string(result.classification.semantic);
  out += " state=";
  out += aifc::to_string(result.classification.state);
  out += " confidence=";
  out += result.classification.confidence.to_decimal();
  out += " selected_source=";
  out += aifc::to_string(result.classification.selected_source);
  out += " selected_evidence=";
  out += result.classification.selected_evidence.empty()
             ? std::string("<none>")
             : result.classification.selected_evidence.value();
  out += " historical=";
  out += result.historical ? "true" : "false";
  for (const aifc::EvidenceCitation& citation : result.classification.citations) {
    out += " [";
    out += citation.id.value();
    out += " source=";
    out += aifc::to_string(citation.source);
    out += " state=";
    out += aifc::to_string(citation.state);
    out += " class=";
    out += aifc::to_string(citation.semantic);
    out += " disposition=";
    out += aifc::to_string(citation.disposition);
    out += " detail=\"";
    out += citation.detail;
    out += "\"]";
  }
  return out;
}

// True when the text attributes the loss of currentness to the reload or the restart.  Other
// reasons (a dead publisher, an expired freshness window) are legitimate in general but are
// not the reason here, and a case that accepted them would not be testing the closure.
[[nodiscard]] bool names_a_restart_as_the_reason(const std::string& text) {
  return text.find("restart") != std::string::npos ||
         text.find("re-establish") != std::string::npos ||
         text.find("durable state") != std::string::npos ||
         text.find("reloaded") != std::string::npos;
}

[[nodiscard]] aifc::ClassifierPolicy restart_policy() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.allow_heuristic_evidence = true;
  policy.allow_heuristic_evidence = true;
  // A heuristic submission must cite a declared, enabled hint: the runtime refuses a
  // heuristic observation that names no usable hint, which is what makes "an adapter must be
  // enabled by name" an enforced rule rather than a documented intention.  The policy below
  // declares one adapter and one port hint so that heuristic evidence can legitimately enter.
  aifc::HeuristicAdapterPolicy adapter;
  adapter.name = "synthetic.adapter";
  adapter.enabled = true;
  adapter.max_basis_points = 2000U;
  adapter.priority = 0;
  policy.heuristic_adapters.push_back(adapter);
  aifc::PortHint hint;
  hint.transport = aifc::TransportProtocol::TCP;
  hint.port = kHeuristicPort;
  hint.semantic = aifc::SemanticClass::SHUFFLE;
  hint.basis_points = 500U;
  hint.adapter = "synthetic.adapter";
  policy.port_hints.push_back(hint);
  (void)0;
  return policy;
}

[[nodiscard]] aifc::CoordinatorOptions options_for(const std::string& path) {
  aifc::CoordinatorOptions options;
  options.state_path = path;
  options.policy = restart_policy();
  return options;
}

[[nodiscard]] ClassificationResult classify_now(aifc::Classifier& classifier,
                                               const aifc::FlowRecord& flow) {
  aifc::ClassificationQuery query;
  query.flow_key = flow.key;
  query.flow_generation = flow.generation;
  query.explain = true;
  query.accept_current_generation = true;
  auto result = classifier.classify(query);
  if (!result) {
    AIFC_FAIL("classification failed: " << aifc::render_status(result.status()));
    return ClassificationResult{};
  }
  return result.value();
}

[[nodiscard]] aifc::EvidencePayload declaration_payload(const aifc::FlowRecord& flow,
                                                       std::uint64_t generation) {
  aifc::EvidencePayload payload;
  payload.flow_key = flow.key;
  payload.flow_generation = flow.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{generation};
  payload.semantic = SemanticClass::TRAINING_SYNC;
  payload.claimed_source = EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "restart.topic.declaration";
  payload.metadata.reason = "synthetic authenticated declaration";
  return payload;
}

// A coordinator, a durable image of it, and a second coordinator that has been started on
// that image.  A Coordinator owns a mutex and is therefore neither copyable nor movable, so
// the two incarnations are members of this object rather than values returned from a
// factory.
struct RestartFixture {
  explicit RestartFixture(const std::string& state_path)
      : path(state_path), before(options_for(state_path)), after(options_for(state_path)) {
    declare();
    persist_and_replace();
  }

  // The whole point: a second process, the same state path, a new boot incarnation.
  void restart() {
    const Status started = after.start(aifc::CoordinatorBootId{2});
    AIFC_CHECK_MSG(started.ok(),
                   "the coordinator must start on its own durable state: "
                       << aifc::render_status(started));
    restarted = started.ok();
  }

  [[nodiscard]] aifc::SessionEnvelope pre_restart_envelope() const {
    aifc::SessionEnvelope envelope;
    envelope.publisher = aifc_test::synthetic_publisher(0U);
    envelope.publisher_boot = aifc::PublisherBootId{1};
    envelope.session = aifc_test::synthetic_session(0U);
    envelope.epoch = epoch_before;
    envelope.coordinator_boot = boot_before;
    envelope.max_source = EvidenceSource::DECLARED_AUTHENTICATED;
    return envelope;
  }

  std::string path;
  aifc::Coordinator before;
  aifc::Coordinator after;
  aifc::CoordinatorEpoch epoch_before;
  aifc::CoordinatorBootId boot_before;
  aifc::FlowRecord flow;
  aifc::EvidenceId declaration_id;
  std::uint64_t declaration_generation = 0;
  aifc::Digest256 decision_digest_before;
  bool restarted = false;

 private:
  void declare() {
    AIFC_CHECK_OK(before.start(aifc::CoordinatorBootId{1}));
    epoch_before = before.epoch();
    boot_before = before.boot();

    aifc::Classifier& classifier = before.classifier();
    auto registration = classifier.register_publisher(
        aifc_test::synthetic_publisher(0U), aifc::PublisherBootId{1},
        EvidenceSource::DECLARED_AUTHENTICATED, aifc_test::synthetic_session(0U),
        "synthetic peer 0");
    AIFC_CHECK_OK(registration);
    if (!registration) return;
    const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

    auto registered = classifier.register_flow(aifc_test::synthetic_flow_key(0U),
                                               aifc::FlowGeneration{0},
                                               registration.value().session);
    AIFC_CHECK_OK(registered);
    if (!registered) return;
    flow = registered.value().record;

    auto published = classifier.submit_evidence(envelope, declaration_payload(flow, 1U));
    AIFC_CHECK_OK(published);
    if (!published) return;
    declaration_id = published.value().record.id;
    declaration_generation = published.value().record.generation.value;
    AIFC_CHECK_MSG(published.value().record.state == aifc::EvidenceState::EVIDENCE_CURRENT,
                   "the declaration must be current before the restart: "
                       << aifc::to_string(published.value().record.state));

    const ClassificationResult decided = classify_now(classifier, flow);
    AIFC_CHECK_MSG(decided.classification.semantic == SemanticClass::TRAINING_SYNC,
                   "the authenticated declaration must decide the flow before the restart: "
                       << describe(decided));
    AIFC_CHECK_MSG(decided.classification.state == aifc::ClassificationState::CURRENT,
                   "the pre-restart decision must be current: " << describe(decided));
    decision_digest_before = decided.classification.digest;
  }

  void persist_and_replace() {
    AIFC_CHECK_OK(before.persist());
    AIFC_CHECK_OK(before.stop());
    restart();
  }
};

}  // namespace

AIFC_TEST("restart authority: the epoch and the boot incarnation advance across a restart") {
  aifc_test::ScratchDirectory scratch("restart-epoch");
  RestartFixture fixture(scratch.file("coordinator.aifs"));
  if (!fixture.restarted) return;

  AIFC_CHECK_MSG(fixture.epoch_before.valid(),
                 "the pre-restart epoch is " << fixture.epoch_before.to_string());
  AIFC_CHECK_MSG(fixture.after.epoch().value == fixture.epoch_before.value + 1U,
                 "the epoch did not advance exactly once: before="
                     << fixture.epoch_before.to_string() << " after="
                     << fixture.after.epoch().to_string());
  AIFC_CHECK_MSG(fixture.after.boot() == aifc::CoordinatorBootId{2},
                 "the boot incarnation is " << fixture.after.boot().to_string() << ", expected 2");
  AIFC_CHECK_MSG(fixture.boot_before != fixture.after.boot(),
                 "the boot incarnation did not change across the restart");
  AIFC_CHECK_MSG(fixture.after.stats().coordinator.restarts >= 1U,
                 "the coordinator did not report that it restored durable state: restarts="
                     << fixture.after.stats().coordinator.restarts);
}

AIFC_TEST("restart authority: every session is gone and the pre-restart envelope is refused") {
  aifc_test::ScratchDirectory scratch("restart-sessions");
  RestartFixture fixture(scratch.file("coordinator.aifs"));
  if (!fixture.restarted) return;
  aifc::Classifier& classifier = fixture.after.classifier();

  AIFC_CHECK_EQ(classifier.stats().publishers.live, std::size_t{0});
  AIFC_CHECK_EQ(fixture.after.stats().coordinator.active_sessions, std::size_t{0});

  // The envelope the previous incarnation used is refused on its epoch: the epoch is the
  // first fence, and it moved.
  aifc::EvidencePayload payload = declaration_payload(fixture.flow, 2U);
  auto refused = classifier.submit_evidence(fixture.pre_restart_envelope(), payload);
  AIFC_CHECK_MSG(!refused, "the pre-restart envelope was accepted after the restart");
  if (!refused) {
    AIFC_CHECK_MSG(refused.code() == ErrorCode::STALE_EPOCH,
                   "the pre-restart envelope was refused with " << aifc::to_string(refused.code())
                                                               << " rather than STALE_EPOCH");
  }

  // The same envelope rebuilt with the *current* epoch is still refused, because the session
  // identity it presents is not the session the coordinator holds -- there is none.
  aifc::SessionEnvelope rebound = fixture.pre_restart_envelope();
  rebound.epoch = fixture.after.epoch();
  rebound.coordinator_boot = fixture.after.boot();
  auto rebound_result = classifier.submit_evidence(rebound, payload);
  AIFC_CHECK_MSG(!rebound_result, "a stale session identity was accepted in the new epoch");
  if (!rebound_result) {
    AIFC_CHECK_MSG(rebound_result.code() == ErrorCode::UNAUTHENTICATED,
                   "a stale session identity was refused with "
                       << aifc::to_string(rebound_result.code()) << " rather than UNAUTHENTICATED");
  }

  // The durable registration survives, but without liveness and without a session: that is
  // the whole mechanism.
  auto registration = classifier.find_publisher(aifc_test::synthetic_publisher(0U));
  AIFC_CHECK_OK(registration);
  if (registration) {
    AIFC_CHECK_MSG(registration.value().state != aifc::PublisherState::LIVE,
                   "the restored publisher is LIVE, which would resurrect liveness: "
                       << aifc::to_string(registration.value().state));
    AIFC_CHECK_MSG(registration.value().session.empty(),
                   "the restored registration still carries the session identity ["
                       << registration.value().session.value() << "]");
    AIFC_CHECK_MSG(registration.value().boot == aifc::PublisherBootId{1},
                   "the durable publisher incarnation was lost: boot is "
                       << registration.value().boot.to_string() << ", expected 1");
  }
}

AIFC_TEST("restart authority: restored evidence is not current and the explanation says why") {
  aifc_test::ScratchDirectory scratch("restart-currentness");
  RestartFixture fixture(scratch.file("coordinator.aifs"));
  if (!fixture.restarted) return;
  aifc::Classifier& classifier = fixture.after.classifier();

  auto restored = classifier.find_evidence(fixture.declaration_id);
  AIFC_CHECK_OK(restored);
  std::string reason;
  if (restored) {
    reason = restored.value().state_reason;
    AIFC_CHECK_MSG(restored.value().state != aifc::EvidenceState::EVIDENCE_CURRENT,
                   "the restored evidence is CURRENT, so a restart resurrected authority: "
                       << aifc::to_string(restored.value().state));
    AIFC_CHECK_MSG(!restored.value().carries_authority(),
                   "the restored evidence still claims to carry authority: "
                       << aifc::to_string(restored.value().state));
    AIFC_CHECK_MSG(!reason.empty(),
                   "the restored evidence carries no reason for having lost currentness");
    AIFC_CHECK_MSG(names_a_restart_as_the_reason(reason),
                   "the state reason does not attribute the loss of currentness to the restart: ["
                       << reason << "]");
    AIFC_CHECK_MSG(restored.value().generation.value == fixture.declaration_generation,
                   "the restored evidence lost its generation: "
                       << restored.value().generation.to_string() << " rather than "
                       << fixture.declaration_generation);
  }

  const ClassificationResult result = classify_now(classifier, fixture.flow);
  AIFC_CHECK_MSG(result.classification.semantic == SemanticClass::UNKNOWN,
                 "the pre-restart class is still reported after the restart: " << describe(result));
  AIFC_CHECK_MSG(result.classification.state == aifc::ClassificationState::STALE ||
                     result.classification.state == aifc::ClassificationState::INSUFFICIENT,
                 "the post-restart state is " << aifc::to_string(result.classification.state)
                                              << ", expected STALE or INSUFFICIENT: "
                                              << describe(result));
  AIFC_CHECK_MSG(result.classification.state != aifc::ClassificationState::CURRENT,
                 "the pre-restart class is reported as CURRENT: " << describe(result));
  AIFC_CHECK_MSG(result.classification.semantic != SemanticClass::TRAINING_SYNC,
                 "the pre-restart class survived the restart: " << describe(result));

  if (!reason.empty()) {
    AIFC_CHECK_MSG(result.explanation.find(reason) != std::string::npos,
                   "the explanation does not surface the reason recorded on the evidence; "
                   "reason=["
                       << reason << "] explanation=[" << result.explanation << "]");
  }
  AIFC_CHECK_MSG(names_a_restart_as_the_reason(result.explanation),
                 "the explanation does not attribute the loss of currentness to the restart: ["
                     << result.explanation << "]");
}

AIFC_TEST("restart authority: the pre-restart decision is history, and recovery takes a real act") {
  aifc_test::ScratchDirectory scratch("restart-recovery");
  RestartFixture fixture(scratch.file("coordinator.aifs"));
  if (!fixture.restarted) return;
  aifc::Classifier& classifier = fixture.after.classifier();

  // --- the pre-restart decision is still recorded, as a historical fact ---
  const auto count_history = [&](const std::vector<aifc::Classification>& entries,
                                 const aifc::Digest256& digest) {
    std::size_t count = 0;
    for (const aifc::Classification& entry : entries) {
      if (entry.flow_id == fixture.flow.id && entry.flow_generation == fixture.flow.generation &&
          entry.digest == digest) {
        ++count;
      }
    }
    return count;
  };
  const aifc::Classifier::DurableState durable = classifier.durable_state();
  AIFC_CHECK_MSG(count_history(durable.classifications, fixture.decision_digest_before) > 0,
                 "the pre-restart decision digest " << fixture.decision_digest_before.to_hex()
                                                    << " is not in history; history holds "
                                                    << durable.classifications.size()
                                                    << " decisions");
  for (const aifc::Classification& entry : durable.classifications) {
    if (entry.digest == fixture.decision_digest_before) {
      AIFC_CHECK_MSG(entry.semantic == SemanticClass::TRAINING_SYNC,
                     "the historical decision lost its class");
    }
  }

  // Classifying after the restart records a new decision.  The pre-restart decision stays in
  // history; the answer the runtime now gives is a different, newly computed one.
  const ClassificationResult after_restart = classify_now(classifier, fixture.flow);
  AIFC_CHECK_MSG(after_restart.classification.semantic == SemanticClass::UNKNOWN,
                 "the post-restart classification is " << describe(after_restart));
  AIFC_CHECK_MSG(after_restart.classification.digest != fixture.decision_digest_before,
                 "the post-restart decision reuses the pre-restart digest");
  const aifc::Classifier::DurableState after_durable = classifier.durable_state();
  AIFC_CHECK_MSG(count_history(after_durable.classifications, after_restart.classification.digest) > 0,
                 "the decision that was just produced (" << after_restart.classification.digest.to_hex()
                                                         << ") was not recorded in history");
  AIFC_CHECK_MSG(count_history(after_durable.classifications, fixture.decision_digest_before) > 0,
                 "recording the new decision lost the pre-restart decision");

  // --- recovery: a new session, in the new epoch, with a strictly larger generation ---
  auto registration = classifier.register_publisher(
      aifc_test::synthetic_publisher(0U), aifc::PublisherBootId{2},
      EvidenceSource::DECLARED_AUTHENTICATED, aifc_test::synthetic_session(1U),
      "synthetic peer 0, second incarnation");
  AIFC_CHECK_OK(registration);
  if (!registration) return;
  const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

  const aifc::EvidencePayload payload =
      declaration_payload(fixture.flow, fixture.declaration_generation + 1U);
  auto republished = classifier.submit_evidence(envelope, payload);
  AIFC_CHECK_MSG(republished.ok(), "re-establishing authority must be possible: "
                                       << aifc::render_status(republished.status()));
  if (!republished) return;

  const ClassificationResult recovered = classify_now(classifier, fixture.flow);
  AIFC_CHECK_MSG(recovered.classification.semantic == SemanticClass::TRAINING_SYNC,
                 "the recovering declaration did not decide the flow: " << describe(recovered));
  AIFC_CHECK_MSG(recovered.classification.state == aifc::ClassificationState::CURRENT,
                 "the recovered class is not current: " << describe(recovered));
  AIFC_CHECK_MSG(recovered.classification.selected_source == EvidenceSource::DECLARED_AUTHENTICATED,
                 "the recovered decision is not attributed to the authenticated source: "
                     << describe(recovered));
  AIFC_CHECK_MSG(recovered.classification.digest != fixture.decision_digest_before,
                 "the recovered decision reuses the pre-restart decision digest");

  // The recovery took a real act, and a not-an-act is refused: neither a repeat of the
  // generation that was just used nor a return to the generation the previous incarnation
  // used is accepted.
  auto repeated = classifier.submit_evidence(envelope, payload);
  AIFC_CHECK_MSG(!repeated, "a repeated evidence generation was accepted");
  if (!repeated) {
    AIFC_CHECK_MSG(repeated.code() == ErrorCode::REPLAY_DETECTED,
                   "a repeated evidence generation was refused with "
                       << aifc::to_string(repeated.code()) << " rather than REPLAY_DETECTED");
  }
  const aifc::EvidencePayload older =
      declaration_payload(fixture.flow, fixture.declaration_generation);
  auto rejected_older = classifier.submit_evidence(envelope, older);
  AIFC_CHECK_MSG(!rejected_older,
                 "an evidence generation below the high-water mark was accepted");
  if (!rejected_older) {
    AIFC_CHECK_MSG(rejected_older.code() == ErrorCode::REPLAY_DETECTED,
                   "an older evidence generation was refused with "
                       << aifc::to_string(rejected_older.code()) << " rather than REPLAY_DETECTED");
  }

  // Recovery is durable: the state can be written again and read back with the recovered
  // decision in place.
  AIFC_CHECK_OK(fixture.after.persist());
  const aifc::SnapshotLimits limits;
  auto reloaded = aifc::read_snapshot_file(fixture.path, limits);
  AIFC_CHECK_OK(reloaded);
  if (reloaded) {
    AIFC_CHECK_MSG(reloaded.value().epoch == fixture.after.epoch(),
                   "the re-written image carries epoch "
                       << reloaded.value().epoch.to_string() << " rather than "
                       << fixture.after.epoch().to_string());
  }
}
