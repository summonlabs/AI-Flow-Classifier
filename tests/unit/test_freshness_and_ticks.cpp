// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Proof surface: freshness windows and liveness expiry are real, and they are expressed in ticks
// supplied by the caller rather than read from a clock inside the engine.
//
// REAL: the freshness rule, the liveness rule and the manual time source are all exercised through
// the public API.
//
// SYNTHETIC: the flow metadata is invented.
//
// Why this surface exists separately: the decision engine takes a tick as an input so that a test
// can stand exactly on a boundary instead of sleeping past it.  That design only pays off if the
// boundary is actually tested, and a rule that is never reached is a rule nobody has checked.

#include "test_framework.hpp"

#include <string>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "synthetic.hpp"

namespace {

// Builds a classifier whose clock the test controls.  A separate factory is used because the
// clock has to outlive the classifier and the options structure holds a pointer to it.
struct ManualRig {
  aifc::ManualTickSource clock;
  aifc::Classifier classifier;

  ManualRig(aifc::ClassifierPolicy policy, aifc::Tick start) : clock(start), classifier(build(policy)) {}

  [[nodiscard]] aifc::ClassifierOptions build(const aifc::ClassifierPolicy& policy) {
    aifc::ClassifierOptions options;
    options.policy = policy;
    options.clock = &clock;
    return options;
  }
};

}  // namespace

AIFC_TEST("freshness: evidence inside its window is current and past it is stale") {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.default_freshness_window = 1000;
  ManualRig rig(policy, 100);

  const aifc::PublisherId publisher = aifc::make_publisher_id("freshness-publisher");
  auto registration = rig.classifier.register_publisher(
      publisher, aifc::PublisherBootId{1}, aifc::EvidenceSource::DECLARED_AUTHENTICATED,
      aifc::SessionId("freshness-session"), "freshness publisher");
  AIFC_CHECK_OK(registration);
  const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(9001);
  auto flow = rig.classifier.register_flow(key, aifc::FlowGeneration{0}, envelope.session);
  AIFC_CHECK_OK(flow);

  aifc::EvidencePayload payload;
  payload.flow_key = key;
  payload.flow_generation = flow.value().record.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};
  payload.semantic = aifc::SemanticClass::CHECKPOINT;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "freshness.topic";
  AIFC_CHECK_OK(rig.classifier.submit_evidence(envelope, payload));

  auto outcome = rig.classifier.find_evidence(aifc::EvidenceId{});
  (void)outcome;

  aifc::ClassificationQuery query;
  query.flow_key = key;
  query.explain = true;

  // Immediately after publication, and at the exact deadline, the record is still current.
  auto at_publication = rig.classifier.classify(query);
  AIFC_CHECK_OK(at_publication);
  AIFC_CHECK_EQ(static_cast<int>(at_publication.value().classification.semantic),
                static_cast<int>(aifc::SemanticClass::CHECKPOINT));
  AIFC_CHECK_EQ(static_cast<int>(at_publication.value().classification.state),
                static_cast<int>(aifc::ClassificationState::CURRENT));

  rig.clock.set(100 + 1000);
  auto at_deadline = rig.classifier.classify(query);
  AIFC_CHECK_OK(at_deadline);
  AIFC_CHECK_MSG(at_deadline.value().classification.semantic == aifc::SemanticClass::CHECKPOINT,
                 "a record must still be current at exactly its freshness deadline; the state was " +
                     std::string(aifc::to_string(at_deadline.value().classification.state)));

  // One tick later it is stale, and the reason names the deadline.
  rig.clock.set(100 + 1001);
  auto past_deadline = rig.classifier.classify(query);
  AIFC_CHECK_OK(past_deadline);
  // The store's own view is asserted too: a decision that says STALE while the store still says
  // CURRENT would mean the two disagree about the same record, which an operator would see as a
  // contradiction between the answer and the evidence behind it.
  auto stored = rig.classifier.evidence_for_flow(flow.value().record.id);
  AIFC_CHECK_OK(stored);
  AIFC_CHECK_EQ(stored.value().size(), std::size_t{1});
  auto record = rig.classifier.find_evidence(stored.value().front());
  AIFC_CHECK_OK(record);
  AIFC_CHECK_EQ(record.value().fresh_until, static_cast<aifc::Tick>(1100));
  AIFC_CHECK_MSG(record.value().accepted_tick + policy.default_freshness_window ==
                     record.value().fresh_until,
                 "the freshness deadline is not the acceptance tick plus the window");
  AIFC_CHECK_EQ(static_cast<int>(past_deadline.value().classification.semantic),
                static_cast<int>(aifc::SemanticClass::UNKNOWN));
  AIFC_CHECK_EQ(static_cast<int>(past_deadline.value().classification.state),
                static_cast<int>(aifc::ClassificationState::STALE));
  AIFC_CHECK_EQ(past_deadline.value().classification.confidence.to_decimal(), std::string("0.0000"));

  bool saw_deadline_reason = false;
  for (const aifc::EvidenceCitation& citation : past_deadline.value().classification.citations) {
    if (citation.detail.find("freshness window expired") != std::string::npos) {
      saw_deadline_reason = true;
    }
  }
  AIFC_CHECK_MSG(saw_deadline_reason,
                 "the stale citation did not say the freshness window expired:\n" +
                     past_deadline.value().explanation);
}

AIFC_TEST("freshness: republishing in the same epoch restores a current classification") {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.default_freshness_window = 50;
  ManualRig rig(policy, 1);

  const aifc::PublisherId publisher = aifc::make_publisher_id("refresh-publisher");
  auto registration = rig.classifier.register_publisher(
      publisher, aifc::PublisherBootId{1}, aifc::EvidenceSource::DECLARED_AUTHENTICATED,
      aifc::SessionId("refresh-session"), "refresh publisher");
  AIFC_CHECK_OK(registration);
  const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(9002);
  auto flow = rig.classifier.register_flow(key, aifc::FlowGeneration{0}, envelope.session);
  AIFC_CHECK_OK(flow);

  aifc::EvidencePayload payload;
  payload.flow_key = key;
  payload.flow_generation = flow.value().record.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};
  payload.semantic = aifc::SemanticClass::SHUFFLE;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "refresh.topic";
  auto first_submission = rig.classifier.submit_evidence(envelope, payload);
  AIFC_CHECK_OK(first_submission);
  // Captured so the assertions below name the exact records rather than guessing at them.
  const aifc::EvidenceId superseded_id = first_submission.value().record.id;

  aifc::ClassificationQuery query;
  query.flow_key = key;

  rig.clock.set(1 + 51);
  auto stale = rig.classifier.classify(query);
  AIFC_CHECK_OK(stale);
  AIFC_CHECK_EQ(static_cast<int>(stale.value().classification.state),
                static_cast<int>(aifc::ClassificationState::STALE));

  // A new publication with a strictly larger generation is the only way back to current.  There is
  // no path that revives the old record.
  payload.evidence_generation = aifc::EvidenceGeneration{2};
  payload.metadata.reason = "periodic refresh";
  auto second_submission = rig.classifier.submit_evidence(envelope, payload);
  AIFC_CHECK_OK(second_submission);
  const aifc::EvidenceId replacement_id = second_submission.value().record.id;
  AIFC_CHECK_MSG(second_submission.value().superseded_previous,
                 "the second publication did not report superseding the first");
  AIFC_CHECK_EQ(second_submission.value().superseded_id.value(), superseded_id.value());

  auto refreshed = rig.classifier.classify(query);
  AIFC_CHECK_OK(refreshed);
  AIFC_CHECK_EQ(static_cast<int>(refreshed.value().classification.semantic),
                static_cast<int>(aifc::SemanticClass::SHUFFLE));
  AIFC_CHECK_EQ(static_cast<int>(refreshed.value().classification.state),
                static_cast<int>(aifc::ClassificationState::CURRENT));

  // The replaced record is retained and reported, and the promise of a strictly newer generation is
  // recorded as a supersession.  Which citation state an operator sees depends on whether the
  // replacement was observed before or after the older record aged out, so the assertion is about
  // the guarantee rather than about one particular label: nothing may be silently dropped, and a
  // supersession must exist for the pair.
  bool older_record_still_cited = false;
  bool older_record_is_decisive = false;
  for (const aifc::EvidenceCitation& citation : refreshed.value().classification.citations) {
    if (citation.id == superseded_id) {
      older_record_still_cited = true;
      if (citation.disposition == aifc::EvidenceDisposition::SELECTED ||
          citation.disposition == aifc::EvidenceDisposition::CORROBORATING ||
          citation.disposition == aifc::EvidenceDisposition::CONTRADICTING) {
        older_record_is_decisive = true;
      }
    }
  }
  AIFC_CHECK_MSG(older_record_still_cited,
                 "the replaced record was dropped from the explanation entirely:\n" +
                     refreshed.value().explanation);
  AIFC_CHECK_MSG(!older_record_is_decisive,
                 "the replaced record still counted towards the classification:\n" +
                     refreshed.value().explanation);

  const std::vector<aifc::SupersessionRecord> supersessions = rig.classifier.supersessions();
  AIFC_CHECK_MSG(supersessions.size() == 1,
                 "expected exactly one supersession record, saw " +
                     std::to_string(supersessions.size()));
  if (supersessions.size() == 1) {
    AIFC_CHECK_EQ(supersessions.front().previous_id.value(), superseded_id.value());
    AIFC_CHECK_EQ(supersessions.front().replacement_id.value(), replacement_id.value());
    AIFC_CHECK_EQ(supersessions.front().previous_generation.value, std::uint64_t{1});
    AIFC_CHECK_EQ(supersessions.front().replacement_generation.value, std::uint64_t{2});
  }
}

AIFC_TEST("liveness: a publisher goes idle when the idle window elapses") {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.limits.max_session_idle_ticks = 100;
  policy.default_freshness_window = 1000000;  // isolate liveness from freshness
  ManualRig rig(policy, 10);

  const aifc::PublisherId publisher = aifc::make_publisher_id("idle-publisher");
  auto registration = rig.classifier.register_publisher(
      publisher, aifc::PublisherBootId{1}, aifc::EvidenceSource::DECLARED_AUTHENTICATED,
      aifc::SessionId("idle-session"), "idle publisher");
  AIFC_CHECK_OK(registration);
  const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(9003);
  auto flow = rig.classifier.register_flow(key, aifc::FlowGeneration{0}, envelope.session);
  AIFC_CHECK_OK(flow);

  aifc::EvidencePayload payload;
  payload.flow_key = key;
  payload.flow_generation = flow.value().record.generation;
  payload.evidence_generation = aifc::EvidenceGeneration{1};
  payload.semantic = aifc::SemanticClass::TELEMETRY;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.metadata.topic = "idle.topic";
  AIFC_CHECK_OK(rig.classifier.submit_evidence(envelope, payload));

  aifc::ClassificationQuery query;
  query.flow_key = key;
  auto current = rig.classifier.classify(query);
  AIFC_CHECK_OK(current);
  AIFC_CHECK_EQ(static_cast<int>(current.value().classification.state),
                static_cast<int>(aifc::ClassificationState::CURRENT));

  // Past the idle window with no further contact: liveness expires and the evidence stops being
  // current.  Liveness is never inferred from silence in the other direction either.
  rig.clock.set(10 + 101);
  const std::uint32_t expired = rig.classifier.expire_publisher_liveness();
  AIFC_CHECK_MSG(expired == 1, "expected exactly one publisher to be expired, got " +
                                   std::to_string(expired));

  auto idle = rig.classifier.classify(query);
  AIFC_CHECK_OK(idle);
  AIFC_CHECK_EQ(static_cast<int>(idle.value().classification.state),
                static_cast<int>(aifc::ClassificationState::STALE));

  auto registration_after = rig.classifier.find_publisher(publisher);
  AIFC_CHECK_OK(registration_after);
  AIFC_CHECK(registration_after.value().state != aifc::PublisherState::LIVE);

  // Contact brings the session back to live, but the record that expired stays expired: restoring
  // liveness does not restore the freshness window that already elapsed.
  AIFC_CHECK_OK(rig.classifier.heartbeat(publisher, aifc::PublisherBootId{1}));
  auto after_heartbeat = rig.classifier.find_publisher(publisher);
  AIFC_CHECK_OK(after_heartbeat);
  AIFC_CHECK_EQ(static_cast<int>(after_heartbeat.value().state),
                static_cast<int>(aifc::PublisherState::LIVE));
  auto still_stale = rig.classifier.classify(query);
  AIFC_CHECK_OK(still_stale);
  AIFC_CHECK_EQ(static_cast<int>(still_stale.value().classification.state),
                static_cast<int>(aifc::ClassificationState::STALE));
}

AIFC_TEST("ticks: the same evidence at the same tick produces the same decision digest") {
  // The digest excludes the tick, and this case proves that the exclusion is deliberate rather than
  // accidental: two different ticks with identical evidence must agree, and a change of tick must
  // not be able to make one decision look like a different one.
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.default_freshness_window = 100000;
  ManualRig first(policy, 1);
  ManualRig second(policy, 50000);

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(9004);
  aifc::FlowId flow_id;

  for (ManualRig* rig : {&first, &second}) {
    const aifc::PublisherId publisher = aifc::make_publisher_id("digest-publisher");
    auto registration = rig->classifier.register_publisher(
        publisher, aifc::PublisherBootId{1}, aifc::EvidenceSource::DECLARED_AUTHENTICATED,
        aifc::SessionId("digest-session"), "digest publisher");
    AIFC_CHECK_OK(registration);
    const aifc::SessionEnvelope envelope = aifc::make_session_envelope(registration.value(), 0);
    auto flow = rig->classifier.register_flow(key, aifc::FlowGeneration{0}, envelope.session);
    AIFC_CHECK_OK(flow);
    flow_id = flow.value().record.id;
    aifc::EvidencePayload payload;
    payload.flow_key = key;
    payload.flow_generation = flow.value().record.generation;
    payload.evidence_generation = aifc::EvidenceGeneration{1};
    payload.semantic = aifc::SemanticClass::MODEL_STATE_TRANSFER;
    payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.topic = "digest.topic";
    AIFC_CHECK_OK(rig->classifier.submit_evidence(envelope, payload));
  }

  aifc::ClassificationQuery query;
  query.flow_key = key;
  auto left = first.classifier.classify(query);
  auto right = second.classifier.classify(query);
  AIFC_CHECK_OK(left);
  AIFC_CHECK_OK(right);
  AIFC_CHECK_EQ(left.value().classification.flow_id.to_hex(), flow_id.to_hex());
  AIFC_CHECK_EQ(left.value().classification.digest.to_hex(),
                right.value().classification.digest.to_hex());
  AIFC_CHECK(left.value().classification == right.value().classification);
}
