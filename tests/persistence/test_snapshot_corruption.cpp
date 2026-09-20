// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Durable state corruption: every way a snapshot file can be wrong, and the guarantee
// that a wrong file is never partially applied.
//
// Capability labels
// -----------------
//   REAL        write_snapshot_file, read_snapshot_file, decode_snapshot,
//               recover_orphan_temporaries and Coordinator::start, exercised on real files
//               in a scratch directory.
//   SYNTHETIC   the state image that is corrupted, and every record in it.
//   UNSUPPORTED nothing is stubbed or skipped.
//
// Two claims are made and they are different claims:
//
//   1. the refusal is specific -- each mutation is refused with the code that names what is
//      wrong, not with a generic failure;
//   2. the refusal is total -- the classifier that was going to be restored still holds
//      exactly the values it held before, and a coordinator asked to start on the file does
//      not start.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "ai_flow_classifier/foundation/text.hpp"
#include "synthetic.hpp"
#include "test_framework.hpp"

namespace {

using aifc::ByteBuffer;
using aifc::BufferWriter;
using aifc::ErrorCode;
using aifc::EvidenceSource;
using aifc::SemanticClass;
using aifc::Status;
// The port a synthetic heuristic submission cites, and the value that travels in the record's
// opaque binding field as (transport << 16) | port.  It must match a hint the policy declares.
constexpr std::uint16_t kHeuristicPort = 8443U;

constexpr std::uint32_t kRecordBound = aifc::kMaxBlobBytes;
constexpr std::uint64_t kKnownWallClock = 1'700'000'000'123ULL;

// Header field offsets, restated so that a silent layout change is a test failure.
constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kFormatOffset = 4;
constexpr std::size_t kGenerationOffset = 6;
constexpr std::size_t kBodyLengthOffset = 8;
constexpr std::size_t kEpochOffset = 16;
constexpr std::size_t kBodyDigestOffset = 48;
constexpr std::size_t kHeaderChecksumOffset = 80;

[[nodiscard]] std::string hex_dump(const std::uint8_t* data, std::size_t size,
                                   std::size_t limit = 48) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  const std::size_t shown = size < limit ? size : limit;
  for (std::size_t i = 0; i < shown; ++i) {
    if (i != 0) out.push_back(' ');
    out.push_back(kHex[(data[i] >> 4) & 0x0FU]);
    out.push_back(kHex[data[i] & 0x0FU]);
  }
  if (shown != size) {
    out += " ... (";
    out += std::to_string(size);
    out += " bytes total)";
  }
  return out;
}

[[nodiscard]] std::string hex_dump(const ByteBuffer& bytes) {
  return hex_dump(bytes.data(), bytes.size());
}

void patch_u16(ByteBuffer& bytes, std::size_t offset, std::uint16_t value) {
  aifc::store_u16_le(bytes.data() + offset, value);
}

void patch_u64(ByteBuffer& bytes, std::size_t offset, std::uint64_t value) {
  aifc::store_u64_le(bytes.data() + offset, value);
}

void flip_bit(ByteBuffer& bytes, std::size_t offset, std::size_t bit) {
  bytes[offset] = static_cast<std::uint8_t>(bytes[offset] ^ static_cast<std::uint8_t>(1U << bit));
}

// --- a small, deterministic, valid state image -----------------------------

[[nodiscard]] aifc::ClassifierPolicy image_policy() {
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

[[nodiscard]] aifc::StateSnapshot valid_snapshot() {
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(1U);
  const aifc::PublisherId publisher = aifc_test::synthetic_publisher(1U);
  const aifc::WorkloadId workload = aifc_test::synthetic_workload(1U);
  const aifc::ContractId contract = aifc_test::synthetic_contract(1U);
  const aifc::SessionId session = aifc_test::synthetic_session(1U);

  aifc::StateSnapshot snapshot;
  snapshot.epoch = aifc::CoordinatorEpoch{7};
  snapshot.boot = aifc::CoordinatorBootId{9};
  snapshot.sequence_high_water = 123;
  snapshot.written_at_wall_millis = kKnownWallClock;
  snapshot.policy = image_policy();

  aifc::PublisherRecord publisher_record;
  publisher_record.id = publisher;
  publisher_record.highest_boot = aifc::PublisherBootId{4};
  publisher_record.highest_generation = aifc::EvidenceGeneration{5};
  publisher_record.max_source = EvidenceSource::DECLARED_AUTHENTICATED;
  publisher_record.first_seen_tick = 11;
  publisher_record.last_seen_wall_millis = 22;
  publisher_record.total_evidence_accepted = 3;
  publisher_record.description = "synthetic publisher";
  snapshot.publishers.push_back(publisher_record);

  aifc::WorkloadRecord workload_record;
  workload_record.id = workload;
  workload_record.owner = publisher;
  workload_record.generation = aifc::WorkloadGeneration{2};
  workload_record.state = aifc::WorkloadState::ACTIVE;
  workload_record.active_contract = contract;
  workload_record.declared_tick = 1;
  workload_record.activated_tick = 2;
  workload_record.description = "synthetic workload";
  snapshot.workloads.push_back(workload_record);

  aifc::WorkloadContract contract_record;
  contract_record.id = contract;
  contract_record.workload = workload;
  contract_record.workload_generation = aifc::WorkloadGeneration{2};
  contract_record.owner = publisher;
  contract_record.state = aifc::ContractState::ACTIVE;
  contract_record.declared_class = SemanticClass::TRAINING_SYNC;
  contract_record.match_any_remote_address = true;
  contract_record.transport = aifc::TransportProtocol::TCP;
  contract_record.derived_source = EvidenceSource::CONTRACT_DERIVED;
  contract_record.created_tick = 3;
  contract_record.activated_tick = 4;
  contract_record.description = "synthetic contract";
  contract_record.definition_digest = aifc::compute_contract_digest(contract_record);
  snapshot.contracts.push_back(contract_record);

  aifc::FlowRecord flow_record;
  flow_record.key = key;
  flow_record.id = aifc::derive_flow_id(key);
  flow_record.generation = aifc::FlowGeneration{3};
  flow_record.registered_seq = 5;
  flow_record.registered_tick = 6;
  flow_record.last_activity_tick = 7;
  flow_record.registered_by = session;
  flow_record.renewals = 1;
  snapshot.flows.push_back(flow_record);

  aifc::EvidenceRecord evidence;
  evidence.id = aifc::make_evidence_id("ev-00000000000000000000000000000001");
  evidence.publisher = publisher;
  evidence.publisher_boot = aifc::PublisherBootId{4};
  evidence.session = session;
  evidence.accepted_epoch = aifc::CoordinatorEpoch{7};
  evidence.accepted_boot = aifc::CoordinatorBootId{9};
  evidence.workload = workload;
  evidence.workload_generation = aifc::WorkloadGeneration{2};
  evidence.contract = contract;
  evidence.flow_id = flow_record.id;
  evidence.flow_generation = flow_record.generation;
  evidence.generation = aifc::EvidenceGeneration{5};
  evidence.accepted_seq = 100;
  evidence.accepted_tick = 101;
  evidence.fresh_until = 5000;
  evidence.semantic = SemanticClass::TRAINING_SYNC;
  evidence.source = EvidenceSource::DECLARED_AUTHENTICATED;
  evidence.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  evidence.confidence = aifc::source_confidence(evidence.source);
  evidence.metadata.topic = "corruption.topic";
  evidence.metadata.binding = 77;
  evidence.metadata.reason = "synthetic evidence";
  evidence.metadata.contract = contract;
  evidence.content_digest = aifc::compute_evidence_digest(evidence);
  snapshot.evidence.push_back(evidence);

  aifc::Classification classification;
  classification.flow_id = flow_record.id;
  classification.flow_generation = flow_record.generation;
  classification.semantic = SemanticClass::TRAINING_SYNC;
  classification.state = aifc::ClassificationState::CURRENT;
  classification.confidence = aifc::Confidence::from_basis_points(9000);
  classification.selected_evidence = evidence.id;
  classification.selected_source = EvidenceSource::DECLARED_AUTHENTICATED;
  classification.corroboration_count = 0;
  classification.policy_generation = snapshot.policy.generation;
  classification.policy_digest = aifc::compute_policy_digest(snapshot.policy);
  classification.coordinator_epoch = snapshot.epoch;
  classification.coordinator_boot = snapshot.boot;
  classification.decided_tick = 102;
  classification.digest = aifc::compute_classification_digest(classification);
  snapshot.classifications.push_back(classification);

  aifc::RevocationRecord revocation;
  revocation.flow_id = flow_record.id;
  revocation.flow_generation = flow_record.generation;
  revocation.evidence_id = evidence.id;
  revocation.revoked_by_session = session;
  revocation.revoked_by_publisher = publisher;
  revocation.epoch = snapshot.epoch;
  revocation.seq = 110;
  revocation.revoked_tick = 111;
  revocation.reason = "synthetic revocation";
  snapshot.revocations.push_back(revocation);

  aifc::SupersessionRecord supersession;
  supersession.previous_id = aifc::make_evidence_id("ev-00000000000000000000000000000002");
  supersession.replacement_id = evidence.id;
  supersession.previous_generation = aifc::EvidenceGeneration{4};
  supersession.replacement_generation = evidence.generation;
  supersession.publisher = publisher;
  supersession.seq = 112;
  supersession.recorded_tick = 113;
  snapshot.supersessions.push_back(supersession);

  return snapshot;
}

// --- state of the classifier that was going to be restored ------------------

struct ClassifierState {
  std::size_t publishers = 0;
  std::size_t flows = 0;
  std::size_t evidence = 0;
  std::uint64_t sequence = 0;
  std::uint64_t epoch = 0;
  std::uint64_t boot = 0;
  std::size_t decisions = 0;
  aifc::Digest256 policy_digest;
  aifc::Digest256 decision_digest;
  std::string decision_class;
};

[[nodiscard]] ClassifierState capture(aifc::Classifier& classifier);

// The classifier that a restore was about to overwrite.  It is populated through the real
// API and its whole observable state is captured, so "the caller's state is untouched" is a
// comparison of every value rather than an assumption.
//
// A Classifier owns a mutex and is therefore neither copyable nor movable, so the victim is
// constructed in place and its members are filled by the constructor body.
struct Victim {
  Victim() : options(make_options()), classifier(options) { populate(); }

  [[nodiscard]] static aifc::ClassifierOptions make_options() {
    aifc::ClassifierOptions value;
    value.policy = image_policy();
    value.epoch = aifc::CoordinatorEpoch{4};
    value.coordinator_boot = aifc::CoordinatorBootId{5};
    return value;
  }

  void populate() {
    auto registration = classifier.register_publisher(
        aifc_test::synthetic_publisher(9U), aifc::PublisherBootId{1},
        EvidenceSource::DECLARED_AUTHENTICATED, aifc_test::synthetic_session(9U),
        "the classifier that was going to be restored");
    AIFC_CHECK_OK(registration);
    if (!registration) return;
    auto registered = classifier.register_flow(aifc_test::synthetic_flow_key(9U),
                                               aifc::FlowGeneration{0},
                                               registration.value().session);
    AIFC_CHECK_OK(registered);
    if (!registered) return;
    flow = registered.value().record;

    aifc::EvidencePayload payload;
    payload.flow_key = flow.key;
    payload.flow_generation = flow.generation;
    payload.evidence_generation = aifc::EvidenceGeneration{1};
    payload.semantic = SemanticClass::CHECKPOINT;
    payload.claimed_source = EvidenceSource::DECLARED_AUTHENTICATED;
    payload.metadata.topic = "victim.topic";
    AIFC_CHECK_OK(classifier.submit_evidence(aifc::make_session_envelope(registration.value(), 0),
                                             payload));

    aifc::ClassificationQuery query;
    query.flow_key = flow.key;
    query.flow_generation = flow.generation;
    query.accept_current_generation = true;
    auto decision = classifier.classify(query);
    AIFC_CHECK_OK(decision);
    state = capture(classifier);
  }

  aifc::ClassifierOptions options;
  aifc::Classifier classifier;
  aifc::FlowRecord flow;
  ClassifierState state;
};
ClassifierState capture(aifc::Classifier& classifier) {
  const aifc::Classifier::Stats stats = classifier.stats();
  ClassifierState state;
  state.publishers = stats.publishers.publishers;
  state.flows = stats.flows.size;
  state.evidence = stats.evidence.records;
  state.sequence = stats.next_sequence;
  state.epoch = stats.epoch.value;
  state.boot = stats.coordinator_boot.value;
  state.policy_digest = stats.policy_digest;
  const aifc::Classifier::DurableState durable = classifier.durable_state();
  if (!durable.classifications.empty()) {
    state.decisions = durable.classifications.size();
    state.decision_digest = durable.classifications.back().digest;
    state.decision_class = std::string(aifc::to_string(durable.classifications.back().semantic));
  }
  return state;
}

void expect_state_unchanged(aifc::Classifier& classifier, const ClassifierState& before,
                            const std::string& context) {
  const ClassifierState now = capture(classifier);
  AIFC_CHECK_MSG(now.publishers == before.publishers,
                 context << ": the classifier holds " << now.publishers << " publishers, it held "
                         << before.publishers);
  AIFC_CHECK_MSG(now.flows == before.flows,
                 context << ": the classifier holds " << now.flows << " flows, it held "
                         << before.flows);
  AIFC_CHECK_MSG(now.evidence == before.evidence,
                 context << ": the classifier holds " << now.evidence << " evidence records, it "
                         << "held " << before.evidence);
  AIFC_CHECK_MSG(now.sequence == before.sequence,
                 context << ": the sequence counter moved from " << before.sequence << " to "
                         << now.sequence);
  AIFC_CHECK_MSG(now.epoch == before.epoch,
                 context << ": the epoch moved from " << before.epoch << " to " << now.epoch);
  AIFC_CHECK_MSG(now.boot == before.boot,
                 context << ": the boot incarnation moved from " << before.boot << " to "
                         << now.boot);
  AIFC_CHECK_MSG(now.policy_digest == before.policy_digest,
                 context << ": the policy digest changed from " << before.policy_digest.to_hex()
                         << " to " << now.policy_digest.to_hex());
  AIFC_CHECK_MSG(now.decisions == before.decisions,
                 context << ": the classification history changed size from " << before.decisions
                         << " to " << now.decisions);
  AIFC_CHECK_MSG(now.decision_digest == before.decision_digest,
                 context << ": the recorded decision changed from " << before.decision_digest.to_hex()
                         << " to " << now.decision_digest.to_hex());
  AIFC_CHECK_MSG(now.decision_class == before.decision_class,
                 context << ": the recorded decision class changed from " << before.decision_class
                         << " to " << now.decision_class);
}

// --- the two refusal checks -------------------------------------------------

// The format level: decode the bytes directly.
void expect_decode_refused(const ByteBuffer& image, ErrorCode expected,
                           const aifc::SnapshotLimits& limits, const std::string& context) {
  auto decoded = aifc::decode_snapshot(image.data(), image.size(), limits);
  if (decoded) {
    AIFC_FAIL(context << ": the image was accepted as a snapshot of " << image.size()
                      << " bytes; image=[" << hex_dump(image) << "]");
    return;
  }
  if (decoded.code() != expected) {
    AIFC_FAIL(context << ": expected " << aifc::to_string(expected) << " but got "
                      << aifc::render_status(decoded.status()));
  }
}

// The file level, plus the caller's state, plus the real start path.
void expect_file_refused(const std::string& path, const ByteBuffer& image, ErrorCode expected,
                         Victim& victim, const ClassifierState& before,
                         std::string_view description) {
  const std::string context = "corrupted snapshot: " + std::string(description);
  const Status written = aifc::atomic_replace(path, image.data(), image.size());
  AIFC_CHECK_MSG(written.ok(), context << ": could not stage the corrupted image: "
                                       << aifc::render_status(written));

  const aifc::SnapshotLimits limits;
  auto read = aifc::read_snapshot_file(path, limits);
  if (read) {
    AIFC_FAIL(context << ": read_snapshot_file accepted the image (" << image.size()
                      << " bytes); image=[" << hex_dump(image) << "]");
    return;
  }
  if (read.code() != expected) {
    AIFC_FAIL(context << ": expected " << aifc::to_string(expected) << " from read_snapshot_file "
                      << "but got " << aifc::render_status(read.status()));
  }

  expect_state_unchanged(victim.classifier, before, context);

  // The real call site.  A coordinator asked to start on this file must refuse, must not
  // be running afterwards, and must not have restored anything.
  aifc::CoordinatorOptions options;
  options.state_path = path;
  options.policy = image_policy();
  aifc::Coordinator coordinator(options);
  const ClassifierState before_start = capture(coordinator.classifier());
  const Status started = coordinator.start(aifc::CoordinatorBootId{1});
  if (started.ok()) {
    AIFC_FAIL(context << ": Coordinator::start succeeded on a corrupted state file");
    return;
  }
  AIFC_CHECK_MSG(started.code == expected,
                 context << ": Coordinator::start refused with " << aifc::render_status(started)
                         << " rather than " << aifc::to_string(expected));
  AIFC_CHECK_MSG(!coordinator.running(), context << ": the coordinator is running after a refused "
                                                    "start");
  AIFC_CHECK_MSG(coordinator.stats().coordinator.restarts == 0,
                 context << ": the coordinator counted a restart (" << coordinator.stats().coordinator.restarts
                         << ") although the state file was refused");
  expect_state_unchanged(coordinator.classifier(), before_start, context + " (fresh coordinator)");
}

// The expected refusal for a single bit flipped in the header, derived from the documented
// reader order: magic, format version, persistence generation, body length, checksum.
[[nodiscard]] ErrorCode expected_header_flip_code(const ByteBuffer& image, std::size_t offset,
                                                  const aifc::SnapshotLimits& limits) {
  if (offset < kFormatOffset) return ErrorCode::CORRUPT_STATE;
  if (offset < kBodyLengthOffset) return ErrorCode::UNSUPPORTED_FORMAT_VERSION;
  if (offset < kEpochOffset) {
    const std::uint64_t body_length = aifc::load_u64_le(image.data() + kBodyLengthOffset);
    if (body_length > limits.max_file_bytes) return ErrorCode::CAPACITY_EXCEEDED;
    if (body_length > image.size() - aifc::kSnapshotHeaderBytes) return ErrorCode::TRUNCATED_STATE;
    return ErrorCode::INTEGRITY_FAILURE;
  }
  return ErrorCode::INTEGRITY_FAILURE;
}

}  // namespace

AIFC_TEST("snapshot corruption: the baseline image is valid before anything is mutated") {
  aifc_test::ScratchDirectory scratch("corruption-baseline");
  const aifc::SnapshotLimits limits;
  const aifc::StateSnapshot snapshot = valid_snapshot();
  auto image = aifc::encode_snapshot(snapshot, limits);
  AIFC_CHECK_OK(image);
  if (!image) return;
  AIFC_CHECK_EQ(image.value().size(), aifc::kSnapshotHeaderBytes + 0U +
                                          aifc::load_u64_le(image.value().data() + kBodyLengthOffset));

  // A valid image decodes and reports exactly the header fields it was built with.
  auto decoded = aifc::decode_snapshot(image.value().data(), image.value().size(), limits);
  AIFC_CHECK_OK(decoded);
  if (decoded) {
    AIFC_CHECK_MSG(decoded.value().epoch == snapshot.epoch, "the epoch did not survive");
    AIFC_CHECK_MSG(decoded.value().boot == snapshot.boot, "the boot incarnation did not survive");
    AIFC_CHECK_EQ(decoded.value().sequence_high_water, snapshot.sequence_high_water);
    AIFC_CHECK_EQ(decoded.value().written_at_wall_millis, kKnownWallClock);
    AIFC_CHECK_EQ(decoded.value().record_count(), snapshot.record_count());
  }

  // And it survives a real write and read, so every mutation below starts from a file that
  // demonstrably worked.
  const std::string path = scratch.file("baseline.aifs");
  AIFC_CHECK_OK(aifc::write_snapshot_file(path, snapshot, limits));
  auto read_back = aifc::read_snapshot_file(path, limits);
  AIFC_CHECK_MSG(read_back.ok(), "the baseline file is not readable: "
                                     << aifc::render_status(read_back.status()));
}

AIFC_TEST("snapshot corruption: every header mutation is refused with the code that names it") {
  aifc_test::ScratchDirectory scratch("corruption-header");
  const std::string path = scratch.file("coordinator.aifs");
  const aifc::SnapshotLimits limits;
  const ByteBuffer image = [&]() {
    auto encoded = aifc::encode_snapshot(valid_snapshot(), limits);
    return encoded ? encoded.value() : ByteBuffer{};
  }();
  AIFC_CHECK_MSG(image.size() > aifc::kSnapshotHeaderBytes,
                 "the baseline image is not usable: " << image.size() << " bytes");

  Victim victim;
  const ClassifierState before = victim.state;

  // A bad magic: the whole magic, byte by byte.
  for (std::size_t offset = 0; offset < 4U; ++offset) {
    ByteBuffer mutated = image;
    mutated[offset] = static_cast<std::uint8_t>(mutated[offset] ^ 0x5AU);
    expect_decode_refused(mutated, ErrorCode::CORRUPT_STATE, limits,
                          "magic byte " + std::to_string(offset) + " changed; image=[" +
                              hex_dump(mutated) + "]");
  }
  {
    ByteBuffer mutated = image;
    for (std::size_t offset = 0; offset < 4U; ++offset) mutated[offset] = 0U;
    expect_file_refused(path, mutated, ErrorCode::CORRUPT_STATE, victim, before,
                        "a snapshot whose magic was zeroed");
  }

  // An unsupported format version and an unsupported persistence generation.
  const std::uint16_t bad_versions[] = {0U, 2U, 0x00FFU, 0xFFFFU};
  for (const std::uint16_t version : bad_versions) {
    {
      ByteBuffer mutated = image;
      patch_u16(mutated, kFormatOffset, version);
      expect_file_refused(path, mutated, ErrorCode::UNSUPPORTED_FORMAT_VERSION, victim, before,
                          "format version " + std::to_string(version));
    }
    {
      ByteBuffer mutated = image;
      patch_u16(mutated, kGenerationOffset, version);
      expect_file_refused(path, mutated, ErrorCode::UNSUPPORTED_FORMAT_VERSION, victim, before,
                          "persistence generation " + std::to_string(version));
    }
  }

  // A body length past the file, and past the configured bound.
  const std::size_t body_length = image.size() - aifc::kSnapshotHeaderBytes;
  {
    ByteBuffer mutated = image;
    patch_u64(mutated, kBodyLengthOffset, static_cast<std::uint64_t>(body_length) + 1U);
    expect_file_refused(path, mutated, ErrorCode::TRUNCATED_STATE, victim, before,
                        "a body length one byte past the end of the file");
  }
  {
    ByteBuffer mutated = image;
    patch_u64(mutated, kBodyLengthOffset, 1ULL << 20);
    expect_file_refused(path, mutated, ErrorCode::TRUNCATED_STATE, victim, before,
                        "a declared body length of 1 MiB against a file of " +
                            std::to_string(image.size()) + " bytes");
  }
  {
    // The bound is checked before the file, so a length that is both past the bound and
    // past the file is reported as the bound.  A small bound makes that explicit.
    aifc::SnapshotLimits small;
    small.max_file_bytes = 2048U;
    auto small_image = aifc::encode_snapshot(valid_snapshot(), small);
    AIFC_CHECK_OK(small_image);
    if (small_image) {
      ByteBuffer mutated = small_image.value();
      patch_u64(mutated, kBodyLengthOffset, 2049ULL);
      auto decoded = aifc::decode_snapshot(mutated.data(), mutated.size(), small);
      if (decoded) {
        AIFC_FAIL("a body length past the configured bound was accepted");
      } else {
        AIFC_CHECK_MSG(decoded.code() == ErrorCode::CAPACITY_EXCEEDED,
                       "a body length past the bound was refused with "
                           << aifc::render_status(decoded.status())
                           << " rather than CAPACITY_EXCEEDED");
      }
      ByteBuffer huge = small_image.value();
      patch_u64(huge, kBodyLengthOffset, 0xFFFFFFFFFFFFFFFFULL);
      expect_decode_refused(huge, ErrorCode::CAPACITY_EXCEEDED, small,
                            "a body length of 0xFFFFFFFFFFFFFFFF against a bound of 2048");
      expect_file_refused(path, huge, ErrorCode::CAPACITY_EXCEEDED, victim, before,
                          "a body length of 0xFFFFFFFFFFFFFFFF");
    }
  }
  // A *plausible* body length is covered by the header checksum, so it is an integrity
  // failure rather than a silent reinterpretation of the body.
  {
    ByteBuffer mutated = image;
    patch_u64(mutated, kBodyLengthOffset, static_cast<std::uint64_t>(body_length) - 1U);
    expect_file_refused(path, mutated, ErrorCode::INTEGRITY_FAILURE, victim, before,
                        "a body length one byte short of the body that is present");
  }
  {
    ByteBuffer mutated = image;
    patch_u64(mutated, kBodyLengthOffset, 0U);
    expect_file_refused(path, mutated, ErrorCode::INTEGRITY_FAILURE, victim, before,
                        "a declared body length of zero");
  }

  // The exhaustive sweep: every single bit of the header, with the code the reader order
  // implies.  The file level is exercised separately above; this is the format level.
  for (std::size_t offset = 0; offset < aifc::kSnapshotHeaderBytes; ++offset) {
    for (std::size_t bit = 0; bit < 8U; ++bit) {
      ByteBuffer mutated = image;
      flip_bit(mutated, offset, bit);
      const ErrorCode expected = expected_header_flip_code(mutated, offset, limits);
      expect_decode_refused(mutated, expected, limits,
                            "header byte " + std::to_string(offset) + " bit " + std::to_string(bit) +
                                " flipped; image=[" + hex_dump(mutated) + "]");
    }
  }
  expect_state_unchanged(victim.classifier, before, "after the header sweep");
}

AIFC_TEST("snapshot corruption: a flipped byte in the body is INTEGRITY_FAILURE") {
  aifc_test::ScratchDirectory scratch("corruption-body");
  const std::string path = scratch.file("coordinator.aifs");
  const aifc::SnapshotLimits limits;
  auto encoded = aifc::encode_snapshot(valid_snapshot(), limits);
  AIFC_CHECK_OK(encoded);
  if (!encoded) return;
  const ByteBuffer image = encoded.value();
  const std::size_t body_length = image.size() - aifc::kSnapshotHeaderBytes;
  AIFC_CHECK_MSG(body_length > 64U, "the baseline body is only " << body_length << " bytes");

  Victim victim;
  const ClassifierState before = victim.state;

  // Named cases first, so the code is pinned by name.
  {
    ByteBuffer mutated = image;
    flip_bit(mutated, kBodyDigestOffset, 0U);
    expect_file_refused(path, mutated, ErrorCode::INTEGRITY_FAILURE, victim, before,
                        "a flipped bit in the body digest field");
  }
  {
    ByteBuffer mutated = image;
    flip_bit(mutated, kEpochOffset, 3U);
    expect_file_refused(path, mutated, ErrorCode::INTEGRITY_FAILURE, victim, before,
                        "a flipped bit in the header epoch field");
  }
  {
    ByteBuffer mutated = image;
    flip_bit(mutated, kHeaderChecksumOffset, 0U);
    expect_file_refused(path, mutated, ErrorCode::INTEGRITY_FAILURE, victim, before,
                        "a flipped bit in the header checksum field");
  }
  {
    ByteBuffer mutated = image;
    flip_bit(mutated, aifc::kSnapshotHeaderBytes, 0U);
    expect_file_refused(path, mutated, ErrorCode::INTEGRITY_FAILURE, victim, before,
                        "a flipped bit in the first body byte");
  }
  {
    ByteBuffer mutated = image;
    flip_bit(mutated, image.size() - 1U, 0U);
    expect_file_refused(path, mutated, ErrorCode::INTEGRITY_FAILURE, victim, before,
                        "a flipped bit in the last body byte");
  }

  // Every body byte, one bit each: the body digest must catch all of them, and the header
  // checksum is untouched by a body mutation, so this is exactly the body digest's job.
  for (std::size_t offset = aifc::kSnapshotHeaderBytes; offset < image.size(); ++offset) {
    ByteBuffer mutated = image;
    flip_bit(mutated, offset, 0U);
    expect_decode_refused(mutated, ErrorCode::INTEGRITY_FAILURE, limits,
                          "body byte " + std::to_string(offset - aifc::kSnapshotHeaderBytes) +
                              " bit 0 flipped");
  }
  // Every header checksum byte, which is the header's own tag.
  for (std::size_t offset = kHeaderChecksumOffset; offset < aifc::kSnapshotHeaderBytes; ++offset) {
    ByteBuffer mutated = image;
    flip_bit(mutated, offset, 0U);
    expect_decode_refused(mutated, ErrorCode::INTEGRITY_FAILURE, limits,
                          "header checksum byte " + std::to_string(offset) + " bit 0 flipped");
  }
  expect_state_unchanged(victim.classifier, before, "after the body sweep");
}

AIFC_TEST("snapshot corruption: truncation at every length is TRUNCATED_STATE") {
  aifc_test::ScratchDirectory scratch("corruption-truncation");
  const std::string path = scratch.file("coordinator.aifs");
  const aifc::SnapshotLimits limits;
  auto encoded = aifc::encode_snapshot(valid_snapshot(), limits);
  AIFC_CHECK_OK(encoded);
  if (!encoded) return;
  const ByteBuffer image = encoded.value();

  Victim victim;
  const ClassifierState before = victim.state;

  for (std::size_t length = 0; length < image.size(); ++length) {
    // The format level.
    expect_decode_refused(ByteBuffer(image.begin(), image.begin() + static_cast<std::ptrdiff_t>(length)),
                          ErrorCode::TRUNCATED_STATE, limits,
                          "the first " + std::to_string(length) + " of " +
                              std::to_string(image.size()) + " bytes");
  }

  // The file level, at the boundaries that matter: empty, one byte short of the header,
  // exactly the header, one byte short of the whole image, and a few interior points.
  const std::size_t lengths[] = {0U,
                                 1U,
                                 aifc::kSnapshotHeaderBytes - 1U,
                                 aifc::kSnapshotHeaderBytes,
                                 aifc::kSnapshotHeaderBytes + 1U,
                                 image.size() / 2U,
                                 image.size() - 1U};
  for (const std::size_t length : lengths) {
    const ByteBuffer truncated(image.begin(),
                               image.begin() + static_cast<std::ptrdiff_t>(length));
    expect_file_refused(path, truncated, ErrorCode::TRUNCATED_STATE, victim, before,
                        "a file truncated to " + std::to_string(length) + " of " +
                            std::to_string(image.size()) + " bytes");
  }
  expect_state_unchanged(victim.classifier, before, "after the truncation sweep");
}

AIFC_TEST("snapshot corruption: trailing bytes are TRAILING_GARBAGE") {
  aifc_test::ScratchDirectory scratch("corruption-trailing");
  const std::string path = scratch.file("coordinator.aifs");
  const aifc::SnapshotLimits limits;
  auto encoded = aifc::encode_snapshot(valid_snapshot(), limits);
  AIFC_CHECK_OK(encoded);
  if (!encoded) return;
  const ByteBuffer image = encoded.value();

  Victim victim;
  const ClassifierState before = victim.state;

  const std::uint8_t appended[] = {0x00U, 0x01U, 0xFFU};
  for (const std::uint8_t extra : appended) {
    ByteBuffer mutated = image;
    mutated.push_back(extra);
    expect_decode_refused(mutated, ErrorCode::TRAILING_GARBAGE, limits,
                          "one 0x" + hex_dump(&extra, 1U) + " byte appended to a valid image");
  }
  {
    // A whole second snapshot glued to the first: the most plausible way for a file to
    // acquire trailing bytes, and the one a decoder that trusted the header length alone
    // would silently accept.
    ByteBuffer mutated = image;
    mutated.insert(mutated.end(), image.begin(), image.end());
    expect_file_refused(path, mutated, ErrorCode::TRAILING_GARBAGE, victim, before,
                        "a second complete snapshot appended to the first");
  }
  {
    ByteBuffer mutated = image;
    mutated.insert(mutated.end(), 4096U, 0x5AU);
    expect_file_refused(path, mutated, ErrorCode::TRAILING_GARBAGE, victim, before,
                        "4096 bytes of padding appended to a valid image");
  }
  expect_state_unchanged(victim.classifier, before, "after the trailing-byte cases");

  // The valid image itself is still accepted, so the refusals above are about the surplus
  // and not about the baseline having been broken.
  expect_decode_refused(ByteBuffer(image.begin(), image.end() - 1), ErrorCode::TRUNCATED_STATE,
                        limits, "the baseline image with its last byte removed");
  auto decoded = aifc::decode_snapshot(image.data(), image.size(), limits);
  AIFC_CHECK_MSG(decoded.ok(), "the unmodified baseline image is no longer accepted: "
                                   << aifc::render_status(decoded.status()));
}

AIFC_TEST("snapshot corruption: recover_orphan_temporaries removes only .tmp- files") {
  aifc_test::ScratchDirectory scratch("corruption-orphans");
  const aifc::SnapshotLimits limits;
  const std::string state_path = scratch.file("coordinator.aifs");
  const std::string keeping = scratch.file("keep-me.txt");
  const std::string unrelated = scratch.file("other.aifs.tmp-notmine");
  const std::string orphan_a = scratch.file("coordinator.aifs.tmp-1700000000000-1");
  const std::string orphan_b = scratch.file("coordinator.aifs.tmp-1700000000001-2");

  AIFC_CHECK_OK(aifc::write_snapshot_file(state_path, valid_snapshot(), limits));
  for (const std::string& path : {keeping, unrelated, orphan_a, orphan_b}) {
    const ByteBuffer content(16U, 0x41U);
    AIFC_CHECK_MSG(aifc::atomic_replace(path, content.data(), content.size()).ok(),
                   "could not stage " << path);
  }
  AIFC_CHECK(aifc::path_exists(orphan_a));
  AIFC_CHECK(aifc::path_exists(orphan_b));

  // With no prefix, every temporary in the directory goes -- and nothing else does.
  auto removed = aifc::recover_orphan_temporaries(scratch.path(), "");
  AIFC_CHECK_OK(removed);
  if (removed) AIFC_CHECK_EQ(removed.value(), 3U);
  AIFC_CHECK_MSG(!aifc::path_exists(orphan_a), "an orphaned temporary survived the sweep");
  AIFC_CHECK_MSG(!aifc::path_exists(orphan_b), "an orphaned temporary survived the sweep");
  AIFC_CHECK_MSG(!aifc::path_exists(unrelated), "a .tmp- file unrelated to the state file was skipped");
  AIFC_CHECK_MSG(aifc::path_exists(keeping),
                 "recover_orphan_temporaries removed a file that is not a temporary");
  AIFC_CHECK_MSG(aifc::path_exists(state_path),
                 "recover_orphan_temporaries removed the state file itself");

  // The state file is still exactly the snapshot that was written: the sweep cannot have
  // damaged committed state.
  auto read_back = aifc::read_snapshot_file(state_path, limits);
  AIFC_CHECK_MSG(read_back.ok(), "the state file is no longer readable after the sweep: "
                                     << aifc::render_status(read_back.status()));
  if (read_back) {
    AIFC_CHECK_EQ(read_back.value().record_count(), valid_snapshot().record_count());
    AIFC_CHECK_MSG(read_back.value().epoch == valid_snapshot().epoch,
                   "the state file lost its epoch across the sweep");
  }

  // A second sweep finds nothing, which is what makes the sweep safe to run on every start.
  auto second = aifc::recover_orphan_temporaries(scratch.path(), "");
  AIFC_CHECK_OK(second);
  if (second) AIFC_CHECK_EQ(second.value(), 0U);

  // A prefix restricts the sweep to the state file it belongs to.
  const std::string other_orphan = scratch.file("other.aifs.tmp-1700000000002-3");
  const ByteBuffer content(8U, 0x42U);
  AIFC_CHECK_OK(aifc::atomic_replace(other_orphan, content.data(), content.size()));
  auto prefixed = aifc::recover_orphan_temporaries(scratch.path(), "coordinator.aifs");
  AIFC_CHECK_OK(prefixed);
  if (prefixed) AIFC_CHECK_EQ(prefixed.value(), 0U);
  AIFC_CHECK_MSG(aifc::path_exists(other_orphan),
                 "a temporary belonging to a different state file was removed");
  AIFC_CHECK_MSG(aifc::path_exists(state_path), "the state file was removed by a prefixed sweep");
}
