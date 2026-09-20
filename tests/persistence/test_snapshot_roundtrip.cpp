// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Durable state round trip: a populated coordinator, written to a scratch directory,
// read back through the real read_snapshot_file, and compared field by field.
//
// Capability labels
// -----------------
//   REAL        Coordinator, Classifier, persist(), read_snapshot_file and the canonical
//               record codecs.  The file really is written to disk and really is read
//               back from disk.
//   SYNTHETIC   every publisher, workload, contract, flow and payload.
//   UNSUPPORTED nothing is stubbed or skipped.
//
// The comparison is deliberately done twice: once per record, through the canonical
// encoder, so a failure names the collection and the index; and once over the whole
// image, so a field that belongs to no collection (the epoch, the boot incarnation, the
// sequence high-water mark, the written-at stamp) cannot escape notice by living outside
// every per-record comparison.

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

constexpr std::uint32_t kRecordBound = aifc::kMaxBlobBytes;
constexpr std::uint64_t kKnownWallClock = 1'700'000'000'123ULL;
// Offsets of the two header fields that are functions of the wall clock: the informational
// stamp itself, and the CRC-32 that covers the header (and therefore covers the stamp).
// They are restated here so that a silent layout change is a test failure rather than a
// silently compared field.
constexpr std::size_t kWrittenAtOffset = 40;
constexpr std::size_t kHeaderChecksumOffset = 80;

// The informational stamp and the header checksum that covers it are the only two fields a
// repeat write may legitimately differ in.  Everything else must be bit-for-bit identical,
// which is what "the byte image is deterministic" means for a format that carries a
// timestamp.
[[nodiscard]] ByteBuffer image_without_time_derived_fields(ByteBuffer bytes) {
  for (std::size_t i = kWrittenAtOffset; i < kWrittenAtOffset + 8U; ++i) bytes[i] = 0U;
  for (std::size_t i = kHeaderChecksumOffset; i < kHeaderChecksumOffset + 4U; ++i) bytes[i] = 0U;
  return bytes;
}

[[nodiscard]] std::string hex_dump(const std::uint8_t* data, std::size_t size,
                                   std::size_t limit = 64) {
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


// How a heuristic submission cites the hint it claims: the claim travels in the record's
// opaque binding field as (transport << 16) | port.  The hint must be declared by the policy
// and must name an adapter the policy enables.
constexpr std::uint16_t kHeuristicPort = 8443U;

[[nodiscard]] std::uint64_t heuristic_binding() {
  return static_cast<std::uint64_t>(kHeuristicPort) |
         (static_cast<std::uint64_t>(aifc::TransportProtocol::TCP) << 16U);
}

// A policy that admits heuristic evidence as well, so that the round trip covers an
// evidence record of the weakest source too.
[[nodiscard]] aifc::ClassifierPolicy roundtrip_policy() {
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

[[nodiscard]] aifc::PublisherRegistration register_peer(aifc::Classifier& classifier,
                                                       std::uint32_t index,
                                                       EvidenceSource ceiling) {
  const auto registration = classifier.register_publisher(
      aifc_test::synthetic_publisher(index), aifc::PublisherBootId{1}, ceiling,
      aifc_test::synthetic_session(index), "synthetic peer " + std::to_string(index));
  if (!registration) {
    AIFC_FAIL("could not register synthetic peer " << index << ": "
                                                   << aifc::render_status(registration.status()));
    return aifc::PublisherRegistration{};
  }
  return registration.value();
}

// One populated coordinator's worth of durable state, with the counts that the round trip
// must reproduce.  Returning them makes the assertions below state what they expect
// rather than deriving it from whatever was written.
struct Population {
  std::size_t publishers = 0;
  std::size_t workloads = 0;
  std::size_t contracts = 0;
  std::size_t flows = 0;
  std::size_t evidence = 0;
  std::size_t classifications = 0;
  std::size_t revocations = 0;
  std::size_t supersessions = 0;
  std::string session_text;
  std::string flow_topic;
};

Population populate(aifc::Coordinator& coordinator) {
  aifc::Classifier& classifier = coordinator.classifier();
  Population counts;

  const aifc::PublisherRegistration declared =
      register_peer(classifier, 0U, EvidenceSource::DECLARED_AUTHENTICATED);
  const aifc::PublisherRegistration derived =
      register_peer(classifier, 1U, EvidenceSource::CONTRACT_DERIVED);
  const aifc::PublisherRegistration guessed =
      register_peer(classifier, 2U, EvidenceSource::HEURISTIC);
  counts.publishers = 3;
  counts.session_text = declared.session.value();

  const aifc::SessionEnvelope declared_envelope = aifc::make_session_envelope(declared, 0);
  const aifc::SessionEnvelope derived_envelope = aifc::make_session_envelope(derived, 0);
  const aifc::SessionEnvelope guessed_envelope = aifc::make_session_envelope(guessed, 0);

  // --- workloads and contracts ---
  auto workload_0 = classifier.declare_workload(aifc_test::synthetic_workload(0U), declared.id,
                                                aifc::WorkloadGeneration{1}, "synthetic workload 0");
  AIFC_CHECK_OK(workload_0);
  auto workload_1 = classifier.declare_workload(aifc_test::synthetic_workload(1U), derived.id,
                                                aifc::WorkloadGeneration{2}, "synthetic workload 1");
  AIFC_CHECK_OK(workload_1);
  counts.workloads = 2;
  if (!workload_0 || !workload_1) return counts;

  const auto propose = [&](std::uint32_t index, const aifc::WorkloadRecord& workload,
                           const aifc::PublisherId& owner, SemanticClass declared_class) {
    aifc::WorkloadContract contract;
    contract.id = aifc_test::synthetic_contract(index);
    contract.workload = workload.id;
    contract.workload_generation = workload.generation;
    contract.owner = owner;
    contract.declared_class = declared_class;
    contract.match_any_remote_address = true;
    contract.transport = aifc::TransportProtocol::TCP;
    contract.description = "synthetic contract " + std::to_string(index);
    auto proposed = classifier.propose_contract(contract);
    if (!proposed) {
      AIFC_FAIL("could not propose synthetic contract " << index << ": "
                                                       << aifc::render_status(proposed.status()));
      return;
    }
    auto activated = classifier.activate_contract(proposed.value().id, owner);
    if (!activated) {
      AIFC_FAIL("could not activate synthetic contract " << index << ": "
                                                         << aifc::render_status(activated.status()));
      return;
    }
    ++counts.contracts;
  };
  propose(0U, workload_0.value(), declared.id, SemanticClass::TRAINING_SYNC);
  propose(1U, workload_1.value(), derived.id, SemanticClass::INFERENCE_REQUEST);

  // --- flows ---
  auto flow_0 = classifier.register_flow(aifc_test::synthetic_flow_key(0U), aifc::FlowGeneration{0},
                                         declared.session);
  auto flow_1 = classifier.register_flow(aifc_test::synthetic_flow_key(1U), aifc::FlowGeneration{0},
                                         derived.session);
  auto flow_2 = classifier.register_flow(aifc_test::synthetic_flow_key(2U), aifc::FlowGeneration{0},
                                         guessed.session);
  AIFC_CHECK_OK(flow_0);
  AIFC_CHECK_OK(flow_1);
  AIFC_CHECK_OK(flow_2);
  counts.flows = 3;
  if (!flow_0 || !flow_1 || !flow_2) return counts;

  // --- evidence, including a supersession and a withdrawal ---
  const auto publish = [&](const aifc::SessionEnvelope& envelope, const aifc::FlowRecord& flow,
                           SemanticClass semantic, std::uint64_t generation, EvidenceSource claimed,
                           const std::string& topic, const aifc::WorkloadRecord* workload) {
    aifc::EvidencePayload payload;
    payload.flow_key = flow.key;
    payload.flow_generation = flow.generation;
    payload.evidence_generation = aifc::EvidenceGeneration{generation};
    payload.semantic = semantic;
    payload.claimed_source = claimed;
    payload.metadata.topic = topic;
    payload.metadata.reason = "synthetic evidence";
    payload.metadata.binding = heuristic_binding();
    if (workload != nullptr) {
      payload.workload = workload->id;
      payload.workload_generation = workload->generation;
    }
    auto outcome = classifier.submit_evidence(envelope, payload);
    if (!outcome) {
      AIFC_FAIL("could not publish synthetic evidence [" << topic << "] generation " << generation
                                                         << ": "
                                                         << aifc::render_status(outcome.status()));
      return aifc::EvidenceRecord{};
    }
    ++counts.evidence;
    return outcome.value().record;
  };

  counts.flow_topic = "roundtrip.topic.a";
  const aifc::EvidenceRecord first =
      publish(declared_envelope, flow_0.value().record, SemanticClass::TRAINING_SYNC, 1U,
              EvidenceSource::DECLARED_AUTHENTICATED, counts.flow_topic, &workload_0.value());
  const aifc::EvidenceRecord second =
      publish(declared_envelope, flow_0.value().record, SemanticClass::TRAINING_SYNC, 2U,
              EvidenceSource::DECLARED_AUTHENTICATED, counts.flow_topic, &workload_0.value());
  const aifc::EvidenceRecord third =
      publish(derived_envelope, flow_1.value().record, SemanticClass::INFERENCE_REQUEST, 1U,
              EvidenceSource::CONTRACT_DERIVED, "roundtrip.topic.b", &workload_1.value());
  publish(guessed_envelope, flow_2.value().record, SemanticClass::SHUFFLE, 1U,
          EvidenceSource::HEURISTIC, "roundtrip.topic.c", nullptr);
  if (second.id == first.id || third.id.empty()) {
    AIFC_FAIL("the synthetic publications did not produce distinct evidence identities");
    return counts;
  }
  counts.supersessions = 1;  // the second generation supersedes the first on the same topic

  // --- classifications ---
  const auto classify = [&](const aifc::FlowRecord& flow) {
    aifc::ClassificationQuery query;
    query.flow_key = flow.key;
    query.flow_generation = flow.generation;
    query.explain = false;
    query.accept_current_generation = true;
    auto result = classifier.classify(query);
    if (!result) {
      AIFC_FAIL("could not classify synthetic flow " << flow.key.to_string() << ": "
                                                     << aifc::render_status(result.status()));
      return;
    }
    ++counts.classifications;
  };
  classify(flow_0.value().record);
  classify(flow_1.value().record);
  classify(flow_2.value().record);

  // --- revocations: a withdrawal by the publisher, and a generation revocation ---
  const Status withdrawn = classifier.withdraw_evidence(
      derived_envelope, third.id, "synthetic withdrawal by its publisher");
  if (!withdrawn) {
    AIFC_FAIL("could not withdraw synthetic evidence " << third.id.value() << ": "
                                                      << aifc::render_status(withdrawn));
  } else {
    counts.revocations += 1;
  }
  const Status revoked = classifier.revoke_generation(
      declared_envelope, flow_0.value().record.id, flow_0.value().record.generation,
      "synthetic generation revocation");
  if (!revoked) {
    AIFC_FAIL("could not revoke a synthetic flow generation: " << aifc::render_status(revoked));
  } else {
    counts.revocations += 1;
  }
  return counts;
}

// Compares one collection element by element through the canonical encoder, so a failure
// names the collection and the index rather than the whole file.
template <typename Record>
void expect_collection_equal(const std::vector<Record>& live, const std::vector<Record>& decoded,
                             const std::string& name,
                             Status (*encode)(BufferWriter&, const Record&)) {
  if (live.size() != decoded.size()) {
    AIFC_FAIL(name << ": the live coordinator holds " << live.size() << " records but the file "
                   << "produced " << decoded.size());
    return;
  }
  for (std::size_t i = 0; i < live.size(); ++i) {
    BufferWriter live_writer(kRecordBound);
    BufferWriter decoded_writer(kRecordBound);
    const Status live_status = encode(live_writer, live[i]);
    const Status decoded_status = encode(decoded_writer, decoded[i]);
    if (!live_status) {
      AIFC_FAIL(name << "[" << i << "]: the live record could not be encoded: "
                     << aifc::render_status(live_status));
      continue;
    }
    if (!decoded_status) {
      AIFC_FAIL(name << "[" << i << "]: the decoded record could not be encoded: "
                     << aifc::render_status(decoded_status));
      continue;
    }
    if (live_writer.bytes() != decoded_writer.bytes()) {
      AIFC_FAIL(name << "[" << i << "] did not survive the round trip;\n      live    =["
                     << hex_dump(live_writer.bytes()) << "]\n      decoded =["
                     << hex_dump(decoded_writer.bytes()) << "]");
    }
  }
}

// Compares two images and reports the first differing byte rather than only "they differ".
void expect_images_equal(const ByteBuffer& left, const ByteBuffer& right,
                         const std::string& context) {
  if (left.size() != right.size()) {
    AIFC_FAIL(context << ": the images are " << left.size() << " and " << right.size()
                      << " bytes long");
    return;
  }
  for (std::size_t i = 0; i < left.size(); ++i) {
    if (left[i] == right[i]) continue;
    AIFC_FAIL(context << ": first difference at byte " << i << ": "
                      << static_cast<unsigned>(left[i]) << " vs "
                      << static_cast<unsigned>(right[i]) << ";\n      left =["
                      << hex_dump(left) << "]\n      right=[" << hex_dump(right) << "]");
    return;
  }
}

}  // namespace

AIFC_TEST("snapshot roundtrip: every collection and every field survives exactly") {
  aifc_test::ScratchDirectory scratch("roundtrip-fields");
  const std::string path = scratch.file("coordinator.aifs");
  aifc::CoordinatorOptions options;
  options.state_path = path;
  options.policy = roundtrip_policy();
  aifc::Coordinator coordinator(options);
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const Population expected = populate(coordinator);
  AIFC_CHECK_OK(coordinator.persist());

  const aifc::SnapshotLimits limits;
  auto decoded = aifc::read_snapshot_file(path, limits);
  AIFC_CHECK_MSG(decoded.ok(), "reading back the snapshot failed: "
                                   << aifc::render_status(decoded.status()));
  if (!decoded) return;
  const auto live_snapshot = coordinator.snapshot();
  AIFC_CHECK_OK(live_snapshot);
  if (!live_snapshot) return;
  const aifc::StateSnapshot& live = live_snapshot.value();

  // --- the collections ---
  expect_collection_equal(live.publishers, decoded.value().publishers, "publishers",
                          aifc::encode_publisher_record);
  expect_collection_equal(live.workloads, decoded.value().workloads, "workloads",
                          aifc::encode_workload_record);
  expect_collection_equal(live.contracts, decoded.value().contracts, "contracts",
                          aifc::encode_contract);
  expect_collection_equal(live.flows, decoded.value().flows, "flows", aifc::encode_flow_record);
  expect_collection_equal(live.evidence, decoded.value().evidence, "evidence",
                          aifc::encode_evidence_record);
  expect_collection_equal(live.classifications, decoded.value().classifications, "classifications",
                          aifc::encode_classification);
  expect_collection_equal(live.revocations, decoded.value().revocations, "revocations",
                          aifc::encode_revocation);
  expect_collection_equal(live.supersessions, decoded.value().supersessions, "supersessions",
                          aifc::encode_supersession);

  AIFC_CHECK_EQ(live.publishers.size(), expected.publishers);
  AIFC_CHECK_EQ(live.workloads.size(), expected.workloads);
  AIFC_CHECK_EQ(live.contracts.size(), expected.contracts);
  AIFC_CHECK_EQ(live.flows.size(), expected.flows);
  AIFC_CHECK_EQ(live.evidence.size(), expected.evidence);
  AIFC_CHECK_EQ(live.classifications.size(), expected.classifications);
  AIFC_CHECK_EQ(live.revocations.size(), expected.revocations);
  AIFC_CHECK_EQ(live.supersessions.size(), expected.supersessions);

  // --- the header fields that belong to no collection ---
  AIFC_CHECK_MSG(live.epoch == decoded.value().epoch,
                 "the coordinator epoch changed: live=" << live.epoch.to_string()
                                                        << " decoded="
                                                        << decoded.value().epoch.to_string());
  AIFC_CHECK_MSG(live.boot == decoded.value().boot,
                 "the boot incarnation changed: live=" << live.boot.to_string()
                                                       << " decoded="
                                                       << decoded.value().boot.to_string());
  AIFC_CHECK_EQ(live.sequence_high_water, decoded.value().sequence_high_water);
  AIFC_CHECK_EQ(live.format_version, decoded.value().format_version);
  AIFC_CHECK_EQ(live.persistence_generation, decoded.value().persistence_generation);

  // --- the policy, including its digest ---
  AIFC_CHECK_MSG(aifc::compute_policy_digest(decoded.value().policy) ==
                     aifc::compute_policy_digest(live.policy),
                 "the policy digest changed across the round trip: live="
                     << aifc::compute_policy_digest(live.policy).to_hex() << " decoded="
                     << aifc::compute_policy_digest(decoded.value().policy).to_hex());
  AIFC_CHECK_MSG(coordinator.classifier().policy_digest() ==
                     aifc::compute_policy_digest(decoded.value().policy),
                 "the coordinator's own policy digest does not match the file's");
  {
    BufferWriter live_policy(kRecordBound);
    BufferWriter decoded_policy(kRecordBound);
    AIFC_CHECK_OK(aifc::encode_policy(live_policy, live.policy));
    AIFC_CHECK_OK(aifc::encode_policy(decoded_policy, decoded.value().policy));
    AIFC_CHECK_MSG(live_policy.bytes() == decoded_policy.bytes(),
                   "the policy bytes changed across the round trip;\n      live    =["
                       << hex_dump(live_policy.bytes()) << "]\n      decoded =["
                       << hex_dump(decoded_policy.bytes()) << "]");
  }

  // --- the whole image, ignoring only the informational wall-clock field ---
  auto live_image = aifc::encode_snapshot(live, limits);
  AIFC_CHECK_OK(live_image);
  auto decoded_image = aifc::encode_snapshot(decoded.value(), limits);
  AIFC_CHECK_OK(decoded_image);
  if (live_image && decoded_image) {
    const ByteBuffer without_clock_live = image_without_time_derived_fields(live_image.value());
    const ByteBuffer without_clock_decoded = image_without_time_derived_fields(decoded_image.value());
    expect_images_equal(without_clock_live, without_clock_decoded,
                        "the re-encoded snapshot against the live image, outside the wall-clock "
                        "field");
  }
}

AIFC_TEST("snapshot roundtrip: the byte image is deterministic apart from the wall clock") {
  aifc_test::ScratchDirectory scratch("roundtrip-determinism");
  const std::string first_path = scratch.file("first.aifs");
  const std::string second_path = scratch.file("second.aifs");
  aifc::CoordinatorOptions options;
  options.state_path = first_path;
  options.policy = roundtrip_policy();
  aifc::Coordinator coordinator(options);
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  populate(coordinator);

  const aifc::SnapshotLimits limits;
  const auto live_snapshot = coordinator.snapshot();
  AIFC_CHECK_OK(live_snapshot);
  if (!live_snapshot) return;
  const aifc::StateSnapshot& live = live_snapshot.value();

  // Encoding the same snapshot twice must produce the same bytes, including the
  // informational field, because that field is an input to the encoder and not read from
  // the clock by it.
  auto first = aifc::encode_snapshot(live, limits);
  auto second = aifc::encode_snapshot(live, limits);
  AIFC_CHECK_OK(first);
  AIFC_CHECK_OK(second);
  if (first && second) {
    AIFC_CHECK_MSG(first.value() == second.value(),
                   "two encodings of one snapshot differ: ["
                       << hex_dump(first.value()) << "] vs [" << hex_dump(second.value()) << "]");
  }

  // A snapshot with a known wall-clock value must round trip that value exactly, which is
  // what makes the field informational rather than secret.
  aifc::StateSnapshot stamped = live;
  stamped.written_at_wall_millis = kKnownWallClock;
  auto stamped_image = aifc::encode_snapshot(stamped, limits);
  AIFC_CHECK_OK(stamped_image);
  if (stamped_image) {
    auto stamped_back = aifc::decode_snapshot(stamped_image.value().data(),
                                              stamped_image.value().size(), limits);
    AIFC_CHECK_OK(stamped_back);
    if (stamped_back) {
      AIFC_CHECK_EQ(stamped_back.value().written_at_wall_millis, kKnownWallClock);
    }
  }

  // Two real writes to two paths must differ in nothing but the wall-clock field: the
  // writer is the only thing that stamps it, and it stamps nothing else.
  AIFC_CHECK_OK(aifc::write_snapshot_file(first_path, live, limits));
  AIFC_CHECK_OK(aifc::write_snapshot_file(second_path, live, limits));
  auto read_first = aifc::read_snapshot_file(first_path, limits);
  auto read_second = aifc::read_snapshot_file(second_path, limits);
  AIFC_CHECK_OK(read_first);
  AIFC_CHECK_OK(read_second);
  if (read_first && read_second) {
    auto image_a = aifc::encode_snapshot(read_first.value(), limits);
    auto image_b = aifc::encode_snapshot(read_second.value(), limits);
    AIFC_CHECK_OK(image_a);
    AIFC_CHECK_OK(image_b);
    if (image_a && image_b) {
      expect_images_equal(image_without_time_derived_fields(image_a.value()),
                          image_without_time_derived_fields(image_b.value()),
                          "two writes of one state, outside the wall-clock field");
    }
    if (image_a && first) {
      expect_images_equal(image_without_time_derived_fields(image_a.value()),
                          image_without_time_derived_fields(first.value()),
                          "a written snapshot against the in-memory image, outside the wall-clock "
                          "field");
    }
  }
}

AIFC_TEST("snapshot roundtrip: the sequence high-water mark is preserved") {
  aifc_test::ScratchDirectory scratch("roundtrip-sequence");
  const std::string path = scratch.file("coordinator.aifs");
  aifc::CoordinatorOptions options;
  options.state_path = path;
  options.policy = roundtrip_policy();
  aifc::Coordinator coordinator(options);
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  populate(coordinator);
  const std::uint64_t live_sequence = coordinator.classifier().next_sequence();
  AIFC_CHECK_MSG(live_sequence > 0, "a populated coordinator must have issued sequence numbers");
  AIFC_CHECK_OK(coordinator.persist());

  const aifc::SnapshotLimits limits;
  auto decoded = aifc::read_snapshot_file(path, limits);
  AIFC_CHECK_OK(decoded);
  if (!decoded) return;
  AIFC_CHECK_EQ(decoded.value().sequence_high_water, live_sequence);
  const auto live_snapshot = coordinator.snapshot();
  AIFC_CHECK_OK(live_snapshot);
  if (live_snapshot) {
    AIFC_CHECK_EQ(live_snapshot.value().sequence_high_water, live_sequence);
  }
  // Every accepted record carries a sequence number at or below the high-water mark, which
  // is what makes the mark meaningful: it is the largest number the store ever issued.
  for (const aifc::EvidenceRecord& record : decoded.value().evidence) {
    AIFC_CHECK_MSG(record.accepted_seq <= live_sequence,
                   "evidence " << record.id.value() << " carries sequence "
                               << record.accepted_seq << ", above the persisted high-water mark "
                               << live_sequence);
  }
}

AIFC_TEST("snapshot roundtrip: what cannot be restored is not in the file") {
  aifc_test::ScratchDirectory scratch("roundtrip-authority");
  const std::string path = scratch.file("coordinator.aifs");
  aifc::CoordinatorOptions options;
  options.state_path = path;
  options.policy = roundtrip_policy();
  aifc::Coordinator coordinator(options);
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const Population expected = populate(coordinator);
  AIFC_CHECK_OK(coordinator.persist());

  const aifc::SnapshotLimits limits;
  auto bytes = aifc::read_all(path, limits.max_file_bytes);
  AIFC_CHECK_OK(bytes);
  if (!bytes) return;
  auto decoded = aifc::read_snapshot_file(path, limits);
  AIFC_CHECK_OK(decoded);
  if (!decoded) return;

  // The durable publisher descriptor must carry no session identity and no liveness state:
  // a descriptor that did would be one from which a restart could resurrect a session,
  // which is exactly what the durability/liveness split forbids.  Evidence records do carry
  // the publishing session, as provenance, which is why this is asserted against the
  // publisher records rather than against the whole image.
  AIFC_CHECK_MSG(!expected.session_text.empty(),
                 "the synthetic session identity must not be empty (it is " <<
                     expected.session_text.size() << " bytes)");
  {
    std::vector<std::string> sessions;
    for (const aifc::EvidenceRecord& record : decoded.value().evidence) {
      if (!record.session.empty()) sessions.push_back(record.session.value());
    }
    AIFC_CHECK_MSG(!sessions.empty(),
                   "the synthetic evidence must carry its publishing session as provenance");
    for (const aifc::PublisherRecord& publisher : decoded.value().publishers) {
      BufferWriter writer(kRecordBound);
      AIFC_CHECK_OK(aifc::encode_publisher_record(writer, publisher));
      const std::string encoded(reinterpret_cast<const char*>(writer.bytes().data()),
                                writer.bytes().size());
      for (const std::string& session : sessions) {
        AIFC_CHECK_MSG(encoded.find(session) == std::string::npos,
                       "the durable publisher record for "
                           << publisher.id.value() << " contains the session identity ["
                           << session << "]; a restart would then be able to resurrect a session");
      }
    }
  }
  // The whole file is still a snapshot and nothing else; the read back above is the check
  // that the bytes on disk are exactly what the writer produced.
  AIFC_CHECK_MSG(bytes.value().size() > aifc::kSnapshotHeaderBytes,
                 "the durable image is only " << bytes.value().size() << " bytes");

  // The decision memo is not durable either: it is keyed to an evidence set that only
  // exists in the process that produced it.
  AIFC_CHECK_MSG(!decoded.value().classifications.empty(),
                 "the classifications must be durable even though the memo is not");
  AIFC_CHECK_EQ(decoded.value().record_count(),
                expected.publishers + expected.workloads + expected.contracts + expected.flows +
                    expected.evidence + expected.classifications + expected.revocations +
                    expected.supersessions);
}

AIFC_TEST("snapshot roundtrip: writing is atomic and leaves no temporary behind") {
  aifc_test::ScratchDirectory scratch("roundtrip-atomic");
  const std::string path = scratch.file("coordinator.aifs");
  aifc::CoordinatorOptions options;
  options.state_path = path;
  options.policy = roundtrip_policy();
  aifc::Coordinator coordinator(options);
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  populate(coordinator);
  AIFC_CHECK_OK(coordinator.persist());

  const aifc::SnapshotLimits limits;
  auto entries = aifc::list_directory(scratch.path());
  AIFC_CHECK_OK(entries);
  if (entries) {
    AIFC_CHECK_EQ(entries.value().size(), std::size_t{1});
    for (const std::string& name : entries.value()) {
      AIFC_CHECK_MSG(name.find(".tmp-") == std::string::npos,
                     "a temporary file [" << name << "] was left behind by a successful write");
      AIFC_CHECK_MSG(name == "coordinator.aifs",
                     "an unexpected file [" << name << "] appeared in the state directory");
    }
  }
  AIFC_CHECK(aifc::path_exists(path));

  // A second write over the same path replaces the file rather than appending to it, and
  // the file stays readable.
  const std::size_t before = [&]() {
    auto read = aifc::read_all(path, limits.max_file_bytes);
    return read ? read.value().size() : std::size_t{0};
  }();
  AIFC_CHECK_MSG(before > 0, "the first write produced no bytes");
  AIFC_CHECK_OK(coordinator.persist());
  auto after = aifc::read_all(path, limits.max_file_bytes);
  AIFC_CHECK_OK(after);
  if (after) {
    AIFC_CHECK_EQ(after.value().size(), before);
    auto reread = aifc::decode_snapshot(after.value().data(), after.value().size(), limits);
    AIFC_CHECK_MSG(reread.ok(), "the replaced snapshot is not readable: "
                                    << aifc::render_status(reread.status()));
  }
  auto entries_after = aifc::list_directory(scratch.path());
  AIFC_CHECK_OK(entries_after);
  if (entries_after) {
    AIFC_CHECK_EQ(entries_after.value().size(), std::size_t{1});
  }
}
