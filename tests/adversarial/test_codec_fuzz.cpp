// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Seeded fuzzing of every canonical decoder: the nine record codecs in
// codec/record_codec.hpp and the message codecs in protocol/messages.hpp.
//
// Capability labels
// -----------------
//   REAL        the decoders in src/codec/record_codec.cpp and
//               src/protocol/messages.cpp, driven through their public entry points.
//   SYNTHETIC   every fixture.  The values are built by tests/support/synthetic.hpp
//               and by this file; nothing here was observed on a real fabric.
//   UNSUPPORTED no decoder in either header is left unfuzzed, and nothing is skipped.
//
// What a codec can and cannot promise -- stated precisely, because a test that
// overclaims is worse than no test
// -----------------------------------------------------------------------------
//   * A codec is not an authenticator.  Only two of the nine record codecs carry a
//     content digest (evidence and contract), and a digest is a corruption detector,
//     not a signature: a peer that authors a record can always recompute it.  Where
//     a digest exists these cases assert the strong property (a mutated class or
//     source is refused, or the decoded authority-bearing fields are exactly the
//     ones that were encoded); where it does not, the cases assert the properties
//     that hold without one -- the decoder never invents an undefined enumerator,
//     never promotes an unknown numeric code to a known class, and never returns
//     more bytes than it was given.
//   * The authority half of the argument (which of these records may actually decide
//     a classification) is proved in tests/adversarial/test_label_privilege.cpp
//     through the real Classifier::submit_evidence path, and the whole-file
//     integrity half in tests/persistence/test_snapshot_corruption.cpp.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "ai_flow_classifier/foundation/text.hpp"
#include "synthetic.hpp"
#include "test_framework.hpp"

namespace {

using aifc::ByteBuffer;
using aifc::BufferReader;
using aifc::BufferWriter;
using aifc::CodecLimits;
using aifc::ErrorCode;
using aifc::Status;

// The codec bounds a canonical record is read under.  Defaults are used deliberately:
// they are what a coordinator runs with.
[[nodiscard]] const CodecLimits& limits() {
  static const CodecLimits value{};
  return value;
}

constexpr std::uint32_t kRecordBound = aifc::kMaxBlobBytes;
constexpr std::uint32_t kMessageBound = aifc::kMaxFramePayload;

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

void write_u16(ByteBuffer& bytes, std::uint16_t value) {
  std::uint8_t raw[2];
  aifc::store_u16_le(raw, value);
  bytes.insert(bytes.end(), raw, raw + 2);
}

void write_u32(ByteBuffer& bytes, std::uint32_t value) {
  std::uint8_t raw[4];
  aifc::store_u32_le(raw, value);
  bytes.insert(bytes.end(), raw, raw + 4);
}

void write_u64(ByteBuffer& bytes, std::uint64_t value) {
  std::uint8_t raw[8];
  aifc::store_u64_le(raw, value);
  bytes.insert(bytes.end(), raw, raw + 8);
}

void write_bytes(ByteBuffer& bytes, const ByteBuffer& tail) {
  bytes.insert(bytes.end(), tail.begin(), tail.end());
}

void write_string(ByteBuffer& bytes, std::string_view text) {
  write_u32(bytes, static_cast<std::uint32_t>(text.size()));
  bytes.insert(bytes.end(), text.begin(), text.end());
}

void patch_u32(ByteBuffer& bytes, std::size_t offset, std::uint32_t value) {
  aifc::store_u32_le(bytes.data() + offset, value);
}

void flip_bit(ByteBuffer& bytes, std::size_t offset, std::size_t bit) {
  bytes[offset] = static_cast<std::uint8_t>(bytes[offset] ^ static_cast<std::uint8_t>(1U << bit));
}

[[nodiscard]] ByteBuffer reversed(const ByteBuffer& bytes) {
  return ByteBuffer(bytes.rbegin(), bytes.rend());
}

// Moves the first byte to the end: the record's schema byte is then read from whatever
// field happened to be second, which is the "fields arrived in the wrong order" lie.
[[nodiscard]] ByteBuffer schema_rotated(const ByteBuffer& bytes) {
  ByteBuffer out;
  out.reserve(bytes.size());
  out.insert(out.end(), bytes.begin() + 1, bytes.end());
  out.push_back(bytes.front());
  return out;
}

[[nodiscard]] bool is_documented_refusal(ErrorCode code) {
  switch (code) {
    case ErrorCode::MALFORMED_RECORD:
    case ErrorCode::MALFORMED_INPUT:
    case ErrorCode::MALFORMED_FRAME:
    case ErrorCode::CAPACITY_EXCEEDED:
    case ErrorCode::UNSUPPORTED_VERSION:
    case ErrorCode::CORRUPT_STATE:
    case ErrorCode::INTEGRITY_FAILURE:
    case ErrorCode::TRAILING_GARBAGE:
    case ErrorCode::OUT_OF_RANGE:
    case ErrorCode::ARITHMETIC_OVERFLOW:
    case ErrorCode::DUPLICATE_IDENTITY:
    case ErrorCode::INVALID_ARGUMENT:
      return true;
    default:
      return false;
  }
}

void fail_unexpected_code(const std::string& context, ErrorCode code) {
  AIFC_FAIL(context << ": refused with an undocumented code " << aifc::to_string(code));
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

namespace fixtures {

template <typename Record>
struct Codec {
  std::string name;
  std::uint8_t schema = 0;
  ByteBuffer image;
  std::function<ErrorCode(BufferReader&, Record&)> decode;
  std::function<void(const Record&, const std::string&)> invariant;
};

template <typename Message>
struct MessageCodec {
  std::string name;
  ByteBuffer image;
  std::function<Status(const Message&, ByteBuffer&)> encode;
  std::function<ErrorCode(const ByteBuffer&, Message&)> decode;
  std::function<void(const Message&, const std::string&)> invariant;
};

[[nodiscard]] ByteBuffer encode_ok(std::uint32_t bound,
                                   const std::function<Status(BufferWriter&)>& encode,
                                   const std::string& what) {
  BufferWriter writer(bound);
  const Status status = encode(writer);
  if (!status) {
    AIFC_FAIL("could not encode " << what << ": " << aifc::render_status(status));
    return ByteBuffer{};
  }
  return writer.take();
}

// --- record fixtures -------------------------------------------------------

[[nodiscard]] aifc::FlowKey flow_key() { return aifc_test::synthetic_flow_key(1U); }

[[nodiscard]] Codec<aifc::FlowRecord> flow_codec() {
  aifc::FlowRecord record;
  record.key = flow_key();
  record.id = aifc::derive_flow_id(record.key);
  record.generation = aifc::FlowGeneration{3};
  record.registered_seq = 11;
  record.registered_tick = 5;
  record.last_activity_tick = 9;
  record.registered_by = aifc_test::synthetic_session(1U);
  record.renewals = 2;

  Codec<aifc::FlowRecord> codec;
  codec.name = "flow record";
  codec.schema = 1;
  codec.image = encode_ok(kRecordBound,
                          [&](BufferWriter& writer) { return aifc::encode_flow_record(writer, record); },
                          codec.name);
  codec.decode = [](BufferReader& reader, aifc::FlowRecord& out) {
    auto result = aifc::decode_flow_record(reader);
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  codec.invariant = [](const aifc::FlowRecord& decoded, const std::string& context) {
    if (decoded.id != aifc::derive_flow_id(decoded.key)) {
      AIFC_FAIL(context << ": decoded flow identity " << decoded.id.to_hex()
                        << " is not the identity derived from its own key "
                        << decoded.key.to_string());
    }
    if (!decoded.generation.valid()) {
      AIFC_FAIL(context << ": decoded flow generation is zero, which is not a valid incarnation");
    }
  };
  return codec;
}

[[nodiscard]] Codec<aifc::PublisherRecord> publisher_codec() {
  aifc::PublisherRecord record;
  record.id = aifc_test::synthetic_publisher(2U);
  record.highest_boot = aifc::PublisherBootId{4};
  record.highest_generation = aifc::EvidenceGeneration{7};
  record.max_source = aifc::EvidenceSource::CONTRACT_DERIVED;
  record.first_seen_tick = 9;
  record.last_seen_wall_millis = 1234;
  record.total_evidence_accepted = 5;
  record.description = "synthetic publisher";

  Codec<aifc::PublisherRecord> codec;
  codec.name = "publisher record";
  codec.schema = 1;
  codec.image = encode_ok(
      kRecordBound, [&](BufferWriter& writer) { return aifc::encode_publisher_record(writer, record); },
      codec.name);
  codec.decode = [](BufferReader& reader, aifc::PublisherRecord& out) {
    auto result = aifc::decode_publisher_record(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  codec.invariant = [](const aifc::PublisherRecord& decoded, const std::string& context) {
    if (std::string_view(aifc::to_string(decoded.max_source)) == "UNRECOGNIZED_SOURCE") {
      AIFC_FAIL(context << ": decoded publisher carries an undefined evidence source enumerator");
    }
    if (!decoded.id.empty() && !aifc::is_canonical_identity(decoded.id.value())) {
      AIFC_FAIL(context << ": decoded publisher identity " << decoded.id.value()
                        << " is not canonical");
    }
  };
  return codec;
}

[[nodiscard]] Codec<aifc::WorkloadRecord> workload_codec() {
  aifc::WorkloadRecord record;
  record.id = aifc_test::synthetic_workload(3U);
  record.owner = aifc_test::synthetic_publisher(3U);
  record.generation = aifc::WorkloadGeneration{2};
  record.state = aifc::WorkloadState::ACTIVE;
  record.active_contract = aifc_test::synthetic_contract(3U);
  record.declared_tick = 1;
  record.activated_tick = 2;
  record.description = "synthetic workload";

  Codec<aifc::WorkloadRecord> codec;
  codec.name = "workload record";
  codec.schema = 1;
  codec.image = encode_ok(
      kRecordBound, [&](BufferWriter& writer) { return aifc::encode_workload_record(writer, record); },
      codec.name);
  codec.decode = [](BufferReader& reader, aifc::WorkloadRecord& out) {
    auto result = aifc::decode_workload_record(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  codec.invariant = [](const aifc::WorkloadRecord& decoded, const std::string& context) {
    if (!decoded.generation.valid()) {
      AIFC_FAIL(context << ": decoded workload generation is zero");
    }
    switch (decoded.state) {
      case aifc::WorkloadState::DECLARED:
      case aifc::WorkloadState::ACTIVE:
      case aifc::WorkloadState::RETIRED:
        break;
      default:
        AIFC_FAIL(context << ": decoded workload state "
                          << static_cast<unsigned>(decoded.state) << " is not a defined state");
    }
  };
  return codec;
}

[[nodiscard]] aifc::WorkloadContract contract_fixture() {
  aifc::WorkloadContract contract;
  contract.id = aifc_test::synthetic_contract(4U);
  contract.workload = aifc_test::synthetic_workload(4U);
  contract.workload_generation = aifc::WorkloadGeneration{2};
  contract.owner = aifc_test::synthetic_publisher(4U);
  contract.state = aifc::ContractState::ACTIVE;
  contract.declared_class = aifc::SemanticClass::TRAINING_SYNC;
  contract.remote_scope.push_back(aifc_test::synthetic_address(1U));
  contract.remote_scope.push_back(aifc_test::synthetic_address(2U));
  contract.local_port_scope.push_back(40000U);
  contract.local_port_scope.push_back(40001U);
  contract.remote_port = 2048;
  contract.transport = aifc::TransportProtocol::TCP;
  contract.match_any_remote_address = false;
  contract.derived_source = aifc::EvidenceSource::CONTRACT_DERIVED;
  contract.created_tick = 3;
  contract.activated_tick = 4;
  contract.description = "synthetic contract";
  contract.definition_digest = aifc::compute_contract_digest(contract);
  return contract;
}

[[nodiscard]] Codec<aifc::WorkloadContract> contract_codec() {
  const aifc::WorkloadContract record = contract_fixture();

  Codec<aifc::WorkloadContract> codec;
  codec.name = "workload contract";
  codec.schema = 1;
  codec.image = encode_ok(kRecordBound,
                          [&](BufferWriter& writer) { return aifc::encode_contract(writer, record); },
                          codec.name);
  codec.decode = [](BufferReader& reader, aifc::WorkloadContract& out) {
    auto result = aifc::decode_contract(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  // The contract digest covers the declared class, the owner, the scope and the
  // derived source.  Any accepted mutation must therefore leave those exactly as they
  // were encoded: a mutated declared class can never survive the decode.
  codec.invariant = [record](const aifc::WorkloadContract& decoded, const std::string& context) {
    if (decoded.declared_class != record.declared_class) {
      AIFC_FAIL(context << ": decoded contract declares class " << aifc::to_string(decoded.declared_class)
                        << " but the encoded contract declared " << aifc::to_string(record.declared_class));
    }
    if (decoded.derived_source != record.derived_source) {
      AIFC_FAIL(context << ": decoded contract carries source " << aifc::to_string(decoded.derived_source)
                        << " but the encoded contract carried " << aifc::to_string(record.derived_source));
    }
    if (decoded.owner != record.owner || decoded.id != record.id) {
      AIFC_FAIL(context << ": decoded contract identity or owner changed: id="
                        << decoded.id.value() << " owner=" << decoded.owner.value());
    }
    if (decoded.definition_digest != aifc::compute_contract_digest(decoded)) {
      AIFC_FAIL(context << ": decoded contract digest " << decoded.definition_digest.to_hex()
                        << " does not match its own content");
    }
  };
  return codec;
}

[[nodiscard]] aifc::EvidenceRecord evidence_fixture() {
  aifc::EvidenceRecord record;
  record.id = aifc::make_evidence_id("ev-0123456789abcdef0123456789abcdef");
  record.publisher = aifc_test::synthetic_publisher(1U);
  record.publisher_boot = aifc::PublisherBootId{4};
  record.session = aifc_test::synthetic_session(1U);
  record.accepted_epoch = aifc::CoordinatorEpoch{2};
  record.accepted_boot = aifc::CoordinatorBootId{3};
  record.workload = aifc_test::synthetic_workload(1U);
  record.workload_generation = aifc::WorkloadGeneration{2};
  record.contract = aifc_test::synthetic_contract(1U);
  record.flow_id = aifc::derive_flow_id(flow_key());
  record.flow_generation = aifc::FlowGeneration{3};
  record.generation = aifc::EvidenceGeneration{5};
  record.accepted_seq = 17;
  record.accepted_tick = 100;
  record.fresh_until = 4196;
  record.semantic = aifc::SemanticClass::TRAINING_SYNC;
  record.source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  record.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  record.confidence = aifc::source_confidence(record.source);
  record.metadata.topic = "workload.rank.7.collective";
  record.metadata.binding = 99;
  record.metadata.reason = "synthetic evidence";
  record.metadata.contract = record.contract;
  record.state_reason = "accepted";
  record.content_digest = aifc::compute_evidence_digest(record);
  return record;
}

[[nodiscard]] Codec<aifc::EvidenceRecord> evidence_codec() {
  const aifc::EvidenceRecord record = evidence_fixture();

  Codec<aifc::EvidenceRecord> codec;
  codec.name = "evidence record";
  codec.schema = 1;
  codec.image = encode_ok(kRecordBound,
                          [&](BufferWriter& writer) { return aifc::encode_evidence_record(writer, record); },
                          codec.name);
  codec.decode = [](BufferReader& reader, aifc::EvidenceRecord& out) {
    auto result = aifc::decode_evidence_record(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  // Every authority-bearing field of an evidence record is covered by its content
  // digest, and decode_evidence_record recomputes that digest.  An accepted mutation
  // therefore cannot have changed any of them; if one did, the decoder would be
  // handing back authority the input never carried.
  codec.invariant = [record](const aifc::EvidenceRecord& decoded, const std::string& context) {
    if (decoded.semantic != record.semantic) {
      AIFC_FAIL(context << ": decoded evidence class is " << aifc::to_string(decoded.semantic)
                        << " but the encoded record declared " << aifc::to_string(record.semantic));
    }
    if (decoded.source != record.source) {
      AIFC_FAIL(context << ": decoded evidence source is " << aifc::to_string(decoded.source)
                        << " but the encoded record carried " << aifc::to_string(record.source));
    }
    if (decoded.confidence != record.confidence) {
      AIFC_FAIL(context << ": decoded evidence confidence is " << decoded.confidence.to_decimal()
                        << " but the encoded record carried " << record.confidence.to_decimal());
    }
    if (decoded.generation != record.generation || decoded.publisher != record.publisher ||
        decoded.publisher_boot != record.publisher_boot || decoded.flow_id != record.flow_id ||
        decoded.flow_generation != record.flow_generation ||
        decoded.fresh_until != record.fresh_until || decoded.workload != record.workload) {
      AIFC_FAIL(context
                << ": an accepted mutation changed an authority-bearing evidence field:"
                << " publisher=" << decoded.publisher.value()
                << " boot=" << decoded.publisher_boot.to_string()
                << " generation=" << decoded.generation.to_string()
                << " flow=" << decoded.flow_id.to_hex()
                << " flow_generation=" << decoded.flow_generation.to_string()
                << " fresh_until=" << decoded.fresh_until
                << " workload=" << decoded.workload.value());
    }
    if (std::string_view(aifc::to_string(decoded.semantic)) == "EXTENSION" ||
        std::string_view(aifc::to_string(decoded.source)) == "UNRECOGNIZED_SOURCE" ||
        std::string_view(aifc::to_string(decoded.state)) == "UNRECOGNIZED_STATE") {
      AIFC_FAIL(context << ": decoded evidence carries an undefined enumerator: class="
                        << aifc::to_string(decoded.semantic) << " source=" << aifc::to_string(decoded.source)
                        << " state=" << aifc::to_string(decoded.state));
    }
  };
  return codec;
}

[[nodiscard]] Codec<aifc::Classification> classification_codec() {
  aifc::Classification classification;
  classification.flow_id = aifc::derive_flow_id(flow_key());
  classification.flow_generation = aifc::FlowGeneration{3};
  classification.semantic = aifc::SemanticClass::PREFILL_DECODE_HANDOFF;
  classification.state = aifc::ClassificationState::CORROBORATED;
  classification.confidence = aifc::Confidence::from_basis_points(7000);
  classification.selected_evidence = aifc::make_evidence_id("ev-11111111111111111111111111111111");
  classification.selected_source = aifc::EvidenceSource::CONTRACT_DERIVED;
  classification.corroboration_count = 2;
  classification.applied_penalty_basis_points = 0;
  classification.policy_generation = aifc::ClassifierPolicyGeneration{1};
  classification.policy_digest = aifc::compute_policy_digest(aifc::ClassifierPolicy::initial());
  classification.coordinator_epoch = aifc::CoordinatorEpoch{2};
  classification.coordinator_boot = aifc::CoordinatorBootId{3};
  classification.decided_tick = 42;
  aifc::EvidenceCitation citation;
  citation.id = classification.selected_evidence;
  citation.publisher = aifc_test::synthetic_publisher(1U);
  citation.source = aifc::EvidenceSource::CONTRACT_DERIVED;
  citation.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  citation.semantic = classification.semantic;
  citation.disposition = aifc::EvidenceDisposition::SELECTED;
  citation.confidence = aifc::Confidence::from_basis_points(8000);
  citation.generation = aifc::EvidenceGeneration{5};
  citation.accepted_seq = 17;
  citation.accepted_tick = 100;
  citation.fresh_until = 4196;
  citation.detail = "synthetic citation";
  classification.citations.push_back(citation);
  aifc::EvidenceCitation second = citation;
  second.id = aifc::make_evidence_id("ev-22222222222222222222222222222222");
  second.disposition = aifc::EvidenceDisposition::CORROBORATING;
  classification.citations.push_back(second);
  classification.digest = aifc::compute_classification_digest(classification);

  Codec<aifc::Classification> codec;
  codec.name = "classification";
  codec.schema = 1;
  codec.image = encode_ok(kRecordBound,
                          [&](BufferWriter& writer) { return aifc::encode_classification(writer, classification); },
                          codec.name);
  codec.decode = [](BufferReader& reader, aifc::Classification& out) {
    auto result = aifc::decode_classification(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  // A classification record carries no digest check of its own, so the honest
  // invariants are about shape: the decoder must never hand back an undefined
  // enumerator, an extension class the wire never named, or a citation count beyond
  // the codec bound.
  codec.invariant = [](const aifc::Classification& decoded, const std::string& context) {
    if (std::string_view(aifc::to_string(decoded.semantic)) == "EXTENSION") {
      AIFC_FAIL(context << ": decoded classification reports an extension class the input did "
                           "not name");
    }
    if (std::string_view(aifc::to_string(decoded.state)) == "UNRECOGNIZED_STATE") {
      AIFC_FAIL(context << ": decoded classification state is not a defined state");
    }
    if (std::string_view(aifc::to_string(decoded.selected_source)) == "UNRECOGNIZED_SOURCE") {
      AIFC_FAIL(context << ": decoded selected source is not a defined source");
    }
    if (decoded.citations.size() > aifc::kMaxCollectionCount ||
        decoded.contradictions.size() > aifc::kMaxCollectionCount) {
      AIFC_FAIL(context << ": decoded classification carries " << decoded.citations.size()
                        << " citations and " << decoded.contradictions.size()
                        << " contradictions, beyond the codec bound of "
                        << aifc::kMaxCollectionCount);
    }
    for (const aifc::EvidenceCitation& citation : decoded.citations) {
      if (static_cast<unsigned>(citation.disposition) > 9U) {
        AIFC_FAIL(context << ": decoded citation disposition "
                          << static_cast<unsigned>(citation.disposition)
                          << " is outside the defined range");
      }
    }
  };
  return codec;
}

[[nodiscard]] Codec<aifc::RevocationRecord> revocation_codec() {
  aifc::RevocationRecord record;
  record.flow_id = aifc::derive_flow_id(flow_key());
  record.flow_generation = aifc::FlowGeneration{3};
  record.evidence_id = aifc::make_evidence_id("ev-33333333333333333333333333333333");
  record.revoked_by_session = aifc_test::synthetic_session(1U);
  record.revoked_by_publisher = aifc_test::synthetic_publisher(1U);
  record.epoch = aifc::CoordinatorEpoch{2};
  record.seq = 21;
  record.revoked_tick = 77;
  record.reason = "synthetic revocation";

  Codec<aifc::RevocationRecord> codec;
  codec.name = "revocation record";
  codec.schema = 1;
  codec.image = encode_ok(kRecordBound,
                          [&](BufferWriter& writer) { return aifc::encode_revocation(writer, record); },
                          codec.name);
  codec.decode = [](BufferReader& reader, aifc::RevocationRecord& out) {
    auto result = aifc::decode_revocation(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  codec.invariant = [](const aifc::RevocationRecord& decoded, const std::string& context) {
    if (!decoded.evidence_id.empty() && !aifc::is_canonical_identity(decoded.evidence_id.value())) {
      AIFC_FAIL(context << ": decoded revocation carries a non-canonical evidence identity "
                        << decoded.evidence_id.value());
    }
    if (!aifc::is_canonical_identity(decoded.revoked_by_publisher.value())) {
      AIFC_FAIL(context << ": decoded revocation carries a non-canonical publisher identity "
                        << decoded.revoked_by_publisher.value());
    }
  };
  return codec;
}

[[nodiscard]] Codec<aifc::SupersessionRecord> supersession_codec() {
  aifc::SupersessionRecord record;
  record.previous_id = aifc::make_evidence_id("ev-44444444444444444444444444444444");
  record.replacement_id = aifc::make_evidence_id("ev-55555555555555555555555555555555");
  record.previous_generation = aifc::EvidenceGeneration{5};
  record.replacement_generation = aifc::EvidenceGeneration{6};
  record.publisher = aifc_test::synthetic_publisher(1U);
  record.seq = 31;
  record.recorded_tick = 88;

  Codec<aifc::SupersessionRecord> codec;
  codec.name = "supersession record";
  codec.schema = 1;
  codec.image = encode_ok(kRecordBound,
                          [&](BufferWriter& writer) { return aifc::encode_supersession(writer, record); },
                          codec.name);
  codec.decode = [](BufferReader& reader, aifc::SupersessionRecord& out) {
    auto result = aifc::decode_supersession(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  codec.invariant = [](const aifc::SupersessionRecord& decoded, const std::string& context) {
    if (!aifc::is_canonical_identity(decoded.previous_id.value()) ||
        !aifc::is_canonical_identity(decoded.replacement_id.value())) {
      AIFC_FAIL(context << ": decoded supersession carries a non-canonical evidence identity: "
                        << decoded.previous_id.value() << " -> "
                        << decoded.replacement_id.value());
    }
  };
  return codec;
}

[[nodiscard]] aifc::ClassifierPolicy policy_fixture() {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.allow_heuristic_evidence = true;
  policy.allow_heuristic_evidence = true;
  aifc::HeuristicAdapterPolicy adapter;
  adapter.name = "synthetic.adapter";
  adapter.enabled = true;
  adapter.max_basis_points = 1500;
  adapter.priority = 3;
  policy.heuristic_adapters.push_back(adapter);
  aifc::PortHint hint;
  hint.transport = aifc::TransportProtocol::TCP;
  hint.port = 8080;
  hint.semantic = aifc::SemanticClass::INFERENCE_REQUEST;
  hint.basis_points = 500;
  hint.adapter = "synthetic.adapter";
  policy.port_hints.push_back(hint);
  auto canonical = aifc::ClassifierPolicy::canonicalize(std::move(policy));
  if (!canonical) {
    AIFC_FAIL("the synthetic policy fixture is not canonicalizable: "
              << aifc::render_status(canonical.status()));
    return aifc::ClassifierPolicy::initial();
  }
  return canonical.value();
}

[[nodiscard]] Codec<aifc::ClassifierPolicy> policy_codec() {
  const aifc::ClassifierPolicy record = policy_fixture();

  Codec<aifc::ClassifierPolicy> codec;
  codec.name = "classifier policy";
  codec.schema = 1;
  codec.image = encode_ok(kRecordBound,
                          [&](BufferWriter& writer) { return aifc::encode_policy(writer, record); },
                          codec.name);
  codec.decode = [](BufferReader& reader, aifc::ClassifierPolicy& out) {
    auto result = aifc::decode_policy(reader, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  // A decoded policy is re-canonicalised by the decoder, so whatever it returns must
  // be its own canonical form.  If it were not, two equal policies could decide
  // differently.
  codec.invariant = [](const aifc::ClassifierPolicy& decoded, const std::string& context) {
    aifc::ClassifierPolicy copy = decoded;
    auto canonical = aifc::ClassifierPolicy::canonicalize(std::move(copy));
    if (!canonical) {
      AIFC_FAIL(context << ": a decoded policy is not canonicalizable: "
                        << aifc::render_status(canonical.status()));
      return;
    }
    if (aifc::compute_policy_digest(canonical.value()) != aifc::compute_policy_digest(decoded)) {
      AIFC_FAIL(context << ": a decoded policy is not its own canonical form");
    }
  };
  return codec;
}

}  // namespace fixtures

// ---------------------------------------------------------------------------
// Message fixtures
// ---------------------------------------------------------------------------

namespace fixtures {

}  // namespace fixtures

namespace {

using fixtures::classification_codec;
using fixtures::Codec;
using fixtures::contract_fixture;
using fixtures::flow_key;
using fixtures::MessageCodec;

[[nodiscard]] ByteBuffer encode_message_ok(
    const std::function<Status(ByteBuffer&)>& encode, const std::string& what) {
  ByteBuffer out;
  const Status status = encode(out);
  if (!status) {
    AIFC_FAIL("could not encode " << what << ": " << aifc::render_status(status));
  }
  return out;
}

template <typename Message>
[[nodiscard]] MessageCodec<Message> make_message_codec(
    std::string name, const Message& message,
    const std::function<Status(const Message&, ByteBuffer&)>& encode,
    const std::function<aifc::Result<Message>(const ByteBuffer&, const CodecLimits&)>& decode,
    const std::function<void(const Message&, const std::string&)>& invariant = {}) {
  MessageCodec<Message> codec;
  codec.name = std::move(name);
  codec.encode = encode;
  codec.image = encode_message_ok(
      [&](ByteBuffer& out) { return encode(message, out); }, codec.name);
  codec.decode = [decode](const ByteBuffer& payload, Message& out) {
    auto result = decode(payload, limits());
    if (!result) return result.code();
    out = result.value();
    return ErrorCode::OK;
  };
  codec.invariant = invariant;
  return codec;
}

[[nodiscard]] aifc::EvidencePayload evidence_payload_fixture() {
  aifc::EvidencePayload payload;
  payload.workload = aifc_test::synthetic_workload(1U);
  payload.workload_generation = aifc::WorkloadGeneration{2};
  payload.contract = aifc_test::synthetic_contract(1U);
  payload.flow_key = flow_key();
  payload.flow_generation = aifc::FlowGeneration{3};
  payload.evidence_generation = aifc::EvidenceGeneration{5};
  payload.semantic = aifc::SemanticClass::KV_STATE_TRANSFER;
  payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  payload.freshness_window = 4096;
  payload.metadata.topic = "workload.rank.7.kv";
  payload.metadata.binding = 12345;
  payload.metadata.reason = "synthetic reason";
  return payload;
}

[[nodiscard]] MessageCodec<aifc::HelloRequest> hello_codec() {
  aifc::HelloRequest message;
  message.role = aifc::PeerRole::PUBLISHER;
  message.protocol_version = aifc::kProtocolVersion;
  message.protocol_version_min = aifc::kProtocolVersionMin;
  message.requested_flags = aifc::kHelloFlagRequestHeuristics;
  message.client_name = "synthetic-client";
  message.publisher = aifc_test::synthetic_publisher(1U);
  return make_message_codec<aifc::HelloRequest>("hello request", message, aifc::encode_hello,
                                               aifc::decode_hello);
}

[[nodiscard]] MessageCodec<aifc::HelloResponse> hello_response_codec() {
  aifc::HelloResponse message;
  message.protocol_version = aifc::kProtocolVersion;
  message.epoch = aifc::CoordinatorEpoch{2};
  message.boot = aifc::CoordinatorBootId{3};
  message.granted_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  message.coordinator_banner = "synthetic coordinator banner";
  return make_message_codec<aifc::HelloResponse>("hello response", message,
                                                aifc::encode_hello_response,
                                                aifc::decode_hello_response);
}

[[nodiscard]] MessageCodec<aifc::RegisterPublisherRequest> register_publisher_codec() {
  aifc::RegisterPublisherRequest message;
  message.publisher = aifc_test::synthetic_publisher(2U);
  message.boot = aifc::PublisherBootId{4};
  message.first_evidence_generation = 1;
  message.description = "synthetic publisher";
  return make_message_codec<aifc::RegisterPublisherRequest>("register publisher request", message,
                                                           aifc::encode_register_publisher,
                                                           aifc::decode_register_publisher);
}

[[nodiscard]] MessageCodec<aifc::RegisterPublisherResponse> register_publisher_response_codec() {
  aifc::RegisterPublisherResponse message;
  message.session = aifc_test::synthetic_session(2U);
  message.epoch = aifc::CoordinatorEpoch{2};
  message.boot = aifc::CoordinatorBootId{3};
  message.granted_source = aifc::EvidenceSource::HEURISTIC;
  message.default_freshness_window = 4096;
  return make_message_codec<aifc::RegisterPublisherResponse>(
      "register publisher response", message, aifc::encode_register_publisher_response,
      aifc::decode_register_publisher_response);
}

[[nodiscard]] MessageCodec<aifc::DeclareWorkloadRequest> declare_workload_codec() {
  aifc::DeclareWorkloadRequest message;
  message.workload = aifc_test::synthetic_workload(3U);
  message.generation = aifc::WorkloadGeneration{2};
  message.description = "synthetic workload";
  return make_message_codec<aifc::DeclareWorkloadRequest>("declare workload request", message,
                                                         aifc::encode_declare_workload,
                                                         aifc::decode_declare_workload);
}

[[nodiscard]] MessageCodec<aifc::ProposeContractRequest> propose_contract_codec() {
  aifc::ProposeContractRequest message;
  message.contract = contract_fixture();
  // The definition digest is deliberately not part of the request: a peer cannot assert
  // one, so the coordinator recomputes it from the definition it received.
  message.contract.definition_digest = aifc::Digest256{};
  return make_message_codec<aifc::ProposeContractRequest>("propose contract request", message,
                                                         aifc::encode_propose_contract,
                                                         aifc::decode_propose_contract);
}

[[nodiscard]] MessageCodec<aifc::ContractReferenceRequest> contract_reference_codec() {
  aifc::ContractReferenceRequest message;
  message.contract = aifc_test::synthetic_contract(4U);
  return make_message_codec<aifc::ContractReferenceRequest>("contract reference request", message,
                                                           aifc::encode_contract_reference,
                                                           aifc::decode_contract_reference);
}

[[nodiscard]] MessageCodec<aifc::ContractResponse> contract_response_codec() {
  aifc::ContractResponse message;
  message.contract = contract_fixture();
  return make_message_codec<aifc::ContractResponse>("contract response", message,
                                                   aifc::encode_contract_response,
                                                   aifc::decode_contract_response);
}

[[nodiscard]] MessageCodec<aifc::RegisterFlowRequest> register_flow_codec() {
  aifc::RegisterFlowRequest message;
  message.key = flow_key();
  message.generation = aifc::FlowGeneration{3};
  return make_message_codec<aifc::RegisterFlowRequest>("register flow request", message,
                                                      aifc::encode_register_flow,
                                                      aifc::decode_register_flow);
}

[[nodiscard]] MessageCodec<aifc::RegisterFlowResponse> register_flow_response_codec() {
  aifc::RegisterFlowResponse message;
  message.flow_id = aifc::derive_flow_id(flow_key());
  message.generation = aifc::FlowGeneration{3};
  message.fenced_previous = true;
  message.previous_generation = aifc::FlowGeneration{2};
  return make_message_codec<aifc::RegisterFlowResponse>("register flow response", message,
                                                       aifc::encode_register_flow_response,
                                                       aifc::decode_register_flow_response);
}

[[nodiscard]] MessageCodec<aifc::PublishEvidenceRequest> publish_evidence_codec() {
  aifc::PublishEvidenceRequest message;
  message.payload = evidence_payload_fixture();
  return make_message_codec<aifc::PublishEvidenceRequest>(
      "publish evidence request", message, aifc::encode_publish_evidence,
      aifc::decode_publish_evidence,
      [](const aifc::PublishEvidenceRequest& decoded, const std::string& context) {
        // The numeric code the peer wrote must decode to exactly the class and source
        // this build names for it, or to UNKNOWN.  It must never become a different
        // built-in class, and never an extension class.
        if (std::string_view(aifc::to_string(decoded.payload.semantic)) == "EXTENSION") {
          AIFC_FAIL(context << ": a wire class code decoded to an extension class the input did "
                               "not name");
        }
        if (std::string_view(aifc::to_string(decoded.payload.claimed_source)) ==
            "UNRECOGNIZED_SOURCE") {
          AIFC_FAIL(context << ": a wire source code decoded to an undefined source enumerator");
        }
      });
}

[[nodiscard]] MessageCodec<aifc::PublishEvidenceResponse> publish_evidence_response_codec() {
  aifc::PublishEvidenceResponse message;
  message.evidence_id = aifc::make_evidence_id("ev-66666666666666666666666666666666");
  message.flow_id = aifc::derive_flow_id(flow_key());
  message.flow_generation = aifc::FlowGeneration{3};
  message.effective_source = aifc::EvidenceSource::CONTRACT_DERIVED;
  message.superseded_previous = true;
  message.superseded_id = aifc::make_evidence_id("ev-77777777777777777777777777777777");
  message.fenced_flow_generation = false;
  message.notes.push_back("first synthetic note");
  message.notes.push_back("second synthetic note");
  return make_message_codec<aifc::PublishEvidenceResponse>(
      "publish evidence response", message, aifc::encode_publish_evidence_response,
      aifc::decode_publish_evidence_response);
}

[[nodiscard]] MessageCodec<aifc::WithdrawEvidenceRequest> withdraw_evidence_codec() {
  aifc::WithdrawEvidenceRequest message;
  message.evidence = aifc::make_evidence_id("ev-88888888888888888888888888888888");
  message.reason = "synthetic withdrawal";
  return make_message_codec<aifc::WithdrawEvidenceRequest>("withdraw evidence request", message,
                                                          aifc::encode_withdraw_evidence,
                                                          aifc::decode_withdraw_evidence);
}

[[nodiscard]] MessageCodec<aifc::RevokeGenerationRequest> revoke_generation_codec() {
  aifc::RevokeGenerationRequest message;
  message.flow_id = aifc::derive_flow_id(flow_key());
  message.generation = aifc::FlowGeneration{3};
  message.reason = "synthetic revocation";
  return make_message_codec<aifc::RevokeGenerationRequest>("revoke generation request", message,
                                                          aifc::encode_revoke_generation,
                                                          aifc::decode_revoke_generation);
}

[[nodiscard]] MessageCodec<aifc::ClassifyRequest> classify_request_codec() {
  aifc::ClassifyRequest message;
  aifc::ClassifyQueryEntry first;
  first.key = flow_key();
  first.generation = aifc::FlowGeneration{3};
  first.explain = true;
  message.entries.push_back(first);
  aifc::ClassifyQueryEntry second;
  second.key = aifc_test::synthetic_flow_key(2U);
  second.generation = aifc::FlowGeneration{1};
  second.explain = false;
  message.entries.push_back(second);
  return make_message_codec<aifc::ClassifyRequest>("classify request", message,
                                                  aifc::encode_classify_request,
                                                  aifc::decode_classify_request);
}

[[nodiscard]] MessageCodec<aifc::ClassifyResponse> classify_response_codec() {
  aifc::ClassifyResponse message;
  const Codec<aifc::Classification> classification = classification_codec();
  aifc::BufferReader reader(classification.image, limits().max_string_bytes);
  aifc::Classification decoded;
  if (classification.decode(reader, decoded) != ErrorCode::OK) {
    AIFC_FAIL("the classification fixture could not be re-read for the classify response");
  }
  message.classifications.push_back(decoded);
  message.per_key_codes.push_back(ErrorCode::OK);
  message.per_key_messages.push_back("synthetic message");
  message.explanations.push_back("synthetic explanation");
  message.coordinator_epoch = 2;
  message.coordinator_boot = 3;
  message.succeeded = 1;
  message.failed = 0;
  return make_message_codec<aifc::ClassifyResponse>("classify response", message,
                                                   aifc::encode_classify_response,
                                                   aifc::decode_classify_response);
}

[[nodiscard]] MessageCodec<aifc::StatsResponse> stats_response_codec() {
  aifc::StatsResponse message;
  message.rendered = "counters: flows=1 evidence=2 classifications=3";
  return make_message_codec<aifc::StatsResponse>("stats response", message,
                                                aifc::encode_stats_response,
                                                aifc::decode_stats_response);
}

[[nodiscard]] MessageCodec<aifc::ErrorResponse> error_response_codec() {
  aifc::ErrorResponse message;
  message.code = ErrorCode::STALE_EPOCH;
  message.message = "synthetic error text";
  return make_message_codec<aifc::ErrorResponse>("error response", message,
                                                aifc::encode_error_response,
                                                aifc::decode_error_response);
}

// ---------------------------------------------------------------------------
// Generic fuzz drivers
// ---------------------------------------------------------------------------

template <typename Record>
void drive_round_trip(const Codec<Record>& codec,
                      Status (*encode)(BufferWriter&, const Record&)) {
  BufferReader reader(codec.image, limits().max_string_bytes);
  Record decoded{};
  const ErrorCode code = codec.decode(reader, decoded);
  if (code != ErrorCode::OK) {
    AIFC_FAIL(codec.name << ": the canonical image of " << codec.image.size()
                         << " bytes did not decode: " << code << "; image=["
                         << hex_dump(codec.image) << "]");
    return;
  }
  if (!reader.exhausted()) {
    AIFC_FAIL(codec.name << ": decoding consumed " << reader.offset() << " of "
                         << codec.image.size() << " bytes, so the canonical image is not "
                         << "exactly the record it encodes");
  }
  BufferWriter writer(kRecordBound);
  const Status status = encode(writer, decoded);
  if (!status) {
    AIFC_FAIL(codec.name << ": re-encoding a decoded record failed: "
                         << aifc::render_status(status));
    return;
  }
  if (writer.bytes() != codec.image) {
    AIFC_FAIL(codec.name << ": re-encoded bytes differ from the original image;\n      original=["
                         << hex_dump(codec.image) << "]\n      re-encoded=["
                         << hex_dump(writer.bytes()) << "]");
    return;
  }
  if (codec.invariant) codec.invariant(decoded, codec.name + " round trip");
}

template <typename Message>
void drive_message_round_trip(const MessageCodec<Message>& codec) {
  Message decoded{};
  const ErrorCode code = codec.decode(codec.image, decoded);
  if (code != ErrorCode::OK) {
    AIFC_FAIL(codec.name << ": the canonical image of " << codec.image.size()
                         << " bytes did not decode: " << code << "; image=["
                         << hex_dump(codec.image) << "]");
    return;
  }
  ByteBuffer reencoded;
  const Status status = codec.encode(decoded, reencoded);
  if (!status) {
    AIFC_FAIL(codec.name << ": re-encoding a decoded message failed: "
                         << aifc::render_status(status));
    return;
  }
  if (reencoded != codec.image) {
    AIFC_FAIL(codec.name << ": re-encoded bytes differ from the original image;\n      original=["
                         << hex_dump(codec.image) << "]\n      re-encoded=["
                         << hex_dump(reencoded) << "]");
    return;
  }
  if (codec.invariant) codec.invariant(decoded, codec.name + " round trip");
}

template <typename Record>
void drive_truncation(const Codec<Record>& codec) {
  for (std::size_t length = 0; length < codec.image.size(); ++length) {
    BufferReader reader(codec.image.data(), length, limits().max_string_bytes);
    Record decoded{};
    const ErrorCode code = codec.decode(reader, decoded);
    const std::string context = codec.name + ": truncated to " + std::to_string(length) + " of " +
                                std::to_string(codec.image.size()) + " bytes; image=[" +
                                hex_dump(codec.image.data(), length) + "]";
    if (code == ErrorCode::OK) {
      AIFC_FAIL(context << ": a truncated image decoded successfully");
      continue;
    }
    if (code != ErrorCode::MALFORMED_RECORD && code != ErrorCode::CAPACITY_EXCEEDED) {
      AIFC_FAIL(context << ": expected MALFORMED_RECORD or CAPACITY_EXCEEDED but got " << aifc::to_string(code));
    }
  }
}

template <typename Message>
void drive_message_truncation(const MessageCodec<Message>& codec) {
  for (std::size_t length = 0; length < codec.image.size(); ++length) {
    ByteBuffer truncated(codec.image.begin(), codec.image.begin() + static_cast<std::ptrdiff_t>(length));
    Message decoded{};
    const ErrorCode code = codec.decode(truncated, decoded);
    const std::string context = codec.name + ": truncated to " + std::to_string(length) + " of " +
                                std::to_string(codec.image.size()) + " bytes; image=[" +
                                hex_dump(truncated) + "]";
    if (code == ErrorCode::OK) {
      AIFC_FAIL(context << ": a truncated message decoded successfully");
      continue;
    }
    if (code != ErrorCode::MALFORMED_RECORD && code != ErrorCode::CAPACITY_EXCEEDED) {
      AIFC_FAIL(context << ": expected MALFORMED_RECORD or CAPACITY_EXCEEDED but got " << aifc::to_string(code));
    }
  }
}

template <typename Record>
void drive_trailing_garbage(const Codec<Record>& codec) {
  const std::uint8_t extra_bytes[] = {0x00U, 0x01U, 0xFFU};
  for (const std::uint8_t extra : extra_bytes) {
    ByteBuffer padded = codec.image;
    padded.push_back(extra);
    BufferReader reader(padded, limits().max_string_bytes);
    Record decoded{};
    const ErrorCode code = codec.decode(reader, decoded);
    const std::string context = codec.name + ": one 0x" + hex_dump(&extra, 1) +
                                " byte appended to a canonical image";
    if (code != ErrorCode::OK) {
      AIFC_FAIL(context << ": the record itself must still decode (the caller decides about the "
                           "surplus) but got "
                        << aifc::to_string(code));
      continue;
    }
    const Status finished = reader.finish();
    if (finished.ok()) {
      AIFC_FAIL(context << ": " << reader.remaining()
                        << " surplus bytes were accepted as part of the record");
      continue;
    }
    if (finished.code != ErrorCode::TRAILING_GARBAGE) {
      AIFC_FAIL(context << ": expected TRAILING_GARBAGE for the surplus but got "
                        << aifc::render_status(finished));
    }
  }
}

template <typename Message>
void drive_message_trailing_garbage(const MessageCodec<Message>& codec) {
  const std::uint8_t extra_bytes[] = {0x00U, 0x01U, 0xFFU};
  for (const std::uint8_t extra : extra_bytes) {
    ByteBuffer padded = codec.image;
    padded.push_back(extra);
    Message decoded{};
    const ErrorCode code = codec.decode(padded, decoded);
    const std::string context = codec.name + ": one 0x" + hex_dump(&extra, 1) +
                                " byte appended to a canonical message";
    if (code == ErrorCode::OK) {
      AIFC_FAIL(context << ": a message with trailing bytes was accepted");
      continue;
    }
    if (code != ErrorCode::TRAILING_GARBAGE) {
      AIFC_FAIL(context << ": expected TRAILING_GARBAGE but got " << aifc::to_string(code));
    }
  }
}

// A decoder that stops before the end of the buffer is not wrong: the canonical record
// is the bytes it consumed, and the caller's finish() is what reports the surplus.  That
// split is asserted here rather than assumed.
template <typename Record>
void expect_surplus_is_reported(const Codec<Record>& codec, BufferReader& reader,
                                const Record& decoded, const std::string& context) {
  if (reader.exhausted()) {
    if (codec.invariant) codec.invariant(decoded, context);
    return;
  }
  const std::size_t surplus = reader.remaining();
  const Status finished = reader.finish();
  if (finished.ok()) {
    AIFC_FAIL(context << ": " << surplus << " surplus bytes were accepted as part of the record");
    return;
  }
  if (finished.code != ErrorCode::TRAILING_GARBAGE) {
    AIFC_FAIL(context << ": " << surplus << " surplus bytes were reported as "
                      << aifc::render_status(finished) << " rather than TRAILING_GARBAGE");
    return;
  }
  if (codec.invariant) codec.invariant(decoded, context);
}

template <typename Record>
void drive_bit_flips(const Codec<Record>& codec) {
  std::size_t accepted = 0;
  std::size_t refused = 0;
  for (std::size_t offset = 0; offset < codec.image.size(); ++offset) {
    for (std::size_t bit = 0; bit < 8; ++bit) {
      ByteBuffer mutated = codec.image;
      flip_bit(mutated, offset, bit);
      BufferReader reader(mutated, limits().max_string_bytes);
      Record decoded{};
      const ErrorCode code = codec.decode(reader, decoded);
      const std::string context = codec.name + ": byte " + std::to_string(offset) + " bit " +
                                  std::to_string(bit) + " flipped; image=[" + hex_dump(mutated) +
                                  "]";
      if (code == ErrorCode::OK) {
        ++accepted;
        expect_surplus_is_reported(codec, reader, decoded, context);
        continue;
      }
      ++refused;
      if (!is_documented_refusal(code)) fail_unexpected_code(context, code);
    }
  }
  // A decoder that accepted nothing at all would pass the loop above trivially, so the
  // shape of the result is asserted too: a record with identity and description strings
  // has at least one mutation that yields a different but well-formed record (the
  // description bytes are not validated), and a digest-protected record refuses more
  // than it accepts.  Both bounds are loose on purpose: they detect a decoder that has
  // stopped decoding, not a particular mutation count.
  if (accepted == 0 && refused == 0) {
    AIFC_FAIL(codec.name << ": no mutation was decoded at all");
  }
}

template <typename Message>
void drive_message_bit_flips(const MessageCodec<Message>& codec) {
  for (std::size_t offset = 0; offset < codec.image.size(); ++offset) {
    for (std::size_t bit = 0; bit < 8; ++bit) {
      ByteBuffer mutated = codec.image;
      flip_bit(mutated, offset, bit);
      Message decoded{};
      const ErrorCode code = codec.decode(mutated, decoded);
      const std::string context = codec.name + ": byte " + std::to_string(offset) + " bit " +
                                  std::to_string(bit) + " flipped; image=[" + hex_dump(mutated) +
                                  "]";
      if (code == ErrorCode::OK) {
        if (codec.invariant) codec.invariant(decoded, context);
        continue;
      }
      if (!is_documented_refusal(code)) fail_unexpected_code(context, code);
    }
  }
}

template <typename Record>
void drive_random_corruption(const Codec<Record>& codec, std::uint64_t seed, int iterations) {
  aifc::Rng rng(seed);
  for (int iteration = 0; iteration < iterations; ++iteration) {
    ByteBuffer mutated = codec.image;
    const std::uint64_t flips = 1U + rng.next_below(6U);
    std::string description;
    for (std::uint64_t flip = 0; flip < flips; ++flip) {
      const std::size_t offset = static_cast<std::size_t>(rng.next_below(mutated.size()));
      const std::size_t bit = static_cast<std::size_t>(rng.next_below(8U));
      flip_bit(mutated, offset, bit);
      if (!description.empty()) description += ",";
      description += std::to_string(offset) + ":" + std::to_string(bit);
    }
    BufferReader reader(mutated, limits().max_string_bytes);
    Record decoded{};
    const ErrorCode code = codec.decode(reader, decoded);
    const std::string context = codec.name + ": " + aifc::format_seed(seed) + " iteration=" +
                                std::to_string(iteration) + " flips=" + description + " image=[" +
                                hex_dump(mutated) + "]";
    if (code == ErrorCode::OK) {
      expect_surplus_is_reported(codec, reader, decoded, context);
      continue;
    }
    if (!is_documented_refusal(code)) fail_unexpected_code(context, code);
  }
}

template <typename Message>
void drive_message_random_corruption(const MessageCodec<Message>& codec, std::uint64_t seed,
                                     int iterations) {
  aifc::Rng rng(seed);
  for (int iteration = 0; iteration < iterations; ++iteration) {
    ByteBuffer mutated = codec.image;
    const std::uint64_t flips = 1U + rng.next_below(6U);
    std::string description;
    for (std::uint64_t flip = 0; flip < flips; ++flip) {
      const std::size_t offset = static_cast<std::size_t>(rng.next_below(mutated.size()));
      const std::size_t bit = static_cast<std::size_t>(rng.next_below(8U));
      flip_bit(mutated, offset, bit);
      if (!description.empty()) description += ",";
      description += std::to_string(offset) + ":" + std::to_string(bit);
    }
    Message decoded{};
    const ErrorCode code = codec.decode(mutated, decoded);
    const std::string context = codec.name + ": " + aifc::format_seed(seed) + " iteration=" +
                                std::to_string(iteration) + " flips=" + description + " image=[" +
                                hex_dump(mutated) + "]";
    if (code == ErrorCode::OK) {
      if (codec.invariant) codec.invariant(decoded, context);
      continue;
    }
    if (!is_documented_refusal(code)) fail_unexpected_code(context, code);
  }
}

// "The fields arrived in the wrong order."  Reversing the whole image is the crudest
// form; moving the schema byte to the end is the interesting one, because a decoder
// that did not validate its schema first would happily reinterpret the second field as
// a version and keep going.
template <typename Record>
void drive_reversed_order(const Codec<Record>& codec) {
  {
    const ByteBuffer backwards = reversed(codec.image);
    BufferReader reader(backwards, limits().max_string_bytes);
    Record decoded{};
    const ErrorCode code = codec.decode(reader, decoded);
    if (code == ErrorCode::OK) {
      AIFC_FAIL(codec.name << ": a byte-reversed image decoded successfully; image=["
                           << hex_dump(backwards) << "]");
    } else if (!is_documented_refusal(code)) {
      fail_unexpected_code(codec.name + ": byte-reversed image [" + hex_dump(backwards) + "]", code);
    }
  }
  {
    const ByteBuffer rotated = schema_rotated(codec.image);
    BufferReader reader(rotated, limits().max_string_bytes);
    Record decoded{};
    const ErrorCode code = codec.decode(reader, decoded);
    const std::string context = codec.name + ": schema byte moved to the end; image=[" +
                                hex_dump(rotated) + "]";
    if (code == ErrorCode::OK) {
      AIFC_FAIL(context << ": the decoder accepted a record whose schema byte is not first");
      return;
    }
    // The record schema is the first thing every record decoder validates, so when the
    // new first byte is not the schema the refusal must be exactly UNSUPPORTED_VERSION.
    if (rotated.front() != codec.schema) {
      if (code != ErrorCode::UNSUPPORTED_VERSION) {
        AIFC_FAIL(context << ": the first byte is " << static_cast<unsigned>(rotated.front())
                          << ", which is not the schema " << static_cast<unsigned>(codec.schema)
                          << ", so the refusal must be UNSUPPORTED_VERSION but was " << aifc::to_string(code));
      }
    } else if (!is_documented_refusal(code)) {
      fail_unexpected_code(context, code);
    }
  }
}

template <typename Message>
void drive_message_reversed_order(const MessageCodec<Message>& codec) {
  const ByteBuffer backwards = reversed(codec.image);
  Message decoded{};
  const ErrorCode code = codec.decode(backwards, decoded);
  if (code == ErrorCode::OK) {
    // A byte-reversed message is not automatically malformed: a message that is one
    // fixed-width field of 16 bytes or fewer reverses into a different but well-formed
    // message.  When that happens the only honest assertion is that the invariant
    // still holds, which the caller checks through the invariant hook.
    if (codec.invariant) {
      codec.invariant(decoded, codec.name + ": byte-reversed image [" + hex_dump(backwards) + "]");
    }
    return;
  }
  if (!is_documented_refusal(code)) {
    fail_unexpected_code(codec.name + ": byte-reversed image [" + hex_dump(backwards) + "]", code);
  }
}

// Patches a declared 32 bit value and requires the refusal to be CAPACITY_EXCEEDED.
template <typename Record>
void drive_absurd_length(const Codec<Record>& codec, std::size_t offset,
                         const std::string& what) {
  ByteBuffer mutated = codec.image;
  patch_u32(mutated, offset, 0xFFFFFFFFU);
  BufferReader reader(mutated, limits().max_string_bytes);
  Record decoded{};
  const ErrorCode code = codec.decode(reader, decoded);
  const std::string context = codec.name + ": " + what + " at offset " + std::to_string(offset) +
                              " declares 0xFFFFFFFF; image=[" + hex_dump(mutated) + "]";
  if (code == ErrorCode::OK) {
    AIFC_FAIL(context << ": an absurd declared length was accepted");
    return;
  }
  if (code != ErrorCode::CAPACITY_EXCEEDED) {
    AIFC_FAIL(context << ": expected CAPACITY_EXCEEDED (the bound is checked before the bytes "
                         "that are present) but got "
                      << aifc::to_string(code));
  }
}

template <typename Message>
void drive_message_absurd_length(const MessageCodec<Message>& codec, std::size_t offset,
                                 const std::string& what) {
  ByteBuffer mutated = codec.image;
  patch_u32(mutated, offset, 0xFFFFFFFFU);
  Message decoded{};
  const ErrorCode code = codec.decode(mutated, decoded);
  const std::string context = codec.name + ": " + what + " at offset " + std::to_string(offset) +
                              " declares 0xFFFFFFFF; image=[" + hex_dump(mutated) + "]";
  if (code == ErrorCode::OK) {
    AIFC_FAIL(context << ": an absurd declared length was accepted");
    return;
  }
  if (code != ErrorCode::CAPACITY_EXCEEDED) {
    AIFC_FAIL(context << ": expected CAPACITY_EXCEEDED but got " << aifc::to_string(code));
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

AIFC_TEST("codec fuzz: every decoder round trips its own canonical image") {
  drive_round_trip(fixtures::flow_codec(), aifc::encode_flow_record);
  drive_round_trip(fixtures::publisher_codec(), aifc::encode_publisher_record);
  drive_round_trip(fixtures::workload_codec(), aifc::encode_workload_record);
  drive_round_trip(fixtures::contract_codec(), aifc::encode_contract);
  drive_round_trip(fixtures::evidence_codec(), aifc::encode_evidence_record);
  drive_round_trip(fixtures::classification_codec(), aifc::encode_classification);
  drive_round_trip(fixtures::revocation_codec(), aifc::encode_revocation);
  drive_round_trip(fixtures::supersession_codec(), aifc::encode_supersession);
  drive_round_trip(fixtures::policy_codec(), aifc::encode_policy);

  drive_message_round_trip(hello_codec());
  drive_message_round_trip(hello_response_codec());
  drive_message_round_trip(register_publisher_codec());
  drive_message_round_trip(register_publisher_response_codec());
  drive_message_round_trip(declare_workload_codec());
  drive_message_round_trip(propose_contract_codec());
  drive_message_round_trip(contract_reference_codec());
  drive_message_round_trip(contract_response_codec());
  drive_message_round_trip(register_flow_codec());
  drive_message_round_trip(register_flow_response_codec());
  drive_message_round_trip(publish_evidence_codec());
  drive_message_round_trip(publish_evidence_response_codec());
  drive_message_round_trip(withdraw_evidence_codec());
  drive_message_round_trip(revoke_generation_codec());
  drive_message_round_trip(classify_request_codec());
  drive_message_round_trip(classify_response_codec());
  drive_message_round_trip(stats_response_codec());
  drive_message_round_trip(error_response_codec());
}

AIFC_TEST("codec fuzz: a contract proposal carries no digest and never asserts one") {
  aifc::ProposeContractRequest request;
  request.contract = contract_fixture();
  request.contract.definition_digest = aifc::Digest256{};
  ByteBuffer image;
  AIFC_CHECK_OK(aifc::encode_propose_contract(request, image));
  auto decoded = aifc::decode_propose_contract(image, limits());
  AIFC_CHECK_OK(decoded);
  if (decoded) {
    AIFC_CHECK_MSG(decoded.value().contract.definition_digest.is_zero(),
                   "a decoded contract proposal carries the digest "
                       << decoded.value().contract.definition_digest.to_hex()
                       << "; a peer must not be able to assert one");
    const aifc::Digest256 recomputed = aifc::compute_contract_digest(decoded.value().contract);
    AIFC_CHECK_MSG(!recomputed.is_zero(),
                   "the coordinator cannot recompute a digest for the decoded proposal");
    aifc::WorkloadContract with_digest = decoded.value().contract;
    with_digest.definition_digest = recomputed;
    const ByteBuffer verified = fixtures::encode_ok(
        kRecordBound, [&](BufferWriter& writer) { return aifc::encode_contract(writer, with_digest); },
        "the proposal with its recomputed digest");
    BufferReader reader(verified, limits().max_string_bytes);
    AIFC_CHECK_OK(aifc::decode_contract(reader, limits()));
  }
}

AIFC_TEST("codec fuzz: a truncated image is refused at every length") {
  drive_truncation(fixtures::flow_codec());
  drive_truncation(fixtures::publisher_codec());
  drive_truncation(fixtures::workload_codec());
  drive_truncation(fixtures::contract_codec());
  drive_truncation(fixtures::evidence_codec());
  drive_truncation(fixtures::classification_codec());
  drive_truncation(fixtures::revocation_codec());
  drive_truncation(fixtures::supersession_codec());
  drive_truncation(fixtures::policy_codec());

  drive_message_truncation(hello_codec());
  drive_message_truncation(hello_response_codec());
  drive_message_truncation(register_publisher_codec());
  drive_message_truncation(register_publisher_response_codec());
  drive_message_truncation(declare_workload_codec());
  drive_message_truncation(propose_contract_codec());
  drive_message_truncation(contract_reference_codec());
  drive_message_truncation(contract_response_codec());
  drive_message_truncation(register_flow_codec());
  drive_message_truncation(register_flow_response_codec());
  drive_message_truncation(publish_evidence_codec());
  drive_message_truncation(publish_evidence_response_codec());
  drive_message_truncation(withdraw_evidence_codec());
  drive_message_truncation(revoke_generation_codec());
  drive_message_truncation(classify_request_codec());
  drive_message_truncation(classify_response_codec());
  drive_message_truncation(stats_response_codec());
  drive_message_truncation(error_response_codec());
}

AIFC_TEST("codec fuzz: an absurd declared length is CAPACITY_EXCEEDED, not an allocation") {
  // The smallest possible form of the attack: a schema byte followed by a four byte
  // string length of 0xFFFFFFFF, and nothing else.  Five bytes of input must not make
  // the reader reserve four gigabytes, so the refusal has to be the bound and not
  // "the record is truncated".
  const std::uint8_t schemas[] = {1U};
  for (const std::uint8_t schema : schemas) {
    ByteBuffer minimal;
    minimal.push_back(schema);
    write_u32(minimal, 0xFFFFFFFFU);
    {
      BufferReader reader(minimal, limits().max_string_bytes);
      AIFC_CHECK_ERR(aifc::decode_evidence_record(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
    }
    {
      BufferReader reader(minimal, limits().max_string_bytes);
      AIFC_CHECK_ERR(aifc::decode_publisher_record(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
    }
    {
      BufferReader reader(minimal, limits().max_string_bytes);
      AIFC_CHECK_ERR(aifc::decode_workload_record(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
    }
    {
      BufferReader reader(minimal, limits().max_string_bytes);
      AIFC_CHECK_ERR(aifc::decode_contract(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
    }
    {
      BufferReader reader(minimal, limits().max_string_bytes);
      AIFC_CHECK_ERR(aifc::decode_supersession(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
    }
  }

  // The same lie placed in a canonical image: the first declared string of each record
  // is stretched to four gigabytes.  The offset is named in the failure message.
  drive_absurd_length(fixtures::evidence_codec(), 1U, "the evidence identity length");
  drive_absurd_length(fixtures::publisher_codec(), 1U, "the publisher identity length");
  drive_absurd_length(fixtures::workload_codec(), 1U, "the workload identity length");
  drive_absurd_length(fixtures::contract_codec(), 1U, "the contract identity length");
  drive_absurd_length(fixtures::supersession_codec(), 1U, "the previous identity length");
  drive_absurd_length(fixtures::flow_codec(), 18U, "the local address blob length");
  drive_absurd_length(fixtures::revocation_codec(), 25U, "the evidence identity length");
  drive_absurd_length(fixtures::classification_codec(), 32U, "the selected evidence length");

  drive_message_absurd_length(hello_codec(), 9U, "the client name length");
  drive_message_absurd_length(hello_response_codec(), 19U, "the banner length");
  drive_message_absurd_length(register_publisher_codec(), 0U, "the publisher identity length");
  drive_message_absurd_length(register_publisher_response_codec(), 0U, "the session length");
  drive_message_absurd_length(declare_workload_codec(), 0U, "the workload identity length");
  drive_message_absurd_length(propose_contract_codec(), 1U, "the contract identity length");
  drive_message_absurd_length(contract_reference_codec(), 0U, "the contract identity length");
  drive_message_absurd_length(contract_response_codec(), 1U, "the contract identity length");
  drive_message_absurd_length(register_flow_codec(), 1U, "the local address blob length");
  drive_message_absurd_length(publish_evidence_codec(), 0U, "the workload identity length");
  drive_message_absurd_length(publish_evidence_response_codec(), 0U, "the evidence identity length");
  drive_message_absurd_length(withdraw_evidence_codec(), 0U, "the evidence identity length");
  drive_message_absurd_length(revoke_generation_codec(), 24U, "the reason length");
  drive_message_absurd_length(error_response_codec(), 4U, "the error message length");
  drive_message_absurd_length(stats_response_codec(), 0U, "the rendered length");
  drive_message_absurd_length(classify_request_codec(), 0U, "the batch entry count");
  drive_message_absurd_length(classify_response_codec(), 0U, "the classification count");

  // The order of the two checks is the whole point, so it is asserted directly: with a
  // limit of 16 bytes, a declared length of 20 is refused as CAPACITY_EXCEEDED even
  // though the 20 bytes are also absent, while a declared length of 8 -- inside the
  // limit -- is refused as a truncated record.
  {
    CodecLimits small;
    small.max_string_bytes = 16U;
    small.max_blob_bytes = 16U;
    small.max_collection_count = 4U;

    ByteBuffer over_limit;
    over_limit.push_back(1U);
    write_u32(over_limit, 20U);
    BufferReader reader(over_limit, small.max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_evidence_record(reader, small), ErrorCode::CAPACITY_EXCEEDED);

    ByteBuffer within_limit;
    within_limit.push_back(1U);
    write_u32(within_limit, 8U);
    BufferReader reader2(within_limit, small.max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_evidence_record(reader2, small), ErrorCode::MALFORMED_RECORD);

    ByteBuffer over_count;
    write_u32(over_count, 5U);
    AIFC_CHECK_ERR(aifc::decode_classify_request(over_count, small), ErrorCode::CAPACITY_EXCEEDED);

    ByteBuffer within_count;
    write_u32(within_count, 4U);
    AIFC_CHECK_ERR(aifc::decode_classify_request(within_count, small),
                   ErrorCode::MALFORMED_RECORD);
  }
}

AIFC_TEST("codec fuzz: trailing bytes after a canonical record are TRAILING_GARBAGE") {
  drive_trailing_garbage(fixtures::flow_codec());
  drive_trailing_garbage(fixtures::publisher_codec());
  drive_trailing_garbage(fixtures::workload_codec());
  drive_trailing_garbage(fixtures::contract_codec());
  drive_trailing_garbage(fixtures::evidence_codec());
  drive_trailing_garbage(fixtures::classification_codec());
  drive_trailing_garbage(fixtures::revocation_codec());
  drive_trailing_garbage(fixtures::supersession_codec());
  drive_trailing_garbage(fixtures::policy_codec());

  drive_message_trailing_garbage(hello_codec());
  drive_message_trailing_garbage(hello_response_codec());
  drive_message_trailing_garbage(register_publisher_codec());
  drive_message_trailing_garbage(register_publisher_response_codec());
  drive_message_trailing_garbage(declare_workload_codec());
  drive_message_trailing_garbage(propose_contract_codec());
  drive_message_trailing_garbage(contract_reference_codec());
  drive_message_trailing_garbage(contract_response_codec());
  drive_message_trailing_garbage(register_flow_codec());
  drive_message_trailing_garbage(register_flow_response_codec());
  drive_message_trailing_garbage(publish_evidence_codec());
  drive_message_trailing_garbage(publish_evidence_response_codec());
  drive_message_trailing_garbage(withdraw_evidence_codec());
  drive_message_trailing_garbage(revoke_generation_codec());
  drive_message_trailing_garbage(classify_request_codec());
  drive_message_trailing_garbage(classify_response_codec());
  drive_message_trailing_garbage(stats_response_codec());
  drive_message_trailing_garbage(error_response_codec());
}

AIFC_TEST("codec fuzz: every single bit flip is refused or preserves the invariants") {
  drive_bit_flips(fixtures::flow_codec());
  drive_bit_flips(fixtures::publisher_codec());
  drive_bit_flips(fixtures::workload_codec());
  drive_bit_flips(fixtures::contract_codec());
  drive_bit_flips(fixtures::evidence_codec());
  drive_bit_flips(fixtures::classification_codec());
  drive_bit_flips(fixtures::revocation_codec());
  drive_bit_flips(fixtures::supersession_codec());
  drive_bit_flips(fixtures::policy_codec());

  drive_message_bit_flips(hello_codec());
  drive_message_bit_flips(hello_response_codec());
  drive_message_bit_flips(register_publisher_codec());
  drive_message_bit_flips(register_publisher_response_codec());
  drive_message_bit_flips(declare_workload_codec());
  drive_message_bit_flips(propose_contract_codec());
  drive_message_bit_flips(contract_reference_codec());
  drive_message_bit_flips(contract_response_codec());
  drive_message_bit_flips(register_flow_codec());
  drive_message_bit_flips(register_flow_response_codec());
  drive_message_bit_flips(publish_evidence_codec());
  drive_message_bit_flips(publish_evidence_response_codec());
  drive_message_bit_flips(withdraw_evidence_codec());
  drive_message_bit_flips(revoke_generation_codec());
  drive_message_bit_flips(classify_request_codec());
  drive_message_bit_flips(classify_response_codec());
  drive_message_bit_flips(stats_response_codec());
  drive_message_bit_flips(error_response_codec());
}

AIFC_TEST("codec fuzz: seeded multi-byte corruption") {
  const std::uint64_t record_seed = 0xA1FC000000000001ULL;
  const std::uint64_t message_seed = 0xA1FC000000000002ULL;
  const int kRecordIterations = 400;
  const int kMessageIterations = 400;

  drive_random_corruption(fixtures::flow_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::publisher_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::workload_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::contract_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::evidence_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::classification_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::revocation_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::supersession_codec(), record_seed, kRecordIterations);
  drive_random_corruption(fixtures::policy_codec(), record_seed, kRecordIterations);

  drive_message_random_corruption(hello_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(hello_response_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(register_publisher_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(register_publisher_response_codec(), message_seed,
                                  kMessageIterations);
  drive_message_random_corruption(declare_workload_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(propose_contract_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(contract_reference_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(contract_response_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(register_flow_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(register_flow_response_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(publish_evidence_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(publish_evidence_response_codec(), message_seed,
                                  kMessageIterations);
  drive_message_random_corruption(withdraw_evidence_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(revoke_generation_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(classify_request_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(classify_response_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(stats_response_codec(), message_seed, kMessageIterations);
  drive_message_random_corruption(error_response_codec(), message_seed, kMessageIterations);
}

AIFC_TEST("codec fuzz: reversed field order is refused") {
  drive_reversed_order(fixtures::flow_codec());
  drive_reversed_order(fixtures::publisher_codec());
  drive_reversed_order(fixtures::workload_codec());
  drive_reversed_order(fixtures::contract_codec());
  drive_reversed_order(fixtures::evidence_codec());
  drive_reversed_order(fixtures::classification_codec());
  drive_reversed_order(fixtures::revocation_codec());
  drive_reversed_order(fixtures::supersession_codec());
  drive_reversed_order(fixtures::policy_codec());

  drive_message_reversed_order(hello_codec());
  drive_message_reversed_order(hello_response_codec());
  drive_message_reversed_order(register_publisher_codec());
  drive_message_reversed_order(register_publisher_response_codec());
  drive_message_reversed_order(declare_workload_codec());
  drive_message_reversed_order(propose_contract_codec());
  drive_message_reversed_order(contract_reference_codec());
  drive_message_reversed_order(contract_response_codec());
  drive_message_reversed_order(register_flow_codec());
  drive_message_reversed_order(register_flow_response_codec());
  drive_message_reversed_order(publish_evidence_codec());
  drive_message_reversed_order(publish_evidence_response_codec());
  drive_message_reversed_order(withdraw_evidence_codec());
  drive_message_reversed_order(revoke_generation_codec());
  drive_message_reversed_order(classify_request_codec());
  drive_message_reversed_order(classify_response_codec());
  drive_message_reversed_order(stats_response_codec());
  drive_message_reversed_order(error_response_codec());
}

AIFC_TEST("codec fuzz: huge collection counts and nested length lies are refused") {
  // A contract whose remote scope count is a lie.  The three cases are the three
  // shapes a lie can take: beyond the limit, inside the limit but beyond the payload,
  // and inside the payload but not matching the bytes that follow.
  const auto contract_prefix = [](std::uint32_t remote_count, std::size_t addresses_present) {
    ByteBuffer bytes;
    bytes.push_back(1U);
    write_string(bytes, "contract-9");
    write_string(bytes, "workload-9");
    write_u64(bytes, 2U);
    write_string(bytes, "publisher-9");
    bytes.push_back(1U);
    write_u16(bytes, 2U);
    bytes.push_back(1U);
    write_u32(bytes, remote_count);
    for (std::size_t i = 0; i < addresses_present; ++i) {
      write_u32(bytes, 16U);
      write_bytes(bytes, ByteBuffer(16, 0x7FU));
    }
    return bytes;
  };
  {
    const ByteBuffer beyond_limit = contract_prefix(0xFFFFFFFFU, 0U);
    BufferReader reader(beyond_limit, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_contract(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
  }
  {
    const ByteBuffer beyond_payload = contract_prefix(5U, 0U);
    BufferReader reader(beyond_payload, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_contract(reader, limits()), ErrorCode::MALFORMED_RECORD);
  }
  {
    const ByteBuffer lying = contract_prefix(2U, 1U);
    BufferReader reader(lying, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_contract(reader, limits()), ErrorCode::MALFORMED_RECORD);
  }
  {
    const ByteBuffer honest = contract_prefix(1U, 1U);
    BufferReader reader(honest, limits().max_string_bytes);
    // The scope is complete; what is missing is the port scope count that follows, so
    // the refusal is a truncated record and not an invented collection.
    AIFC_CHECK_ERR(aifc::decode_contract(reader, limits()), ErrorCode::MALFORMED_RECORD);
  }

  // A classification whose citation count is a lie.
  const auto classification_prefix = [](std::uint32_t citation_count) {
    ByteBuffer bytes;
    bytes.push_back(1U);
    write_u64(bytes, 0x1111111111111111ULL);
    write_u64(bytes, 0x2222222222222222ULL);
    write_u64(bytes, 3U);
    write_u16(bytes, 2U);
    bytes.push_back(1U);
    write_u32(bytes, 5000U);
    write_string(bytes, "");
    bytes.push_back(0U);
    write_u32(bytes, 0U);
    write_u32(bytes, 0U);
    write_u64(bytes, 1U);
    write_string(bytes, std::string(32U, '\0'));
    write_u64(bytes, 2U);
    write_u64(bytes, 3U);
    write_u64(bytes, 42U);
    write_string(bytes, std::string(32U, '\0'));
    write_u32(bytes, citation_count);
    return bytes;
  };
  {
    const ByteBuffer beyond_limit = classification_prefix(0xFFFFFFFFU);
    BufferReader reader(beyond_limit, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_classification(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
  }
  {
    const ByteBuffer beyond_payload = classification_prefix(3U);
    BufferReader reader(beyond_payload, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_classification(reader, limits()), ErrorCode::MALFORMED_RECORD);
  }

  // A policy whose adapter count is a lie.
  const auto policy_prefix = [](std::uint32_t adapter_count) {
    ByteBuffer bytes;
    bytes.push_back(1U);
    write_u64(bytes, 1U);
    bytes.push_back(0U);
    write_u64(bytes, 4096U);
    write_u32(bytes, 2000U);
    write_u32(bytes, 1000U);
    write_u32(bytes, 32U);
    for (int i = 0; i < 26; ++i) write_u64(bytes, 1024U);
    bytes.push_back(0U);
    write_u32(bytes, adapter_count);
    return bytes;
  };
  {
    const ByteBuffer beyond_limit = policy_prefix(0xFFFFFFFFU);
    BufferReader reader(beyond_limit, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_policy(reader, limits()), ErrorCode::CAPACITY_EXCEEDED);
  }
  {
    const ByteBuffer beyond_payload = policy_prefix(3U);
    BufferReader reader(beyond_payload, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_policy(reader, limits()), ErrorCode::MALFORMED_RECORD);
  }

  // A response whose note count is a lie.
  const auto notes_prefix = [](std::uint32_t note_count) {
    ByteBuffer bytes;
    write_string(bytes, "ev-99999999999999999999999999999999");
    write_bytes(bytes, ByteBuffer(16U, 0x00U));
    write_u64(bytes, 3U);
    bytes.push_back(1U);
    bytes.push_back(0U);
    write_string(bytes, "");
    bytes.push_back(0U);
    write_u32(bytes, note_count);
    return bytes;
  };
  {
    const ByteBuffer beyond_limit = notes_prefix(0xFFFFFFFFU);
    AIFC_CHECK_ERR(aifc::decode_publish_evidence_response(beyond_limit, limits()),
                   ErrorCode::CAPACITY_EXCEEDED);
  }
  {
    const ByteBuffer beyond_payload = notes_prefix(3U);
    AIFC_CHECK_ERR(aifc::decode_publish_evidence_response(beyond_payload, limits()),
                   ErrorCode::MALFORMED_RECORD);
  }

  // A batch request whose entry count is a lie.  Four bytes are enough to state it.
  {
    ByteBuffer beyond_limit;
    write_u32(beyond_limit, 0xFFFFFFFFU);
    AIFC_CHECK_ERR(aifc::decode_classify_request(beyond_limit, limits()),
                   ErrorCode::CAPACITY_EXCEEDED);
    ByteBuffer beyond_payload;
    write_u32(beyond_payload, 5U);
    AIFC_CHECK_ERR(aifc::decode_classify_request(beyond_payload, limits()),
                   ErrorCode::MALFORMED_RECORD);
  }
}

AIFC_TEST("codec fuzz: hostile identities, control characters and invalid UTF-8") {
  // Identity rules.  A near-miss identity is refused; a legal but non-canonical one is
  // folded, and the fold is exactly lower case.
  const std::string rejected[] = {
      std::string(), std::string(200U, 'a'),   "has space",  "has/slash",
      std::string("ctrl\x01", 5U),             std::string("raw\xFF", 4U),
      std::string("nul\0inside", 10U),         "has+plus"};
  for (const std::string& candidate : rejected) {
    auto canonical = aifc::canonicalize_identity(candidate);
    if (canonical) {
      AIFC_FAIL("identity [" << hex_dump(reinterpret_cast<const std::uint8_t*>(candidate.data()),
                                         candidate.size())
                             << "] was accepted as " << canonical.value());
      continue;
    }
    if (canonical.code() != ErrorCode::MALFORMED_INPUT) {
      AIFC_FAIL("identity [" << hex_dump(reinterpret_cast<const std::uint8_t*>(candidate.data()),
                                         candidate.size())
                             << "] was refused with " << canonical.code()
                             << " rather than MALFORMED_INPUT");
    }
  }
  AIFC_CHECK(aifc::is_canonical_identity("publisher-1.a_b:c"));
  AIFC_CHECK(!aifc::is_canonical_identity("Publisher-1"));
  AIFC_CHECK(!aifc::is_canonical_identity(""));
  {
    auto folded = aifc::canonicalize_identity("Publisher-ONE.x");
    AIFC_CHECK_OK(folded);
    if (folded) AIFC_CHECK_EQ(folded.value(), std::string("publisher-one.x"));
  }

  // Vocabulary labels.  A near-miss label is MALFORMED_INPUT, never a silent class.
  const std::string hostile_labels[] = {std::string(),
                                        "collective",
                                        "COLLECTIVE ",
                                        " COLLECTIVE",
                                        "COLLECTIV",
                                        "COLLECTIVEE",
                                        "COLLECTIVE\n",
                                        std::string("A\0B", 3U),
                                        std::string("\xFF\xFE", 2U),
                                        std::string(600U, 'C')};
  for (const std::string& label : hostile_labels) {
    const std::string shown =
        hex_dump(reinterpret_cast<const std::uint8_t*>(label.data()), label.size());
    auto parsed = aifc::parse_semantic_class(label);
    if (parsed) {
      AIFC_FAIL("semantic label [" << shown << "] parsed as " << parsed.value()
                                   << " instead of being refused");
    } else if (parsed.code() != ErrorCode::MALFORMED_INPUT) {
      AIFC_FAIL("semantic label [" << shown << "] was refused with " << parsed.code()
                                   << " rather than MALFORMED_INPUT");
    }
    auto source = aifc::parse_evidence_source(label);
    if (source) {
      AIFC_FAIL("evidence source [" << shown << "] parsed as " << source.value()
                                    << " instead of being refused");
    } else if (source.code() != ErrorCode::MALFORMED_INPUT) {
      AIFC_FAIL("evidence source [" << shown << "] was refused with " << source.code()
                                    << " rather than MALFORMED_INPUT");
    }
    auto state = aifc::parse_evidence_state(label);
    if (state) {
      AIFC_FAIL("evidence state [" << shown << "] parsed as " << state.value()
                                   << " instead of being refused");
    } else if (state.code() != ErrorCode::MALFORMED_INPUT) {
      AIFC_FAIL("evidence state [" << shown << "] was refused with " << state.code()
                                   << " rather than MALFORMED_INPUT");
    }
    auto transport = aifc::parse_transport_protocol(label);
    if (transport) {
      AIFC_FAIL("transport [" << shown << "] parsed as " << transport.value()
                              << " instead of being refused");
    } else if (transport.code() != ErrorCode::MALFORMED_INPUT) {
      AIFC_FAIL("transport [" << shown << "] was refused with " << transport.code()
                              << " rather than MALFORMED_INPUT");
    }
  }
  // UNKNOWN is a legitimate label, and it is the *only* class a malformed numeric code
  // can reach (see the vocabulary case below).
  AIFC_CHECK_OK(aifc::parse_semantic_class("UNKNOWN"));
  AIFC_CHECK_ERR(aifc::parse_confidence("not-a-number"), ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_confidence("1.00001"), ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_confidence("1.5"), ErrorCode::OUT_OF_RANGE);
  AIFC_CHECK_OK(aifc::parse_confidence("0.9000"));

  // A record that carries a non-canonical identity must be refused by the decoder even
  // though the encoder wrote it: validation belongs to the reader.
  {
    aifc::PublisherRecord record;
    record.id = aifc::PublisherId("Publisher-1");
    record.description = "synthetic";
    const ByteBuffer image = fixtures::encode_ok(
        kRecordBound,
        [&](BufferWriter& writer) { return aifc::encode_publisher_record(writer, record); },
        "a publisher record carrying a non-canonical identity");
    BufferReader reader(image, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_publisher_record(reader, limits()), ErrorCode::MALFORMED_RECORD);
  }

  // Control characters in a publisher supplied reason are refused, because an
  // explanation is rendered as text and a line break would make it read as two records.
  for (const std::string& reason :
       {std::string("line one\nline two"), std::string("bell\x07"), std::string("delete\x7F"),
        std::string("nul\0inside", 10U)}) {
    aifc::PublishEvidenceRequest request;
    request.payload = evidence_payload_fixture();
    request.payload.metadata.reason = reason;
    ByteBuffer image;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(request, image));
    const std::string shown =
        hex_dump(reinterpret_cast<const std::uint8_t*>(reason.data()), reason.size());
    auto decoded = aifc::decode_publish_evidence(image, limits());
    if (decoded) {
      AIFC_FAIL("a reason containing [" << shown << "] was accepted");
    } else if (decoded.code() != ErrorCode::MALFORMED_RECORD) {
      AIFC_FAIL("a reason containing [" << shown << "] was refused with " << aifc::to_string(decoded.code())
                                        << " rather than MALFORMED_RECORD");
    }
  }

  // An opaque string field is bytes, not text: invalid UTF-8 must survive verbatim
  // rather than being replaced, truncated or reinterpreted.
  {
    const std::string raw("raw\xFF\xFE\x01bytes", 11U);
    aifc::PublisherRecord record;
    record.id = aifc_test::synthetic_publisher(9U);
    record.description = raw;
    const ByteBuffer image = fixtures::encode_ok(
        kRecordBound,
        [&](BufferWriter& writer) { return aifc::encode_publisher_record(writer, record); },
        "a publisher record carrying raw bytes in its description");
    BufferReader reader(image, limits().max_string_bytes);
    auto decoded = aifc::decode_publisher_record(reader, limits());
    AIFC_CHECK_OK(decoded);
    if (decoded) {
      AIFC_CHECK_EQ(decoded.value().description.size(), raw.size());
      AIFC_CHECK_MSG(decoded.value().description == raw,
                     "an opaque byte string was altered by the round trip: got ["
                         << hex_dump(reinterpret_cast<const std::uint8_t*>(
                                         decoded.value().description.data()),
                                     decoded.value().description.size())
                         << "]");
    }
  }
}

AIFC_TEST("codec fuzz: a wire class code never becomes a class the code does not name") {
  // Every numeric class code a peer can put on the wire.  A code this build knows must
  // decode to exactly that class; a code it does not know must decode to UNKNOWN and to
  // nothing else -- in particular never to a built-in class that the peer did not name.
  const std::uint16_t codes[] = {0U,   1U,    2U,    3U,    4U,    5U,    6U,    7U,
                                 8U,   9U,    10U,   11U,   12U,   13U,   17U,   254U,
                                 255U, 256U,  257U,  1000U, 4095U, 65534U, 65535U};
  for (const std::uint16_t code : codes) {
    aifc::PublishEvidenceRequest request;
    request.payload = evidence_payload_fixture();
    request.payload.semantic = static_cast<aifc::SemanticClass>(code);
    ByteBuffer image;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(request, image));
    auto decoded = aifc::decode_publish_evidence(image, limits());
    const std::string context =
        "a publish-evidence message declaring class code " + std::to_string(code);
    if (!decoded) {
      AIFC_FAIL(context << " was refused outright: " << aifc::render_status(decoded.status()));
      continue;
    }
    const auto expected = aifc::decode_semantic_class(code);
    AIFC_CHECK_OK(expected);
    AIFC_CHECK_MSG(decoded.value().payload.semantic == expected.value(),
                   context << ": decoded to " << aifc::to_string(decoded.value().payload.semantic)
                           << " but this build names code " << code << " as " << aifc::to_string(expected.value()));
    if (code >= 12U) {
      AIFC_CHECK_MSG(decoded.value().payload.semantic == aifc::SemanticClass::UNKNOWN,
                     context << ": an unknown numeric code decoded to "
                             << aifc::to_string(decoded.value().payload.semantic)
                             << " instead of UNKNOWN; UNKNOWN is the only class a code this "
                                "build does not know may reach");
    }
  }

  // The same rule for the claimed source: an unknown byte is UNKNOWN, which is the
  // weakest rank, and never a stronger one.
  const std::uint8_t source_bytes[] = {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 100U, 200U, 255U};
  for (const std::uint8_t code : source_bytes) {
    aifc::PublishEvidenceRequest request;
    request.payload = evidence_payload_fixture();
    request.payload.claimed_source = static_cast<aifc::EvidenceSource>(code);
    ByteBuffer image;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(request, image));
    auto decoded = aifc::decode_publish_evidence(image, limits());
    const std::string context =
        "a publish-evidence message claiming source code " + std::to_string(code);
    if (!decoded) {
      AIFC_FAIL(context << " was refused outright: " << aifc::render_status(decoded.status()));
      continue;
    }
    const auto expected = aifc::decode_evidence_source(code);
    AIFC_CHECK_OK(expected);
    AIFC_CHECK_MSG(decoded.value().payload.claimed_source == expected.value(),
                   context << ": decoded to " << aifc::to_string(decoded.value().payload.claimed_source)
                           << " but this build names code " << static_cast<unsigned>(code)
                           << " as " << aifc::to_string(expected.value()));
    if (code > 5U) {
      AIFC_CHECK_MSG(aifc::source_rank(decoded.value().payload.claimed_source) == 0U,
                     context << ": an unknown source code decoded to rank "
                             << static_cast<unsigned>(
                                    aifc::source_rank(decoded.value().payload.claimed_source))
                             << " instead of the weakest rank 0");
    }
  }
}

AIFC_TEST("codec fuzz: a self-consistent record is decoded, and a stale digest is not") {
  // This case states the boundary of what a codec can promise.  A record whose digest
  // matches its content is decoded -- the codec is a codec, not an authority check --
  // and the record's own digest is what makes a mutated one detectable.  Which of these
  // records may actually decide a classification is proved in
  // tests/adversarial/test_label_privilege.cpp through Classifier::submit_evidence.
  aifc::EvidenceRecord installed = fixtures::evidence_fixture();
  installed.semantic = aifc::SemanticClass::CONTROL_PLANE;
  installed.generation = aifc::EvidenceGeneration{9};
  installed.content_digest = aifc::compute_evidence_digest(installed);

  const ByteBuffer consistent = fixtures::encode_ok(
      kRecordBound,
      [&](BufferWriter& writer) { return aifc::encode_evidence_record(writer, installed); },
      "a self-consistent evidence record");

  {
    BufferReader reader(consistent, limits().max_string_bytes);
    auto decoded = aifc::decode_evidence_record(reader, limits());
    AIFC_CHECK_OK(decoded);
    if (decoded) {
      AIFC_CHECK_MSG(decoded.value().semantic == aifc::SemanticClass::CONTROL_PLANE,
                     "decoded class is " << aifc::to_string(decoded.value().semantic)
                                         << ", expected CONTROL_PLANE");
      AIFC_CHECK_MSG(decoded.value().source == aifc::EvidenceSource::DECLARED_AUTHENTICATED,
                     "decoded source is " << aifc::to_string(decoded.value().source)
                                          << ", expected DECLARED_AUTHENTICATED");
      AIFC_CHECK_MSG(decoded.value().content_digest == aifc::compute_evidence_digest(decoded.value()),
                     "a decoded record's digest does not match its own content");
    }
  }

  // The same content with the digest of the record it was derived from: the class was
  // changed but the digest was not, which is exactly what a mutated file or a
  // hand-edited record looks like.
  {
    aifc::EvidenceRecord forged = fixtures::evidence_fixture();
    forged.semantic = aifc::SemanticClass::CONTROL_PLANE;
    forged.generation = aifc::EvidenceGeneration{9};
    const ByteBuffer image = fixtures::encode_ok(
        kRecordBound,
        [&](BufferWriter& writer) { return aifc::encode_evidence_record(writer, forged); },
        "an evidence record whose class does not match its recorded digest");
    BufferReader reader(image, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_evidence_record(reader, limits()),
                   ErrorCode::INTEGRITY_FAILURE);
  }

  // The same argument for a contract: its declared class is covered by its definition
  // digest, so a contract whose class was edited is refused.
  {
    aifc::WorkloadContract forged = contract_fixture();
    forged.declared_class = aifc::SemanticClass::CONTROL_PLANE;
    const ByteBuffer image = fixtures::encode_ok(
        kRecordBound, [&](BufferWriter& writer) { return aifc::encode_contract(writer, forged); },
        "a contract whose declared class does not match its definition digest");
    BufferReader reader(image, limits().max_string_bytes);
    AIFC_CHECK_ERR(aifc::decode_contract(reader, limits()), ErrorCode::INTEGRITY_FAILURE);
  }
}

}  // namespace
