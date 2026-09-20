// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/codec/record_codec.hpp"

#include <algorithm>
#include <string>
#include <tuple>
#include <vector>

#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

// Every record begins with its own schema version so that a future format change is
// detectable rather than silently misread.
constexpr std::uint8_t kEvidenceSchema = 1;
constexpr std::uint8_t kFlowSchema = 1;
constexpr std::uint8_t kPublisherSchema = 1;
constexpr std::uint8_t kWorkloadSchema = 1;
constexpr std::uint8_t kContractSchema = 1;
constexpr std::uint8_t kClassificationSchema = 1;
constexpr std::uint8_t kRevocationSchema = 1;
constexpr std::uint8_t kSupersessionSchema = 1;
constexpr std::uint8_t kPolicySchema = 1;

[[nodiscard]] Status skip_version(BufferReader& reader, std::uint8_t expected,
                                  std::string_view what) {
  Result<std::uint8_t> version = reader.get_u8();
  if (!version) return version.status();
  if (version.value() != expected) {
    return Status::failure(ErrorCode::UNSUPPORTED_VERSION,
                           std::string(what) + " schema version " +
                               std::to_string(version.value()) + " is not supported by this build");
  }
  return Status::success();
}

[[nodiscard]] Status encode_publisher_id(BufferWriter& writer, const PublisherId& id) {
  return writer.put_string(id.value());
}

[[nodiscard]] Result<PublisherId> decode_publisher_id(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "publisher identity is not canonical: " + text.value());
  }
  return make_publisher_id(text.value());
}

[[nodiscard]] Result<WorkloadId> decode_workload_id(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!text.value().empty() && !is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "workload identity is not canonical: " + text.value());
  }
  return make_workload_id(text.value());
}

[[nodiscard]] Result<EvidenceId> decode_evidence_id(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "evidence identity is not canonical: " + text.value());
  }
  return make_evidence_id(text.value());
}

[[nodiscard]] Result<ContractId> decode_contract_id(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!text.value().empty() && !is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "contract identity is not canonical: " + text.value());
  }
  return make_contract_id(text.value());
}

[[nodiscard]] Result<SessionId> decode_session_id(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!text.value().empty() && !is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "session identity is not canonical: " + text.value());
  }
  return SessionId(text.value());
}

[[nodiscard]] Status encode_semantic(BufferWriter& writer, SemanticClass value) {
  return writer.put_u16(static_cast<std::uint16_t>(value));
}

[[nodiscard]] Result<SemanticClass> decode_semantic(BufferReader& reader) {
  Result<std::uint16_t> code = reader.get_u16();
  if (!code) return code.status();
  return decode_semantic_class(code.value());
}

[[nodiscard]] Result<EvidenceSource> decode_source(BufferReader& reader) {
  Result<std::uint8_t> code = reader.get_u8();
  if (!code) return code.status();
  return decode_evidence_source(code.value());
}

[[nodiscard]] Result<EvidenceState> decode_state(BufferReader& reader) {
  Result<std::uint8_t> code = reader.get_u8();
  if (!code) return code.status();
  switch (code.value()) {
    case 0:
      return EvidenceState::EVIDENCE_NONE;
    case 1:
      return EvidenceState::EVIDENCE_CURRENT;
    case 2:
      return EvidenceState::EVIDENCE_STALE;
    case 3:
      return EvidenceState::EVIDENCE_SUPERSEDED;
    case 4:
      return EvidenceState::EVIDENCE_REVOKED;
    case 5:
      return EvidenceState::EVIDENCE_INSUFFICIENT;
    case 6:
      return EvidenceState::EVIDENCE_REJECTED;
    default:
      // An unrecognised state is NOT a trustworthy state, so it decodes to the
      // weakest one rather than to CURRENT.
      return EvidenceState::EVIDENCE_REJECTED;
  }
}

[[nodiscard]] Result<ClassificationState> decode_classification_state(BufferReader& reader) {
  Result<std::uint8_t> code = reader.get_u8();
  if (!code) return code.status();
  switch (code.value()) {
    case 0:
      return ClassificationState::UNKNOWN;
    case 1:
      return ClassificationState::CURRENT;
    case 2:
      return ClassificationState::CORROBORATED;
    case 3:
      return ClassificationState::CONTRADICTED;
    case 4:
      return ClassificationState::STALE;
    case 5:
      return ClassificationState::INSUFFICIENT;
    case 6:
      return ClassificationState::REVOKED;
    default:
      // An unknown classification state is treated as INSUFFICIENT, which reports the
      // class without claiming current authority.
      return ClassificationState::INSUFFICIENT;
  }
}

[[nodiscard]] Result<EvidenceDisposition> decode_disposition(BufferReader& reader) {
  Result<std::uint8_t> code = reader.get_u8();
  if (!code) return code.status();
  if (code.value() > 9U) return EvidenceDisposition::REJECTED;
  return static_cast<EvidenceDisposition>(code.value());
}

[[nodiscard]] Result<TransportProtocol> decode_transport(BufferReader& reader) {
  Result<std::uint8_t> code = reader.get_u8();
  if (!code) return code.status();
  return decode_transport_protocol(code.value());
}

}  // namespace

CodecLimits CodecLimits::from(const ResourceLimits& limits) noexcept {
  const ResourceLimits clamped = limits.effective();
  CodecLimits out;
  out.max_string_bytes = clamped.max_string_bytes;
  out.max_blob_bytes = clamped.max_blob_bytes;
  out.max_collection_count = clamped.max_collection_count;
  return out;
}

// --- primitives ------------------------------------------------------------

Status encode_flow_key(BufferWriter& writer, const FlowKey& key) {
  Status status = writer.put_u8(static_cast<std::uint8_t>(key.transport));
  if (status) status = writer.put_blob(key.local_address.bytes.data(), key.local_address.bytes.size());
  if (status)
    status = writer.put_blob(key.remote_address.bytes.data(), key.remote_address.bytes.size());
  if (status) status = writer.put_u16(key.local_port);
  if (status) status = writer.put_u16(key.remote_port);
  return status;
}

Result<FlowKey> decode_flow_key(BufferReader& reader) {
  FlowKey key;
  Result<std::uint8_t> transport = reader.get_u8();
  if (!transport) return transport.status();
  Result<TransportProtocol> protocol = decode_transport_protocol(transport.value());
  if (!protocol) return protocol.status();
  key.transport = protocol.value();
  for (IpAddress* address : {&key.local_address, &key.remote_address}) {
    Result<ByteBuffer> raw = reader.get_blob(16);
    if (!raw) return raw.status();
    if (raw.value().size() != 16) {
      return Status::failure(ErrorCode::MALFORMED_RECORD,
                             "address field must be exactly 16 bytes, saw " +
                                 std::to_string(raw.value().size()));
    }
    std::copy(raw.value().begin(), raw.value().end(), address->bytes.begin());
  }
  Result<std::uint16_t> local_port = reader.get_u16();
  if (!local_port) return local_port.status();
  key.local_port = local_port.value();
  Result<std::uint16_t> remote_port = reader.get_u16();
  if (!remote_port) return remote_port.status();
  key.remote_port = remote_port.value();
  return key;
}

Status encode_id128(BufferWriter& writer, const Id128& id) {
  Status status = writer.put_u64(id.hi);
  if (status) status = writer.put_u64(id.lo);
  return status;
}

Result<Id128> decode_id128(BufferReader& reader) {
  Id128 id;
  Result<std::uint64_t> hi = reader.get_u64();
  if (!hi) return hi.status();
  Result<std::uint64_t> lo = reader.get_u64();
  if (!lo) return lo.status();
  id.hi = hi.value();
  id.lo = lo.value();
  return id;
}

Status encode_digest(BufferWriter& writer, const Digest256& digest) {
  return writer.put_blob(digest.bytes, Digest256::kBytes);
}

Result<Digest256> decode_digest(BufferReader& reader) {
  Result<ByteBuffer> raw = reader.get_blob(Digest256::kBytes);
  if (!raw) return raw.status();
  if (raw.value().size() != Digest256::kBytes) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "digest field must be exactly 32 bytes");
  }
  Digest256 digest;
  std::copy(raw.value().begin(), raw.value().end(), digest.bytes);
  return digest;
}

Status encode_confidence(BufferWriter& writer, Confidence confidence) {
  return writer.put_u32(confidence.basis_points());
}

Result<Confidence> decode_confidence(BufferReader& reader) {
  Result<std::uint32_t> basis_points = reader.get_u32();
  if (!basis_points) return basis_points.status();
  if (basis_points.value() > Confidence::kScale) {
    // A confidence above 1.0 is not clamped: clamping would let a peer ask for
    // maximum confidence with an absurd number instead of failing.
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "confidence basis points " + std::to_string(basis_points.value()) +
                               " exceed the fixed point scale of " +
                               std::to_string(Confidence::kScale));
  }
  return Confidence::from_basis_points(basis_points.value());
}

// --- domain records --------------------------------------------------------

Status encode_evidence_record(BufferWriter& writer, const EvidenceRecord& record) {
  Status status = writer.put_u8(kEvidenceSchema);
  if (status) status = writer.put_string(record.id.value());
  if (status) status = encode_publisher_id(writer, record.publisher);
  if (status) status = writer.put_u64(record.publisher_boot.value);
  if (status) status = writer.put_string(record.session.value());
  if (status) status = writer.put_u64(record.accepted_epoch.value);
  if (status) status = writer.put_u64(record.accepted_boot.value);
  if (status) status = writer.put_string(record.workload.value());
  if (status) status = writer.put_u64(record.workload_generation.value);
  if (status) status = writer.put_string(record.contract.value());
  if (status) status = encode_id128(writer, record.flow_id);
  if (status) status = writer.put_u64(record.flow_generation.value);
  if (status) status = writer.put_u64(record.generation.value);
  if (status) status = writer.put_u64(record.accepted_seq);
  if (status) status = writer.put_u64(record.accepted_tick);
  if (status) status = writer.put_u64(record.fresh_until);
  if (status) status = encode_semantic(writer, record.semantic);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(record.source));
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(record.state));
  if (status) status = encode_confidence(writer, record.confidence);
  if (status) status = writer.put_string(record.metadata.topic);
  if (status) status = writer.put_u64(record.metadata.binding);
  if (status) status = writer.put_string(record.metadata.reason);
  if (status) status = writer.put_string(record.metadata.contract.value());
  if (status) status = encode_digest(writer, record.content_digest);
  if (status) status = writer.put_string(record.state_reason);
  return status;
}

Result<EvidenceRecord> decode_evidence_record(BufferReader& reader, const CodecLimits& limits) {
  (void)limits;
  Status status = skip_version(reader, kEvidenceSchema, "evidence record");
  if (!status) return status;
  EvidenceRecord record;
  Result<std::string> id = reader.get_string();
  if (!id) return id.status();
  if (!is_canonical_identity(id.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "evidence identity is not canonical");
  }
  record.id = make_evidence_id(id.value());
  Result<PublisherId> publisher = decode_publisher_id(reader);
  if (!publisher) return publisher.status();
  record.publisher = publisher.value();
  Result<std::uint64_t> boot = reader.get_u64();
  if (!boot) return boot.status();
  record.publisher_boot = PublisherBootId{boot.value()};
  Result<SessionId> session = decode_session_id(reader);
  if (!session) return session.status();
  record.session = session.value();
  Result<std::uint64_t> epoch = reader.get_u64();
  if (!epoch) return epoch.status();
  record.accepted_epoch = CoordinatorEpoch{epoch.value()};
  Result<std::uint64_t> accepted_boot = reader.get_u64();
  if (!accepted_boot) return accepted_boot.status();
  record.accepted_boot = CoordinatorBootId{accepted_boot.value()};
  Result<WorkloadId> workload = decode_workload_id(reader);
  if (!workload) return workload.status();
  record.workload = workload.value();
  Result<std::uint64_t> workload_generation = reader.get_u64();
  if (!workload_generation) return workload_generation.status();
  record.workload_generation = WorkloadGeneration{workload_generation.value()};
  Result<ContractId> contract = decode_contract_id(reader);
  if (!contract) return contract.status();
  record.contract = contract.value();
  Result<Id128> flow_id = decode_id128(reader);
  if (!flow_id) return flow_id.status();
  record.flow_id = flow_id.value();
  Result<std::uint64_t> flow_generation = reader.get_u64();
  if (!flow_generation) return flow_generation.status();
  record.flow_generation = FlowGeneration{flow_generation.value()};
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  record.generation = EvidenceGeneration{generation.value()};
  Result<std::uint64_t> seq = reader.get_u64();
  if (!seq) return seq.status();
  record.accepted_seq = seq.value();
  Result<std::uint64_t> accepted_tick = reader.get_u64();
  if (!accepted_tick) return accepted_tick.status();
  record.accepted_tick = accepted_tick.value();
  Result<std::uint64_t> fresh_until = reader.get_u64();
  if (!fresh_until) return fresh_until.status();
  record.fresh_until = fresh_until.value();
  Result<SemanticClass> semantic = decode_semantic(reader);
  if (!semantic) return semantic.status();
  record.semantic = semantic.value();
  Result<EvidenceSource> source = decode_source(reader);
  if (!source) return source.status();
  record.source = source.value();
  Result<EvidenceState> state = decode_state(reader);
  if (!state) return state.status();
  record.state = state.value();
  Result<Confidence> confidence = decode_confidence(reader);
  if (!confidence) return confidence.status();
  record.confidence = confidence.value();
  Result<std::string> topic = reader.get_string();
  if (!topic) return topic.status();
  record.metadata.topic = topic.value();
  Result<std::uint64_t> binding = reader.get_u64();
  if (!binding) return binding.status();
  record.metadata.binding = binding.value();
  Result<std::string> reason = reader.get_string();
  if (!reason) return reason.status();
  record.metadata.reason = reason.value();
  Result<ContractId> metadata_contract = decode_contract_id(reader);
  if (!metadata_contract) return metadata_contract.status();
  record.metadata.contract = metadata_contract.value();
  Result<Digest256> digest = decode_digest(reader);
  if (!digest) return digest.status();
  record.content_digest = digest.value();
  Result<std::string> state_reason = reader.get_string();
  if (!state_reason) return state_reason.status();
  record.state_reason = state_reason.value();

  // A record whose declared digest does not match its content has been tampered with
  // or corrupted; either way it is not admissible.
  const Digest256 recomputed = compute_evidence_digest(record);
  if (recomputed != record.content_digest) {
    return Status::failure(ErrorCode::INTEGRITY_FAILURE,
                           "evidence " + record.id.value() +
                               " content does not match its recorded digest");
  }
  return record;
}

Status encode_flow_record(BufferWriter& writer, const FlowRecord& record) {
  Status status = writer.put_u8(kFlowSchema);
  if (status) status = encode_id128(writer, record.id);
  if (status) status = encode_flow_key(writer, record.key);
  if (status) status = writer.put_u64(record.generation.value);
  if (status) status = writer.put_u64(record.registered_seq);
  if (status) status = writer.put_u64(record.registered_tick);
  if (status) status = writer.put_u64(record.last_activity_tick);
  if (status) status = writer.put_string(record.registered_by.value());
  if (status) status = writer.put_u64(record.renewals);
  return status;
}

Result<FlowRecord> decode_flow_record(BufferReader& reader) {
  Status status = skip_version(reader, kFlowSchema, "flow record");
  if (!status) return status;
  FlowRecord record;
  Result<Id128> id = decode_id128(reader);
  if (!id) return id.status();
  record.id = id.value();
  Result<FlowKey> key = decode_flow_key(reader);
  if (!key) return key.status();
  record.key = key.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  record.generation = FlowGeneration{generation.value()};
  Result<std::uint64_t> seq = reader.get_u64();
  if (!seq) return seq.status();
  record.registered_seq = seq.value();
  Result<std::uint64_t> registered_tick = reader.get_u64();
  if (!registered_tick) return registered_tick.status();
  record.registered_tick = registered_tick.value();
  Result<std::uint64_t> last_activity = reader.get_u64();
  if (!last_activity) return last_activity.status();
  record.last_activity_tick = last_activity.value();
  Result<SessionId> session = decode_session_id(reader);
  if (!session) return session.status();
  record.registered_by = session.value();
  Result<std::uint64_t> renewals = reader.get_u64();
  if (!renewals) return renewals.status();
  record.renewals = renewals.value();

  // The identity is derived from the key, so a persisted record cannot carry an
  // identity that does not belong to its key.  A mismatch means the file was edited
  // or produced by a different identity scheme.
  const Id128 derived = derive_flow_id(record.key);
  if (derived != record.id) {
    return Status::failure(ErrorCode::CORRUPT_STATE,
                           "persisted flow identity does not match the identity derived from its "
                           "key");
  }
  if (!record.generation.valid()) {
    return Status::failure(ErrorCode::CORRUPT_STATE, "persisted flow generation is zero");
  }
  return record;
}

Status encode_publisher_record(BufferWriter& writer, const PublisherRecord& record) {
  Status status = writer.put_u8(kPublisherSchema);
  if (status) status = encode_publisher_id(writer, record.id);
  if (status) status = writer.put_u64(record.highest_boot.value);
  if (status) status = writer.put_u64(record.highest_generation.value);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(record.max_source));
  if (status) status = writer.put_u64(record.first_seen_tick);
  if (status) status = writer.put_u64(record.last_seen_wall_millis);
  if (status) status = writer.put_u64(record.total_evidence_accepted);
  if (status) status = writer.put_string(record.description);
  return status;
}

Result<PublisherRecord> decode_publisher_record(BufferReader& reader, const CodecLimits& limits) {
  (void)limits;
  Status status = skip_version(reader, kPublisherSchema, "publisher record");
  if (!status) return status;
  PublisherRecord record;
  Result<PublisherId> id = decode_publisher_id(reader);
  if (!id) return id.status();
  record.id = id.value();
  Result<std::uint64_t> boot = reader.get_u64();
  if (!boot) return boot.status();
  record.highest_boot = PublisherBootId{boot.value()};
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  record.highest_generation = EvidenceGeneration{generation.value()};
  Result<EvidenceSource> source = decode_source(reader);
  if (!source) return source.status();
  record.max_source = source.value();
  Result<std::uint64_t> first_seen = reader.get_u64();
  if (!first_seen) return first_seen.status();
  record.first_seen_tick = first_seen.value();
  Result<std::uint64_t> last_seen = reader.get_u64();
  if (!last_seen) return last_seen.status();
  record.last_seen_wall_millis = last_seen.value();
  Result<std::uint64_t> accepted = reader.get_u64();
  if (!accepted) return accepted.status();
  record.total_evidence_accepted = accepted.value();
  Result<std::string> description = reader.get_string();
  if (!description) return description.status();
  record.description = description.value();
  return record;
}

Status encode_workload_record(BufferWriter& writer, const WorkloadRecord& record) {
  Status status = writer.put_u8(kWorkloadSchema);
  if (status) status = writer.put_string(record.id.value());
  if (status) status = encode_publisher_id(writer, record.owner);
  if (status) status = writer.put_u64(record.generation.value);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(record.state));
  if (status) status = writer.put_string(record.active_contract.value());
  if (status) status = writer.put_u64(record.declared_tick);
  if (status) status = writer.put_u64(record.activated_tick);
  if (status) status = writer.put_u64(record.retired_tick);
  if (status) status = writer.put_string(record.description);
  return status;
}

Result<WorkloadRecord> decode_workload_record(BufferReader& reader, const CodecLimits& limits) {
  (void)limits;
  Status status = skip_version(reader, kWorkloadSchema, "workload record");
  if (!status) return status;
  WorkloadRecord record;
  Result<WorkloadId> id = decode_workload_id(reader);
  if (!id) return id.status();
  record.id = id.value();
  Result<PublisherId> owner = decode_publisher_id(reader);
  if (!owner) return owner.status();
  record.owner = owner.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  record.generation = WorkloadGeneration{generation.value()};
  if (!record.generation.valid()) {
    return Status::failure(ErrorCode::CORRUPT_STATE, "persisted workload generation is zero");
  }
  Result<std::uint8_t> state = reader.get_u8();
  if (!state) return state.status();
  if (state.value() > 2U) {
    return Status::failure(ErrorCode::CORRUPT_STATE, "persisted workload state is undefined");
  }
  record.state = static_cast<WorkloadState>(state.value());
  Result<ContractId> contract = decode_contract_id(reader);
  if (!contract) return contract.status();
  record.active_contract = contract.value();
  Result<std::uint64_t> declared = reader.get_u64();
  if (!declared) return declared.status();
  record.declared_tick = declared.value();
  Result<std::uint64_t> activated = reader.get_u64();
  if (!activated) return activated.status();
  record.activated_tick = activated.value();
  Result<std::uint64_t> retired = reader.get_u64();
  if (!retired) return retired.status();
  record.retired_tick = retired.value();
  Result<std::string> description = reader.get_string();
  if (!description) return description.status();
  record.description = description.value();
  return record;
}

Status encode_contract(BufferWriter& writer, const WorkloadContract& contract) {
  Status status = writer.put_u8(kContractSchema);
  if (status) status = writer.put_string(contract.id.value());
  if (status) status = writer.put_string(contract.workload.value());
  if (status) status = writer.put_u64(contract.workload_generation.value);
  if (status) status = encode_publisher_id(writer, contract.owner);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(contract.state));
  if (status) status = encode_semantic(writer, contract.declared_class);
  if (status) status = writer.put_bool(contract.match_any_remote_address);
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(contract.remote_scope.size()));
  for (const IpAddress& address : contract.remote_scope) {
    if (!status) break;
    status = writer.put_blob(address.bytes.data(), address.bytes.size());
  }
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(contract.local_port_scope.size()));
  for (std::uint16_t port : contract.local_port_scope) {
    if (!status) break;
    status = writer.put_u16(port);
  }
  if (status) status = writer.put_u16(contract.remote_port);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(contract.transport));
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(contract.derived_source));
  if (status) status = encode_digest(writer, contract.definition_digest);
  if (status) status = writer.put_u64(contract.created_tick);
  if (status) status = writer.put_u64(contract.activated_tick);
  if (status) status = writer.put_u64(contract.retired_tick);
  if (status) status = writer.put_string(contract.description);
  return status;
}

Result<WorkloadContract> decode_contract(BufferReader& reader, const CodecLimits& limits) {
  Status status = skip_version(reader, kContractSchema, "workload contract");
  if (!status) return status;
  WorkloadContract contract;
  Result<ContractId> id = decode_contract_id(reader);
  if (!id) return id.status();
  contract.id = id.value();
  Result<WorkloadId> workload = decode_workload_id(reader);
  if (!workload) return workload.status();
  contract.workload = workload.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  contract.workload_generation = WorkloadGeneration{generation.value()};
  Result<PublisherId> owner = decode_publisher_id(reader);
  if (!owner) return owner.status();
  contract.owner = owner.value();
  Result<std::uint8_t> state = reader.get_u8();
  if (!state) return state.status();
  if (state.value() > 2U) {
    return Status::failure(ErrorCode::CORRUPT_STATE, "persisted contract state is undefined");
  }
  contract.state = static_cast<ContractState>(state.value());
  Result<SemanticClass> declared = decode_semantic(reader);
  if (!declared) return declared.status();
  contract.declared_class = declared.value();
  Result<bool> any_remote = reader.get_bool();
  if (!any_remote) return any_remote.status();
  contract.match_any_remote_address = any_remote.value();
  Result<std::uint32_t> remote_count = reader.get_count(limits.max_collection_count);
  if (!remote_count) return remote_count.status();
  contract.remote_scope.reserve(remote_count.value());
  for (std::uint32_t i = 0; i < remote_count.value(); ++i) {
    Result<ByteBuffer> raw = reader.get_blob(16);
    if (!raw) return raw.status();
    if (raw.value().size() != 16) {
      return Status::failure(ErrorCode::MALFORMED_RECORD,
                             "contract scope address must be exactly 16 bytes");
    }
    IpAddress address;
    std::copy(raw.value().begin(), raw.value().end(), address.bytes.begin());
    contract.remote_scope.push_back(address);
  }
  Result<std::uint32_t> port_count = reader.get_count(limits.max_collection_count);
  if (!port_count) return port_count.status();
  contract.local_port_scope.reserve(port_count.value());
  for (std::uint32_t i = 0; i < port_count.value(); ++i) {
    Result<std::uint16_t> port = reader.get_u16();
    if (!port) return port.status();
    contract.local_port_scope.push_back(port.value());
  }
  Result<std::uint16_t> remote_port = reader.get_u16();
  if (!remote_port) return remote_port.status();
  contract.remote_port = remote_port.value();
  Result<std::uint8_t> transport = reader.get_u8();
  if (!transport) return transport.status();
  Result<TransportProtocol> protocol = decode_transport_protocol(transport.value());
  if (!protocol) return protocol.status();
  contract.transport = protocol.value();
  Result<EvidenceSource> derived_source = decode_source(reader);
  if (!derived_source) return derived_source.status();
  contract.derived_source = derived_source.value();
  Result<Digest256> digest = decode_digest(reader);
  if (!digest) return digest.status();
  contract.definition_digest = digest.value();
  Result<std::uint64_t> created = reader.get_u64();
  if (!created) return created.status();
  contract.created_tick = created.value();
  Result<std::uint64_t> activated = reader.get_u64();
  if (!activated) return activated.status();
  contract.activated_tick = activated.value();
  Result<std::uint64_t> retired = reader.get_u64();
  if (!retired) return retired.status();
  contract.retired_tick = retired.value();
  Result<std::string> description = reader.get_string();
  if (!description) return description.status();
  contract.description = description.value();

  const Digest256 recomputed = compute_contract_digest(contract);
  if (!contract.definition_digest.is_zero() && recomputed != contract.definition_digest) {
    return Status::failure(ErrorCode::INTEGRITY_FAILURE,
                           "contract " + contract.id.value() +
                               " content does not match its recorded digest");
  }
  contract.definition_digest = recomputed;
  return contract;
}

Status encode_classification(BufferWriter& writer, const Classification& classification) {
  Status status = writer.put_u8(kClassificationSchema);
  if (status) status = encode_id128(writer, classification.flow_id);
  if (status) status = writer.put_u64(classification.flow_generation.value);
  if (status) status = encode_semantic(writer, classification.semantic);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(classification.state));
  if (status) status = encode_confidence(writer, classification.confidence);
  if (status) status = writer.put_string(classification.selected_evidence.value());
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(classification.selected_source));
  if (status) status = writer.put_u32(classification.corroboration_count);
  if (status) status = writer.put_u32(classification.applied_penalty_basis_points);
  if (status) status = writer.put_u64(classification.policy_generation.value);
  if (status) status = encode_digest(writer, classification.policy_digest);
  if (status) status = writer.put_u64(classification.coordinator_epoch.value);
  if (status) status = writer.put_u64(classification.coordinator_boot.value);
  if (status) status = writer.put_u64(classification.decided_tick);
  if (status) status = encode_digest(writer, classification.digest);

  if (status) status = writer.put_u32(static_cast<std::uint32_t>(classification.citations.size()));
  for (const EvidenceCitation& citation : classification.citations) {
    if (!status) break;
    status = writer.put_string(citation.id.value());
    if (status) status = writer.put_string(citation.publisher.value());
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(citation.source));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(citation.state));
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(citation.semantic));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(citation.disposition));
    if (status) status = encode_confidence(writer, citation.confidence);
    if (status) status = writer.put_u64(citation.generation.value);
    if (status) status = writer.put_u64(citation.accepted_seq);
    if (status) status = writer.put_u64(citation.accepted_tick);
    if (status) status = writer.put_u64(citation.fresh_until);
    if (status) status = writer.put_string(citation.detail);
  }

  if (status)
    status = writer.put_u32(static_cast<std::uint32_t>(classification.contradictions.size()));
  for (const ClassificationContradiction& contradiction : classification.contradictions) {
    if (!status) break;
    status = writer.put_string(contradiction.left_id.value());
    if (status) status = writer.put_string(contradiction.right_id.value());
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(contradiction.left_class));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(contradiction.left_source));
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(contradiction.right_class));
    if (status) status = writer.put_u8(static_cast<std::uint8_t>(contradiction.right_source));
    if (status) status = writer.put_string(contradiction.resolved_by);
  }
  return status;
}

Result<Classification> decode_classification(BufferReader& reader, const CodecLimits& limits) {
  Status status = skip_version(reader, kClassificationSchema, "classification");
  if (!status) return status;
  Classification classification;
  Result<Id128> flow_id = decode_id128(reader);
  if (!flow_id) return flow_id.status();
  classification.flow_id = flow_id.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  classification.flow_generation = FlowGeneration{generation.value()};
  Result<SemanticClass> semantic = decode_semantic(reader);
  if (!semantic) return semantic.status();
  classification.semantic = semantic.value();
  Result<ClassificationState> state = decode_classification_state(reader);
  if (!state) return state.status();
  classification.state = state.value();
  Result<Confidence> confidence = decode_confidence(reader);
  if (!confidence) return confidence.status();
  classification.confidence = confidence.value();
  Result<std::string> selected = reader.get_string();
  if (!selected) return selected.status();
  if (!selected.value().empty()) {
    if (!is_canonical_identity(selected.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "selected evidence id is not canonical");
    }
    classification.selected_evidence = make_evidence_id(selected.value());
  }
  Result<EvidenceSource> selected_source = decode_source(reader);
  if (!selected_source) return selected_source.status();
  classification.selected_source = selected_source.value();
  Result<std::uint32_t> corroboration = reader.get_u32();
  if (!corroboration) return corroboration.status();
  classification.corroboration_count = corroboration.value();
  Result<std::uint32_t> penalty = reader.get_u32();
  if (!penalty) return penalty.status();
  classification.applied_penalty_basis_points = penalty.value();
  Result<std::uint64_t> policy_generation = reader.get_u64();
  if (!policy_generation) return policy_generation.status();
  classification.policy_generation = ClassifierPolicyGeneration{policy_generation.value()};
  Result<Digest256> policy_digest = decode_digest(reader);
  if (!policy_digest) return policy_digest.status();
  classification.policy_digest = policy_digest.value();
  Result<std::uint64_t> epoch = reader.get_u64();
  if (!epoch) return epoch.status();
  classification.coordinator_epoch = CoordinatorEpoch{epoch.value()};
  Result<std::uint64_t> boot = reader.get_u64();
  if (!boot) return boot.status();
  classification.coordinator_boot = CoordinatorBootId{boot.value()};
  Result<std::uint64_t> decided_tick = reader.get_u64();
  if (!decided_tick) return decided_tick.status();
  classification.decided_tick = decided_tick.value();
  Result<Digest256> digest = decode_digest(reader);
  if (!digest) return digest.status();
  classification.digest = digest.value();

  Result<std::uint32_t> citation_count = reader.get_count(limits.max_collection_count);
  if (!citation_count) return citation_count.status();
  classification.citations.reserve(citation_count.value());
  for (std::uint32_t i = 0; i < citation_count.value(); ++i) {
    EvidenceCitation citation;
    Result<std::string> id = reader.get_string();
    if (!id) return id.status();
    if (!is_canonical_identity(id.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "citation evidence id is not canonical");
    }
    citation.id = make_evidence_id(id.value());
    Result<PublisherId> publisher = decode_publisher_id(reader);
    if (!publisher) return publisher.status();
    citation.publisher = publisher.value();
    Result<EvidenceSource> source = decode_source(reader);
    if (!source) return source.status();
    citation.source = source.value();
    Result<EvidenceState> citation_state = decode_state(reader);
    if (!citation_state) return citation_state.status();
    citation.state = citation_state.value();
    Result<SemanticClass> citation_semantic = decode_semantic(reader);
    if (!citation_semantic) return citation_semantic.status();
    citation.semantic = citation_semantic.value();
    Result<EvidenceDisposition> disposition = decode_disposition(reader);
    if (!disposition) return disposition.status();
    citation.disposition = disposition.value();
    Result<Confidence> citation_confidence = decode_confidence(reader);
    if (!citation_confidence) return citation_confidence.status();
    citation.confidence = citation_confidence.value();
    Result<std::uint64_t> citation_generation = reader.get_u64();
    if (!citation_generation) return citation_generation.status();
    citation.generation = EvidenceGeneration{citation_generation.value()};
    Result<std::uint64_t> accepted_seq = reader.get_u64();
    if (!accepted_seq) return accepted_seq.status();
    citation.accepted_seq = accepted_seq.value();
    Result<std::uint64_t> accepted_tick = reader.get_u64();
    if (!accepted_tick) return accepted_tick.status();
    citation.accepted_tick = accepted_tick.value();
    Result<std::uint64_t> fresh_until = reader.get_u64();
    if (!fresh_until) return fresh_until.status();
    citation.fresh_until = fresh_until.value();
    Result<std::string> detail = reader.get_string();
    if (!detail) return detail.status();
    citation.detail = detail.value();
    classification.citations.push_back(std::move(citation));
  }

  Result<std::uint32_t> contradiction_count = reader.get_count(limits.max_collection_count);
  if (!contradiction_count) return contradiction_count.status();
  classification.contradictions.reserve(contradiction_count.value());
  for (std::uint32_t i = 0; i < contradiction_count.value(); ++i) {
    ClassificationContradiction contradiction;
    Result<std::string> left = reader.get_string();
    if (!left) return left.status();
    Result<std::string> right = reader.get_string();
    if (!right) return right.status();
    if (!is_canonical_identity(left.value()) || !is_canonical_identity(right.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "contradiction citation id is not canonical");
    }
    contradiction.left_id = make_evidence_id(left.value());
    contradiction.right_id = make_evidence_id(right.value());
    Result<std::uint16_t> left_class = reader.get_u16();
    if (!left_class) return left_class.status();
    Result<SemanticClass> left_semantic = decode_semantic_class(left_class.value());
    if (!left_semantic) return left_semantic.status();
    contradiction.left_class = left_semantic.value();
    Result<EvidenceSource> left_source = decode_source(reader);
    if (!left_source) return left_source.status();
    contradiction.left_source = left_source.value();
    Result<std::uint16_t> right_class = reader.get_u16();
    if (!right_class) return right_class.status();
    Result<SemanticClass> right_semantic = decode_semantic_class(right_class.value());
    if (!right_semantic) return right_semantic.status();
    contradiction.right_class = right_semantic.value();
    Result<EvidenceSource> right_source = decode_source(reader);
    if (!right_source) return right_source.status();
    contradiction.right_source = right_source.value();
    Result<std::string> resolved = reader.get_string();
    if (!resolved) return resolved.status();
    contradiction.resolved_by = resolved.value();
    classification.contradictions.push_back(std::move(contradiction));
  }
  return classification;
}

Status encode_revocation(BufferWriter& writer, const RevocationRecord& record) {
  Status status = writer.put_u8(kRevocationSchema);
  if (status) status = encode_id128(writer, record.flow_id);
  if (status) status = writer.put_u64(record.flow_generation.value);
  if (status) status = writer.put_string(record.evidence_id.value());
  if (status) status = writer.put_string(record.revoked_by_session.value());
  if (status) status = writer.put_string(record.revoked_by_publisher.value());
  if (status) status = writer.put_u64(record.epoch.value);
  if (status) status = writer.put_u64(record.seq);
  if (status) status = writer.put_u64(record.revoked_tick);
  if (status) status = writer.put_string(record.reason);
  return status;
}

Result<RevocationRecord> decode_revocation(BufferReader& reader, const CodecLimits& limits) {
  (void)limits;
  Status status = skip_version(reader, kRevocationSchema, "revocation record");
  if (!status) return status;
  RevocationRecord record;
  Result<Id128> flow_id = decode_id128(reader);
  if (!flow_id) return flow_id.status();
  record.flow_id = flow_id.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  record.flow_generation = FlowGeneration{generation.value()};
  Result<std::string> evidence_id = reader.get_string();
  if (!evidence_id) return evidence_id.status();
  if (!evidence_id.value().empty()) {
    if (!is_canonical_identity(evidence_id.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "revocation evidence id is not canonical");
    }
    record.evidence_id = make_evidence_id(evidence_id.value());
  }
  Result<SessionId> session = decode_session_id(reader);
  if (!session) return session.status();
  record.revoked_by_session = session.value();
  Result<PublisherId> publisher = decode_publisher_id(reader);
  if (!publisher) return publisher.status();
  record.revoked_by_publisher = publisher.value();
  Result<std::uint64_t> epoch = reader.get_u64();
  if (!epoch) return epoch.status();
  record.epoch = CoordinatorEpoch{epoch.value()};
  Result<std::uint64_t> seq = reader.get_u64();
  if (!seq) return seq.status();
  record.seq = seq.value();
  Result<std::uint64_t> tick = reader.get_u64();
  if (!tick) return tick.status();
  record.revoked_tick = tick.value();
  Result<std::string> reason = reader.get_string();
  if (!reason) return reason.status();
  record.reason = reason.value();
  return record;
}

Status encode_supersession(BufferWriter& writer, const SupersessionRecord& record) {
  Status status = writer.put_u8(kSupersessionSchema);
  if (status) status = writer.put_string(record.previous_id.value());
  if (status) status = writer.put_string(record.replacement_id.value());
  if (status) status = writer.put_u64(record.previous_generation.value);
  if (status) status = writer.put_u64(record.replacement_generation.value);
  if (status) status = encode_publisher_id(writer, record.publisher);
  if (status) status = writer.put_u64(record.seq);
  if (status) status = writer.put_u64(record.recorded_tick);
  return status;
}

Result<SupersessionRecord> decode_supersession(BufferReader& reader, const CodecLimits& limits) {
  (void)limits;
  Status status = skip_version(reader, kSupersessionSchema, "supersession record");
  if (!status) return status;
  SupersessionRecord record;
  Result<std::string> previous = reader.get_string();
  if (!previous) return previous.status();
  Result<std::string> replacement = reader.get_string();
  if (!replacement) return replacement.status();
  if (!is_canonical_identity(previous.value()) || !is_canonical_identity(replacement.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "supersession evidence id is not canonical");
  }
  record.previous_id = make_evidence_id(previous.value());
  record.replacement_id = make_evidence_id(replacement.value());
  Result<std::uint64_t> previous_generation = reader.get_u64();
  if (!previous_generation) return previous_generation.status();
  record.previous_generation = EvidenceGeneration{previous_generation.value()};
  Result<std::uint64_t> replacement_generation = reader.get_u64();
  if (!replacement_generation) return replacement_generation.status();
  record.replacement_generation = EvidenceGeneration{replacement_generation.value()};
  Result<PublisherId> publisher = decode_publisher_id(reader);
  if (!publisher) return publisher.status();
  record.publisher = publisher.value();
  Result<std::uint64_t> seq = reader.get_u64();
  if (!seq) return seq.status();
  record.seq = seq.value();
  Result<std::uint64_t> tick = reader.get_u64();
  if (!tick) return tick.status();
  record.recorded_tick = tick.value();
  return record;
}

Status encode_policy(BufferWriter& writer, const ClassifierPolicy& policy) {
  Status status = writer.put_u8(kPolicySchema);
  if (status) status = writer.put_u64(policy.generation.value);
  if (status) status = writer.put_bool(policy.allow_heuristic_evidence);
  if (status) status = writer.put_u64(policy.default_freshness_window);
  if (status) status = writer.put_u32(policy.contradiction_penalty);
  if (status) status = writer.put_u32(policy.minimum_publishable_confidence);
  if (status) status = writer.put_u32(policy.max_evidence_considered);

  const ResourceLimits& limits = policy.limits;
  const std::uint64_t fields[] = {limits.max_flows,
                                  limits.max_publishers,
                                  limits.max_workloads,
                                  limits.max_contracts,
                                  limits.max_pending_contracts,
                                  limits.max_sessions,
                                  limits.max_config_overrides,
                                  limits.max_evidence_per_flow,
                                  limits.max_evidence_records,
                                  limits.max_decisions_per_flow,
                                  limits.max_contradictions_per_flow,
                                  limits.max_contradictions,
                                  limits.max_supersessions,
                                  limits.max_revocations,
                                  limits.max_flow_key_index,
                                  limits.max_frame_payload,
                                  limits.max_string_bytes,
                                  limits.max_blob_bytes,
                                  limits.max_collection_count,
                                  limits.max_batch_keys,
                                  limits.max_workers,
                                  limits.max_queue_depth,
                                  limits.max_inflight_requests,
                                  limits.max_retry_attempts,
                                  limits.default_freshness_window,
                                  limits.max_session_idle_ticks};
  for (std::uint64_t value : fields) {
    if (!status) break;
    status = writer.put_u64(value);
  }

  if (status) status = writer.put_u32(static_cast<std::uint32_t>(policy.heuristic_adapters.size()));
  for (const HeuristicAdapterPolicy& adapter : policy.heuristic_adapters) {
    if (!status) break;
    status = writer.put_string(adapter.name);
    if (status) status = writer.put_bool(adapter.enabled);
    if (status) status = writer.put_u32(adapter.max_basis_points);
    if (status) status = writer.put_u32(adapter.priority);
  }
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(policy.port_hints.size()));
  for (const PortHint& hint : policy.port_hints) {
    if (!status) break;
    status = writer.put_u8(static_cast<std::uint8_t>(hint.transport));
    if (status) status = writer.put_u16(hint.port);
    if (status) status = writer.put_u16(static_cast<std::uint16_t>(hint.semantic));
    if (status) status = writer.put_u32(hint.basis_points);
    if (status) status = writer.put_string(hint.adapter);
  }
  return status;
}

Result<ClassifierPolicy> decode_policy(BufferReader& reader, const CodecLimits& limits) {
  Status status = skip_version(reader, kPolicySchema, "classifier policy");
  if (!status) return status;
  ClassifierPolicy policy;
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  policy.generation = ClassifierPolicyGeneration{generation.value()};
  Result<bool> heuristics = reader.get_bool();
  if (!heuristics) return heuristics.status();
  policy.allow_heuristic_evidence = heuristics.value();
  Result<std::uint64_t> freshness = reader.get_u64();
  if (!freshness) return freshness.status();
  policy.default_freshness_window = freshness.value();
  Result<std::uint32_t> penalty = reader.get_u32();
  if (!penalty) return penalty.status();
  policy.contradiction_penalty = penalty.value();
  Result<std::uint32_t> threshold = reader.get_u32();
  if (!threshold) return threshold.status();
  policy.minimum_publishable_confidence = threshold.value();
  Result<std::uint32_t> considered = reader.get_u32();
  if (!considered) return considered.status();
  policy.max_evidence_considered = considered.value();

  // Widths are read into a portable array, validated, and only then narrowed.  A
  // persisted limit that does not fit its field is corrupt state, not a value to be
  // silently truncated.
  constexpr std::size_t kLimitFields = 26;
  std::uint64_t fields[kLimitFields] = {};
  for (std::size_t i = 0; i < kLimitFields; ++i) {
    Result<std::uint64_t> value = reader.get_u64();
    if (!value) return value.status();
    fields[i] = value.value();
  }
  for (std::size_t i = 0; i < 24; ++i) {
    if (fields[i] > 0xFFFFFFFFULL) {
      return Status::failure(ErrorCode::CORRUPT_STATE,
                             "persisted resource limit " + std::to_string(i) +
                                 " does not fit in 32 bits");
    }
  }
  ResourceLimits& limits_out = policy.limits;
  limits_out.max_flows = static_cast<std::uint32_t>(fields[0]);
  limits_out.max_publishers = static_cast<std::uint32_t>(fields[1]);
  limits_out.max_workloads = static_cast<std::uint32_t>(fields[2]);
  limits_out.max_contracts = static_cast<std::uint32_t>(fields[3]);
  limits_out.max_pending_contracts = static_cast<std::uint32_t>(fields[4]);
  limits_out.max_sessions = static_cast<std::uint32_t>(fields[5]);
  limits_out.max_config_overrides = static_cast<std::uint32_t>(fields[6]);
  limits_out.max_evidence_per_flow = static_cast<std::uint32_t>(fields[7]);
  limits_out.max_evidence_records = static_cast<std::uint32_t>(fields[8]);
  limits_out.max_decisions_per_flow = static_cast<std::uint32_t>(fields[9]);
  limits_out.max_contradictions_per_flow = static_cast<std::uint32_t>(fields[10]);
  limits_out.max_contradictions = static_cast<std::uint32_t>(fields[11]);
  limits_out.max_supersessions = static_cast<std::uint32_t>(fields[12]);
  limits_out.max_revocations = static_cast<std::uint32_t>(fields[13]);
  limits_out.max_flow_key_index = static_cast<std::uint32_t>(fields[14]);
  limits_out.max_frame_payload = static_cast<std::uint32_t>(fields[15]);
  limits_out.max_string_bytes = static_cast<std::uint32_t>(fields[16]);
  limits_out.max_blob_bytes = static_cast<std::uint32_t>(fields[17]);
  limits_out.max_collection_count = static_cast<std::uint32_t>(fields[18]);
  limits_out.max_batch_keys = static_cast<std::uint32_t>(fields[19]);
  limits_out.max_workers = static_cast<std::uint32_t>(fields[20]);
  limits_out.max_queue_depth = static_cast<std::uint32_t>(fields[21]);
  limits_out.max_inflight_requests = static_cast<std::uint32_t>(fields[22]);
  limits_out.max_retry_attempts = static_cast<std::uint32_t>(fields[23]);
  limits_out.default_freshness_window = fields[24];
  limits_out.max_session_idle_ticks = fields[25];

  Result<std::uint32_t> adapter_count = reader.get_count(limits.max_collection_count);
  if (!adapter_count) return adapter_count.status();
  policy.heuristic_adapters.reserve(adapter_count.value());
  for (std::uint32_t i = 0; i < adapter_count.value(); ++i) {
    HeuristicAdapterPolicy adapter;
    Result<std::string> name = reader.get_string();
    if (!name) return name.status();
    adapter.name = name.value();
    Result<bool> enabled = reader.get_bool();
    if (!enabled) return enabled.status();
    adapter.enabled = enabled.value();
    Result<std::uint32_t> max_basis = reader.get_u32();
    if (!max_basis) return max_basis.status();
    adapter.max_basis_points = max_basis.value();
    Result<std::uint32_t> priority = reader.get_u32();
    if (!priority) return priority.status();
    adapter.priority = priority.value();
    policy.heuristic_adapters.push_back(std::move(adapter));
  }
  Result<std::uint32_t> hint_count = reader.get_count(limits.max_collection_count);
  if (!hint_count) return hint_count.status();
  policy.port_hints.reserve(hint_count.value());
  for (std::uint32_t i = 0; i < hint_count.value(); ++i) {
    PortHint hint;
    Result<std::uint8_t> transport = reader.get_u8();
    if (!transport) return transport.status();
    Result<TransportProtocol> protocol = decode_transport_protocol(transport.value());
    if (!protocol) return protocol.status();
    hint.transport = protocol.value();
    Result<std::uint16_t> port = reader.get_u16();
    if (!port) return port.status();
    hint.port = port.value();
    Result<std::uint16_t> semantic = reader.get_u16();
    if (!semantic) return semantic.status();
    Result<SemanticClass> parsed = decode_semantic_class(semantic.value());
    if (!parsed) return parsed.status();
    hint.semantic = parsed.value();
    Result<std::uint32_t> basis = reader.get_u32();
    if (!basis) return basis.status();
    hint.basis_points = basis.value();
    Result<std::string> adapter = reader.get_string();
    if (!adapter) return adapter.status();
    hint.adapter = adapter.value();
    policy.port_hints.push_back(std::move(hint));
  }

  // The decoded policy is re-canonicalised, so a persisted policy that is internally
  // contradictory is refused here rather than at first use.
  Result<ClassifierPolicy> canonical = ClassifierPolicy::canonicalize(std::move(policy));
  if (!canonical) {
    return Status::failure(ErrorCode::CORRUPT_STATE,
                           "persisted policy is not valid: " + canonical.status().message);
  }
  return canonical.value();
}

Status encode_classification_query(BufferWriter& writer, const FlowKey& key,
                                   FlowGeneration generation, bool explain) {
  Status status = encode_flow_key(writer, key);
  if (status) status = writer.put_u64(generation.value);
  if (status) status = writer.put_bool(explain);
  return status;
}

Result<std::tuple<FlowKey, FlowGeneration, bool>> decode_classification_query(
    BufferReader& reader) {
  Result<FlowKey> key = decode_flow_key(reader);
  if (!key) return key.status();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  Result<bool> explain = reader.get_bool();
  if (!explain) return explain.status();
  return std::make_tuple(key.value(), FlowGeneration{generation.value()}, explain.value());
}

std::string render_classification_json(const Classification& classification) {
  std::string out;
  out.reserve(512);
  out += "{\"flow_id\":\"";
  out += classification.flow_id.to_hex();
  out += "\",\"flow_generation\":";
  out += classification.flow_generation.to_string();
  out += ",\"semantic_class\":\"";
  out += to_string(classification.semantic);
  out += "\",\"state\":\"";
  out += to_string(classification.state);
  out += "\",\"confidence\":\"";
  out += classification.confidence.to_decimal();
  out += "\",\"selected_evidence\":\"";
  out += classification.selected_evidence.value();
  out += "\",\"selected_source\":\"";
  out += to_string(classification.selected_source);
  out += "\",\"corroboration_count\":";
  out += std::to_string(classification.corroboration_count);
  out += ",\"applied_penalty_basis_points\":";
  out += std::to_string(classification.applied_penalty_basis_points);
  out += ",\"policy_generation\":";
  out += classification.policy_generation.to_string();
  out += ",\"policy_digest\":\"";
  out += classification.policy_digest.to_hex();
  out += "\",\"coordinator_epoch\":";
  out += classification.coordinator_epoch.to_string();
  out += ",\"coordinator_boot\":";
  out += classification.coordinator_boot.to_string();
  out += ",\"decision_digest\":\"";
  out += classification.digest.to_hex();
  out += "\",\"evidence_considered\":";
  out += std::to_string(classification.citations.size());
  out += ",\"citations\":[";
  for (std::size_t i = 0; i < classification.citations.size(); ++i) {
    const EvidenceCitation& citation = classification.citations[i];
    if (i != 0) out += ',';
    out += "{\"id\":\"";
    out += citation.id.value();
    out += "\",\"publisher\":\"";
    out += citation.publisher.value();
    out += "\",\"source\":\"";
    out += to_string(citation.source);
    out += "\",\"evidence_state\":\"";
    out += to_string(citation.state);
    out += "\",\"semantic_class\":\"";
    out += to_string(citation.semantic);
    out += "\",\"disposition\":\"";
    out += to_string(citation.disposition);
    out += "\",\"confidence\":\"";
    out += citation.confidence.to_decimal();
    out += "\",\"generation\":";
    out += citation.generation.to_string();
    out += ",\"detail\":\"";
    // The detail is generated text from a bounded field; quotes and backslashes are
    // escaped so that the rendering is always valid JSON.
    for (char ch : citation.detail) {
      if (ch == '"' || ch == '\\') out.push_back('\\');
      if (ch == '\n' || ch == '\r' || ch == '\t') {
        out.push_back(' ');
        continue;
      }
      out.push_back(ch);
    }
    out += "\"}";
  }
  out += "],\"contradictions\":[";
  for (std::size_t i = 0; i < classification.contradictions.size(); ++i) {
    const ClassificationContradiction& contradiction = classification.contradictions[i];
    if (i != 0) out += ',';
    out += "{\"left\":\"";
    out += contradiction.left_id.value();
    out += "\",\"left_class\":\"";
    out += to_string(contradiction.left_class);
    out += "\",\"left_source\":\"";
    out += to_string(contradiction.left_source);
    out += "\",\"right\":\"";
    out += contradiction.right_id.value();
    out += "\",\"right_class\":\"";
    out += to_string(contradiction.right_class);
    out += "\",\"right_source\":\"";
    out += to_string(contradiction.right_source);
    out += "\",\"resolved_by\":\"";
    for (char ch : contradiction.resolved_by) {
      if (ch == '"' || ch == '\\') out.push_back('\\');
      out.push_back(ch);
    }
    out += "\"}";
  }
  out += "]}";
  return out;
}

}  // namespace aifc
