// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/protocol/messages.hpp"

#include <string>
#include <utility>
#include <vector>

namespace aifc {
namespace {

[[nodiscard]] Result<PeerRole> decode_peer_role(BufferReader& reader) {
  Result<std::uint8_t> code = reader.get_u8();
  if (!code) return code.status();
  if (code.value() == 1U) return PeerRole::PUBLISHER;
  if (code.value() == 2U) return PeerRole::CLIENT;
  return Status::failure(ErrorCode::MALFORMED_RECORD,
                         "peer role " + std::to_string(code.value()) + " is not defined");
}

[[nodiscard]] Result<PublisherId> decode_publisher(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "publisher identity is not canonical");
  }
  return make_publisher_id(text.value());
}

[[nodiscard]] Result<WorkloadId> decode_workload(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "workload identity is not canonical");
  }
  return make_workload_id(text.value());
}

[[nodiscard]] Result<ContractId> decode_contract(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "contract identity is not canonical");
  }
  return make_contract_id(text.value());
}

[[nodiscard]] Result<EvidenceId> decode_evidence(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "evidence identity is not canonical");
  }
  return make_evidence_id(text.value());
}

[[nodiscard]] Result<SessionId> decode_session(BufferReader& reader) {
  Result<std::string> text = reader.get_string();
  if (!text) return text.status();
  if (!text.value().empty() && !is_canonical_identity(text.value())) {
    return Status::failure(ErrorCode::MALFORMED_RECORD, "session identity is not canonical");
  }
  return SessionId(text.value());
}

[[nodiscard]] Status finish(BufferReader& reader) { return reader.finish(); }

}  // namespace

// --- HELLO -----------------------------------------------------------------

Status encode_hello(const HelloRequest& hello, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_u8(static_cast<std::uint8_t>(hello.role));
  if (status) status = writer.put_u16(hello.protocol_version);
  if (status) status = writer.put_u16(hello.protocol_version_min);
  if (status) status = writer.put_u32(hello.requested_flags);
  if (status) status = writer.put_string(hello.client_name);
  if (status) status = writer.put_string(hello.publisher.value());
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<HelloRequest> decode_hello(const ByteBuffer& payload, const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  HelloRequest hello;
  Result<PeerRole> role = decode_peer_role(reader);
  if (!role) return role.status();
  hello.role = role.value();
  Result<std::uint16_t> version = reader.get_u16();
  if (!version) return version.status();
  hello.protocol_version = version.value();
  Result<std::uint16_t> version_min = reader.get_u16();
  if (!version_min) return version_min.status();
  hello.protocol_version_min = version_min.value();
  Result<std::uint32_t> flags = reader.get_u32();
  if (!flags) return flags.status();
  hello.requested_flags = flags.value();
  Result<std::string> name = reader.get_string();
  if (!name) return name.status();
  hello.client_name = name.value();
  Result<std::string> publisher = reader.get_string();
  if (!publisher) return publisher.status();
  if (!publisher.value().empty()) {
    if (!is_canonical_identity(publisher.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "publisher identity is not canonical");
    }
    hello.publisher = make_publisher_id(publisher.value());
  }
  Status done = finish(reader);
  if (!done) return done;
  return hello;
}

Status encode_hello_response(const HelloResponse& response, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_u16(response.protocol_version);
  if (status) status = writer.put_u64(response.epoch.value);
  if (status) status = writer.put_u64(response.boot.value);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(response.granted_source));
  if (status) status = writer.put_string(response.coordinator_banner);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<HelloResponse> decode_hello_response(const ByteBuffer& payload, const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  HelloResponse response;
  Result<std::uint16_t> version = reader.get_u16();
  if (!version) return version.status();
  response.protocol_version = version.value();
  Result<std::uint64_t> epoch = reader.get_u64();
  if (!epoch) return epoch.status();
  response.epoch = CoordinatorEpoch{epoch.value()};
  Result<std::uint64_t> boot = reader.get_u64();
  if (!boot) return boot.status();
  response.boot = CoordinatorBootId{boot.value()};
  Result<std::uint8_t> source = reader.get_u8();
  if (!source) return source.status();
  Result<EvidenceSource> parsed = decode_evidence_source(source.value());
  if (!parsed) return parsed.status();
  response.granted_source = parsed.value();
  Result<std::string> banner = reader.get_string();
  if (!banner) return banner.status();
  response.coordinator_banner = banner.value();
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

// --- REGISTER_PUBLISHER ----------------------------------------------------

Status encode_register_publisher(const RegisterPublisherRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_string(request.publisher.value());
  if (status) status = writer.put_u64(request.boot.value);
  if (status) status = writer.put_u64(request.first_evidence_generation);
  if (status) status = writer.put_string(request.description);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<RegisterPublisherRequest> decode_register_publisher(const ByteBuffer& payload,
                                                           const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  RegisterPublisherRequest request;
  Result<PublisherId> publisher = decode_publisher(reader);
  if (!publisher) return publisher.status();
  request.publisher = publisher.value();
  Result<std::uint64_t> boot = reader.get_u64();
  if (!boot) return boot.status();
  request.boot = PublisherBootId{boot.value()};
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  request.first_evidence_generation = generation.value();
  Result<std::string> description = reader.get_string();
  if (!description) return description.status();
  request.description = description.value();
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

Status encode_register_publisher_response(const RegisterPublisherResponse& response,
                                          ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_string(response.session.value());
  if (status) status = writer.put_u64(response.epoch.value);
  if (status) status = writer.put_u64(response.boot.value);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(response.granted_source));
  if (status) status = writer.put_u64(response.default_freshness_window);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<RegisterPublisherResponse> decode_register_publisher_response(const ByteBuffer& payload,
                                                                    const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  RegisterPublisherResponse response;
  Result<SessionId> session = decode_session(reader);
  if (!session) return session.status();
  response.session = session.value();
  Result<std::uint64_t> epoch = reader.get_u64();
  if (!epoch) return epoch.status();
  response.epoch = CoordinatorEpoch{epoch.value()};
  Result<std::uint64_t> boot = reader.get_u64();
  if (!boot) return boot.status();
  response.boot = CoordinatorBootId{boot.value()};
  Result<std::uint8_t> source = reader.get_u8();
  if (!source) return source.status();
  Result<EvidenceSource> parsed = decode_evidence_source(source.value());
  if (!parsed) return parsed.status();
  response.granted_source = parsed.value();
  Result<std::uint64_t> freshness = reader.get_u64();
  if (!freshness) return freshness.status();
  response.default_freshness_window = freshness.value();
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

// --- workloads and contracts ------------------------------------------------

Status encode_declare_workload(const DeclareWorkloadRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_string(request.workload.value());
  if (status) status = writer.put_u64(request.generation.value);
  if (status) status = writer.put_string(request.description);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<DeclareWorkloadRequest> decode_declare_workload(const ByteBuffer& payload,
                                                       const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  DeclareWorkloadRequest request;
  Result<WorkloadId> workload = decode_workload(reader);
  if (!workload) return workload.status();
  request.workload = workload.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  request.generation = WorkloadGeneration{generation.value()};
  Result<std::string> description = reader.get_string();
  if (!description) return description.status();
  request.description = description.value();
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

Status encode_propose_contract(const ProposeContractRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = encode_contract(writer, request.contract);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<ProposeContractRequest> decode_propose_contract(const ByteBuffer& payload,
                                                       const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  ProposeContractRequest request;
  Result<WorkloadContract> contract = decode_contract(reader, limits);
  if (!contract) return contract.status();
  request.contract = contract.value();
  Status done = finish(reader);
  if (!done) return done;
  // The definition digest is not part of the request.  A peer cannot assert a digest:
  // the coordinator recomputes it from the definition it received, so a claimed digest
  // could never be used to smuggle a different contract past a comparison.
  request.contract.definition_digest = Digest256{};
  return request;
}

Status encode_contract_reference(const ContractReferenceRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_string(request.contract.value());
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<ContractReferenceRequest> decode_contract_reference(const ByteBuffer& payload,
                                                           const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  ContractReferenceRequest request;
  Result<ContractId> contract = decode_contract(reader);
  if (!contract) return contract.status();
  request.contract = contract.value();
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

Status encode_contract_response(const ContractResponse& response, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = encode_contract(writer, response.contract);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<ContractResponse> decode_contract_response(const ByteBuffer& payload,
                                                  const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  ContractResponse response;
  Result<WorkloadContract> contract = decode_contract(reader, limits);
  if (!contract) return contract.status();
  response.contract = contract.value();
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

// --- flows -----------------------------------------------------------------

Status encode_register_flow(const RegisterFlowRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = encode_flow_key(writer, request.key);
  if (status) status = writer.put_u64(request.generation.value);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<RegisterFlowRequest> decode_register_flow(const ByteBuffer& payload,
                                                 const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  RegisterFlowRequest request;
  Result<FlowKey> key = decode_flow_key(reader);
  if (!key) return key.status();
  request.key = key.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  request.generation = FlowGeneration{generation.value()};
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

Status encode_register_flow_response(const RegisterFlowResponse& response, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = encode_id128(writer, response.flow_id);
  if (status) status = writer.put_u64(response.generation.value);
  if (status) status = writer.put_bool(response.fenced_previous);
  if (status) status = writer.put_u64(response.previous_generation.value);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<RegisterFlowResponse> decode_register_flow_response(const ByteBuffer& payload,
                                                           const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  RegisterFlowResponse response;
  Result<Id128> flow_id = decode_id128(reader);
  if (!flow_id) return flow_id.status();
  response.flow_id = flow_id.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  response.generation = FlowGeneration{generation.value()};
  Result<bool> fenced = reader.get_bool();
  if (!fenced) return fenced.status();
  response.fenced_previous = fenced.value();
  Result<std::uint64_t> previous = reader.get_u64();
  if (!previous) return previous.status();
  response.previous_generation = FlowGeneration{previous.value()};
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

// --- evidence --------------------------------------------------------------

Status encode_publish_evidence(const PublishEvidenceRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  const EvidencePayload& payload = request.payload;
  Status status = writer.put_string(payload.workload.value());
  if (status) status = writer.put_u64(payload.workload_generation.value);
  if (status) status = writer.put_string(payload.contract.value());
  if (status) status = encode_flow_key(writer, payload.flow_key);
  if (status) status = writer.put_u64(payload.flow_generation.value);
  if (status) status = writer.put_u64(payload.evidence_generation.value);
  if (status) status = writer.put_u16(static_cast<std::uint16_t>(payload.semantic));
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(payload.claimed_source));
  if (status) status = writer.put_u64(payload.freshness_window);
  if (status) status = writer.put_string(payload.metadata.topic);
  if (status) status = writer.put_u64(payload.metadata.binding);
  if (status) status = writer.put_string(payload.metadata.reason);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<PublishEvidenceRequest> decode_publish_evidence(const ByteBuffer& payload,
                                                       const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  PublishEvidenceRequest request;
  Result<std::string> workload = reader.get_string();
  if (!workload) return workload.status();
  if (!workload.value().empty()) {
    if (!is_canonical_identity(workload.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "workload identity is not canonical");
    }
    request.payload.workload = make_workload_id(workload.value());
  }
  Result<std::uint64_t> workload_generation = reader.get_u64();
  if (!workload_generation) return workload_generation.status();
  request.payload.workload_generation = WorkloadGeneration{workload_generation.value()};
  Result<std::string> contract = reader.get_string();
  if (!contract) return contract.status();
  if (!contract.value().empty()) {
    if (!is_canonical_identity(contract.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "contract identity is not canonical");
    }
    request.payload.contract = make_contract_id(contract.value());
  }
  Result<FlowKey> key = decode_flow_key(reader);
  if (!key) return key.status();
  request.payload.flow_key = key.value();
  Result<std::uint64_t> flow_generation = reader.get_u64();
  if (!flow_generation) return flow_generation.status();
  request.payload.flow_generation = FlowGeneration{flow_generation.value()};
  Result<std::uint64_t> evidence_generation = reader.get_u64();
  if (!evidence_generation) return evidence_generation.status();
  request.payload.evidence_generation = EvidenceGeneration{evidence_generation.value()};
  Result<std::uint16_t> semantic = reader.get_u16();
  if (!semantic) return semantic.status();
  Result<SemanticClass> parsed_semantic = decode_semantic_class(semantic.value());
  if (!parsed_semantic) return parsed_semantic.status();
  request.payload.semantic = parsed_semantic.value();
  Result<std::uint8_t> source = reader.get_u8();
  if (!source) return source.status();
  // The claimed source is decoded as data, not as authority.  Whatever the peer writes
  // here, the coordinator clamps it to the ceiling of the authenticated session.
  Result<EvidenceSource> parsed_source = decode_evidence_source(source.value());
  if (!parsed_source) return parsed_source.status();
  request.payload.claimed_source = parsed_source.value();
  Result<std::uint64_t> freshness = reader.get_u64();
  if (!freshness) return freshness.status();
  request.payload.freshness_window = freshness.value();
  Result<std::string> topic = reader.get_string();
  if (!topic) return topic.status();
  request.payload.metadata.topic = topic.value();
  Result<std::uint64_t> binding = reader.get_u64();
  if (!binding) return binding.status();
  request.payload.metadata.binding = binding.value();
  Result<std::string> reason = reader.get_string();
  if (!reason) return reason.status();
  // Control characters are refused rather than escaped, so a peer cannot inject a line
  // break that makes an explanation read as two records.
  for (char ch : reason.value()) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7FU) {
      return Status::failure(ErrorCode::MALFORMED_RECORD,
                             "evidence reason contains a control character");
    }
  }
  request.payload.metadata.reason = reason.value();
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

Status encode_publish_evidence_response(const PublishEvidenceResponse& response, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_string(response.evidence_id.value());
  if (status) status = encode_id128(writer, response.flow_id);
  if (status) status = writer.put_u64(response.flow_generation.value);
  if (status) status = writer.put_u8(static_cast<std::uint8_t>(response.effective_source));
  if (status) status = writer.put_bool(response.superseded_previous);
  if (status) status = writer.put_string(response.superseded_id.value());
  if (status) status = writer.put_bool(response.fenced_flow_generation);
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(response.notes.size()));
  for (const std::string& note : response.notes) {
    if (!status) break;
    status = writer.put_string(note);
  }
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<PublishEvidenceResponse> decode_publish_evidence_response(const ByteBuffer& payload,
                                                                 const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  PublishEvidenceResponse response;
  Result<EvidenceId> evidence_id = decode_evidence(reader);
  if (!evidence_id) return evidence_id.status();
  response.evidence_id = evidence_id.value();
  Result<Id128> flow_id = decode_id128(reader);
  if (!flow_id) return flow_id.status();
  response.flow_id = flow_id.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  response.flow_generation = FlowGeneration{generation.value()};
  Result<std::uint8_t> source = reader.get_u8();
  if (!source) return source.status();
  Result<EvidenceSource> parsed = decode_evidence_source(source.value());
  if (!parsed) return parsed.status();
  response.effective_source = parsed.value();
  Result<bool> superseded = reader.get_bool();
  if (!superseded) return superseded.status();
  response.superseded_previous = superseded.value();
  Result<std::string> superseded_id = reader.get_string();
  if (!superseded_id) return superseded_id.status();
  if (!superseded_id.value().empty()) {
    if (!is_canonical_identity(superseded_id.value())) {
      return Status::failure(ErrorCode::MALFORMED_RECORD, "superseded evidence id is not canonical");
    }
    response.superseded_id = make_evidence_id(superseded_id.value());
  }
  Result<bool> fenced = reader.get_bool();
  if (!fenced) return fenced.status();
  response.fenced_flow_generation = fenced.value();
  Result<std::uint32_t> note_count = reader.get_count(limits.max_collection_count);
  if (!note_count) return note_count.status();
  response.notes.reserve(note_count.value());
  for (std::uint32_t i = 0; i < note_count.value(); ++i) {
    Result<std::string> note = reader.get_string();
    if (!note) return note.status();
    response.notes.push_back(note.value());
  }
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

Status encode_withdraw_evidence(const WithdrawEvidenceRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_string(request.evidence.value());
  if (status) status = writer.put_string(request.reason);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<WithdrawEvidenceRequest> decode_withdraw_evidence(const ByteBuffer& payload,
                                                         const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  WithdrawEvidenceRequest request;
  Result<EvidenceId> evidence = decode_evidence(reader);
  if (!evidence) return evidence.status();
  request.evidence = evidence.value();
  Result<std::string> reason = reader.get_long_string(limits.max_blob_bytes);
  if (!reason) return reason.status();
  request.reason = reason.value();
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

Status encode_revoke_generation(const RevokeGenerationRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = encode_id128(writer, request.flow_id);
  if (status) status = writer.put_u64(request.generation.value);
  if (status) status = writer.put_string(request.reason);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<RevokeGenerationRequest> decode_revoke_generation(const ByteBuffer& payload,
                                                         const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  RevokeGenerationRequest request;
  Result<Id128> flow_id = decode_id128(reader);
  if (!flow_id) return flow_id.status();
  request.flow_id = flow_id.value();
  Result<std::uint64_t> generation = reader.get_u64();
  if (!generation) return generation.status();
  request.generation = FlowGeneration{generation.value()};
  Result<std::string> reason = reader.get_string();
  if (!reason) return reason.status();
  request.reason = reason.value();
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

// --- classification --------------------------------------------------------

Status encode_classify_request(const ClassifyRequest& request, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_u32(static_cast<std::uint32_t>(request.entries.size()));
  for (const ClassifyQueryEntry& entry : request.entries) {
    if (!status) break;
    status = encode_flow_key(writer, entry.key);
    if (status) status = writer.put_u64(entry.generation.value);
    if (status) status = writer.put_bool(entry.explain);
  }
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<ClassifyRequest> decode_classify_request(const ByteBuffer& payload,
                                                const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  ClassifyRequest request;
  Result<std::uint32_t> count = reader.get_count(limits.max_collection_count);
  if (!count) return count.status();
  // The declared count is bounded by the codec limit and by the bytes that actually
  // remain, because each entry needs at least a fixed number of bytes.
  constexpr std::size_t kMinimumEntryBytes = 24;
  if (static_cast<std::size_t>(count.value()) > reader.remaining() / kMinimumEntryBytes + 1) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           "classification batch declares more entries than the payload can hold");
  }
  request.entries.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    ClassifyQueryEntry entry;
    Result<FlowKey> key = decode_flow_key(reader);
    if (!key) return key.status();
    entry.key = key.value();
    Result<std::uint64_t> generation = reader.get_u64();
    if (!generation) return generation.status();
    entry.generation = FlowGeneration{generation.value()};
    Result<bool> explain = reader.get_bool();
    if (!explain) return explain.status();
    entry.explain = explain.value();
    request.entries.push_back(std::move(entry));
  }
  Status done = finish(reader);
  if (!done) return done;
  return request;
}

Status encode_classify_response(const ClassifyResponse& response, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_u32(static_cast<std::uint32_t>(response.classifications.size()));
  for (const Classification& classification : response.classifications) {
    if (!status) break;
    status = encode_classification(writer, classification);
  }
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(response.per_key_codes.size()));
  for (ErrorCode code : response.per_key_codes) {
    if (!status) break;
    status = writer.put_u32(static_cast<std::uint32_t>(code));
  }
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(response.per_key_messages.size()));
  for (const std::string& message : response.per_key_messages) {
    if (!status) break;
    status = writer.put_string(message);
  }
  if (status) status = writer.put_u32(static_cast<std::uint32_t>(response.explanations.size()));
  for (const std::string& explanation : response.explanations) {
    if (!status) break;
    status = writer.put_string(explanation);
  }
  if (status) status = writer.put_u64(response.coordinator_epoch);
  if (status) status = writer.put_u64(response.coordinator_boot);
  if (status) status = writer.put_u32(response.succeeded);
  if (status) status = writer.put_u32(response.failed);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<ClassifyResponse> decode_classify_response(const ByteBuffer& payload,
                                                  const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  ClassifyResponse response;
  Result<std::uint32_t> count = reader.get_count(limits.max_collection_count);
  if (!count) return count.status();
  response.classifications.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    Result<Classification> classification = decode_classification(reader, limits);
    if (!classification) return classification.status();
    response.classifications.push_back(std::move(classification).value());
  }
  Result<std::uint32_t> code_count = reader.get_count(limits.max_collection_count);
  if (!code_count) return code_count.status();
  response.per_key_codes.reserve(code_count.value());
  for (std::uint32_t i = 0; i < code_count.value(); ++i) {
    Result<std::uint32_t> code = reader.get_u32();
    if (!code) return code.status();
    response.per_key_codes.push_back(static_cast<ErrorCode>(code.value()));
  }
  Result<std::uint32_t> message_count = reader.get_count(limits.max_collection_count);
  if (!message_count) return message_count.status();
  response.per_key_messages.reserve(message_count.value());
  for (std::uint32_t i = 0; i < message_count.value(); ++i) {
    Result<std::string> message = reader.get_long_string(limits.max_blob_bytes);
    if (!message) return message.status();
    response.per_key_messages.push_back(message.value());
  }
  Result<std::uint32_t> explanation_count = reader.get_count(limits.max_collection_count);
  if (!explanation_count) return explanation_count.status();
  response.explanations.reserve(explanation_count.value());
  for (std::uint32_t i = 0; i < explanation_count.value(); ++i) {
    // An explanation is a rendered document, not an identity: it is bounded by the blob limit and
    // ultimately by the frame limit.  Bounding it by the identity-string limit made the coordinator
    // produce responses that its own clients could not decode, which is a defect the multiprocess
    // surface found: "declared blob length 791 exceeds limit of 512".
    Result<std::string> explanation = reader.get_long_string(limits.max_blob_bytes);
    if (!explanation) return explanation.status();
    response.explanations.push_back(explanation.value());
  }
  Result<std::uint64_t> epoch = reader.get_u64();
  if (!epoch) return epoch.status();
  response.coordinator_epoch = epoch.value();
  Result<std::uint64_t> boot = reader.get_u64();
  if (!boot) return boot.status();
  response.coordinator_boot = boot.value();
  Result<std::uint32_t> succeeded = reader.get_u32();
  if (!succeeded) return succeeded.status();
  response.succeeded = succeeded.value();
  Result<std::uint32_t> failed = reader.get_u32();
  if (!failed) return failed.status();
  response.failed = failed.value();
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

Status encode_stats_response(const StatsResponse& response, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_string(response.rendered);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<StatsResponse> decode_stats_response(const ByteBuffer& payload, const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  StatsResponse response;
  Result<std::string> rendered = reader.get_long_string(limits.max_blob_bytes);
  if (!rendered) return rendered.status();
  response.rendered = rendered.value();
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

Status encode_error_response(const ErrorResponse& response, ByteBuffer& out) {
  BufferWriter writer(kMaxFramePayload);
  Status status = writer.put_u32(static_cast<std::uint32_t>(response.code));
  if (status) status = writer.put_string(response.message);
  if (!status) return status;
  out = writer.take();
  return Status::success();
}

Result<ErrorResponse> decode_error_response(const ByteBuffer& payload, const CodecLimits& limits) {
  BufferReader reader(payload, limits.max_string_bytes);
  ErrorResponse response;
  Result<std::uint32_t> code = reader.get_u32();
  if (!code) return code.status();
  response.code = static_cast<ErrorCode>(code.value());
  Result<std::string> message = reader.get_long_string(limits.max_blob_bytes);
  if (!message) return message.status();
  response.message = message.value();
  Status done = finish(reader);
  if (!done) return done;
  return response;
}

CoordinatorResponse make_error_response(ErrorCode code, const std::string& message) {
  CoordinatorResponse response;
  response.kind = MessageKind::ERROR_RESPONSE;
  ErrorResponse body;
  body.code = code;
  body.message = message;
  Status status = encode_error_response(body, response.payload);
  if (!status) {
    response.payload.clear();
  }
  return response;
}

}  // namespace aifc
