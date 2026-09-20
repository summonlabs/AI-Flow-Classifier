// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Message codecs.
//
// Every request decoder is canonical: it consumes exactly the bytes it declares and
// the caller then asserts that nothing follows.  Every field that could carry an
// identity is validated as a canonical identity, and every field that could carry
// authority is either absent from the message or explicitly ignored by the receiver in
// favour of the session envelope.

#ifndef AI_FLOW_CLASSIFIER_PROTOCOL_MESSAGES_HPP
#define AI_FLOW_CLASSIFIER_PROTOCOL_MESSAGES_HPP

#include <ostream>
#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/classify/classifier.hpp"
#include "ai_flow_classifier/codec/record_codec.hpp"
#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/protocol/frame.hpp"

namespace aifc {

enum class PeerRole : std::uint8_t {
  PUBLISHER = 1,
  CLIENT = 2,
};

inline constexpr std::uint32_t kHelloFlagRequestHeuristics = 1U << 0;

struct HelloRequest {
  PeerRole role = PeerRole::CLIENT;
  std::uint16_t protocol_version = kProtocolVersion;
  std::uint16_t protocol_version_min = kProtocolVersionMin;
  std::uint32_t requested_flags = 0;
  std::string client_name;
  PublisherId publisher;
};

Status encode_hello(const HelloRequest& hello, ByteBuffer& out);
Result<HelloRequest> decode_hello(const ByteBuffer& payload, const CodecLimits& limits);

struct HelloResponse {
  std::uint16_t protocol_version = kProtocolVersion;
  CoordinatorEpoch epoch;
  CoordinatorBootId boot;
  // The authority ceiling the coordinator is offering this session.  A peer may not
  // request a higher one; it is told what it got.
  EvidenceSource granted_source = EvidenceSource::HEURISTIC;
  std::string coordinator_banner;
};

Status encode_hello_response(const HelloResponse& response, ByteBuffer& out);
Result<HelloResponse> decode_hello_response(const ByteBuffer& payload, const CodecLimits& limits);

struct RegisterPublisherRequest {
  PublisherId publisher;
  PublisherBootId boot;
  std::uint64_t first_evidence_generation = 1;
  std::string description;
};

Status encode_register_publisher(const RegisterPublisherRequest& request, ByteBuffer& out);
Result<RegisterPublisherRequest> decode_register_publisher(const ByteBuffer& payload,
                                                           const CodecLimits& limits);

struct RegisterPublisherResponse {
  SessionId session;
  CoordinatorEpoch epoch;
  CoordinatorBootId boot;
  EvidenceSource granted_source = EvidenceSource::HEURISTIC;
  std::uint64_t default_freshness_window = 0;
};

Status encode_register_publisher_response(const RegisterPublisherResponse& response, ByteBuffer& out);
Result<RegisterPublisherResponse> decode_register_publisher_response(
    const ByteBuffer& payload, const CodecLimits& limits);

struct DeclareWorkloadRequest {
  WorkloadId workload;
  WorkloadGeneration generation;
  std::string description;
};

Status encode_declare_workload(const DeclareWorkloadRequest& request, ByteBuffer& out);
Result<DeclareWorkloadRequest> decode_declare_workload(const ByteBuffer& payload,
                                                       const CodecLimits& limits);

struct ProposeContractRequest {
  WorkloadContract contract;
};

Status encode_propose_contract(const ProposeContractRequest& request, ByteBuffer& out);
Result<ProposeContractRequest> decode_propose_contract(const ByteBuffer& payload,
                                                       const CodecLimits& limits);

struct ContractReferenceRequest {
  ContractId contract;
};

Status encode_contract_reference(const ContractReferenceRequest& request, ByteBuffer& out);
Result<ContractReferenceRequest> decode_contract_reference(const ByteBuffer& payload,
                                                           const CodecLimits& limits);

struct ContractResponse {
  WorkloadContract contract;
};

Status encode_contract_response(const ContractResponse& response, ByteBuffer& out);
Result<ContractResponse> decode_contract_response(const ByteBuffer& payload,
                                                  const CodecLimits& limits);

struct RegisterFlowRequest {
  FlowKey key;
  FlowGeneration generation;
};

Status encode_register_flow(const RegisterFlowRequest& request, ByteBuffer& out);
Result<RegisterFlowRequest> decode_register_flow(const ByteBuffer& payload,
                                                 const CodecLimits& limits);

struct RegisterFlowResponse {
  FlowId flow_id;
  FlowGeneration generation;
  bool fenced_previous = false;
  FlowGeneration previous_generation;
};

Status encode_register_flow_response(const RegisterFlowResponse& response, ByteBuffer& out);
Result<RegisterFlowResponse> decode_register_flow_response(const ByteBuffer& payload,
                                                           const CodecLimits& limits);

// The evidence message deliberately carries no publisher, no session, no epoch and no
// source ceiling.  Every one of those is taken from the authenticated session, which
// is what stops a peer from promoting its own evidence.
struct PublishEvidenceRequest {
  EvidencePayload payload;
};

Status encode_publish_evidence(const PublishEvidenceRequest& request, ByteBuffer& out);
Result<PublishEvidenceRequest> decode_publish_evidence(const ByteBuffer& payload,
                                                       const CodecLimits& limits);

struct PublishEvidenceResponse {
  EvidenceId evidence_id;
  FlowId flow_id;
  FlowGeneration flow_generation;
  EvidenceSource effective_source = EvidenceSource::UNKNOWN;
  bool superseded_previous = false;
  EvidenceId superseded_id;
  bool fenced_flow_generation = false;
  std::vector<std::string> notes;
};

Status encode_publish_evidence_response(const PublishEvidenceResponse& response, ByteBuffer& out);
Result<PublishEvidenceResponse> decode_publish_evidence_response(const ByteBuffer& payload,
                                                                 const CodecLimits& limits);

struct WithdrawEvidenceRequest {
  EvidenceId evidence;
  std::string reason;
};

Status encode_withdraw_evidence(const WithdrawEvidenceRequest& request, ByteBuffer& out);
Result<WithdrawEvidenceRequest> decode_withdraw_evidence(const ByteBuffer& payload,
                                                         const CodecLimits& limits);

struct RevokeGenerationRequest {
  FlowId flow_id;
  FlowGeneration generation;
  std::string reason;
};

Status encode_revoke_generation(const RevokeGenerationRequest& request, ByteBuffer& out);
Result<RevokeGenerationRequest> decode_revoke_generation(const ByteBuffer& payload,
                                                         const CodecLimits& limits);

// One classification query inside a batch.  The batch is bounded by the effective
// policy, so a peer cannot ask for an unbounded amount of work in one message.
struct ClassifyQueryEntry {
  FlowKey key;
  FlowGeneration generation = FlowGeneration{0};
  bool explain = false;
};

struct ClassifyRequest {
  std::vector<ClassifyQueryEntry> entries;
};

Status encode_classify_request(const ClassifyRequest& request, ByteBuffer& out);
Result<ClassifyRequest> decode_classify_request(const ByteBuffer& payload, const CodecLimits& limits);

struct ClassifyResponse {
  std::vector<Classification> classifications;
  std::vector<ErrorCode> per_key_codes;
  std::vector<std::string> per_key_messages;
  std::vector<std::string> explanations;
  std::uint64_t coordinator_epoch = 0;
  std::uint64_t coordinator_boot = 0;
  std::uint32_t succeeded = 0;
  std::uint32_t failed = 0;
};

Status encode_classify_response(const ClassifyResponse& response, ByteBuffer& out);
Result<ClassifyResponse> decode_classify_response(const ByteBuffer& payload,
                                                  const CodecLimits& limits);

struct StatsResponse {
  std::string rendered;
};

Status encode_stats_response(const StatsResponse& response, ByteBuffer& out);
Result<StatsResponse> decode_stats_response(const ByteBuffer& payload, const CodecLimits& limits);

struct ErrorResponse {
  ErrorCode code = ErrorCode::OK;
  // Stable textual reason.  Never a stack trace and never a path.
  std::string message;
};

Status encode_error_response(const ErrorResponse& response, ByteBuffer& out);
Result<ErrorResponse> decode_error_response(const ByteBuffer& payload, const CodecLimits& limits);

// The frame that a handler produces.  Keeping the response as a value (rather than
// writing to a socket inside the handler) is what makes it possible to guarantee that
// no lock is ever held while a socket is written.
struct CoordinatorResponse {
  MessageKind kind = MessageKind::ERROR_RESPONSE;
  ByteBuffer payload;
  bool close_after_send = false;
};

[[nodiscard]] CoordinatorResponse make_error_response(ErrorCode code, const std::string& message);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_PROTOCOL_MESSAGES_HPP
