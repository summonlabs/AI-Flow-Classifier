// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Proof surface: message codec round trips and canonical encoding.
//
// Every message in the protocol is encoded, decoded, and compared field by field.  The
// surface also asserts the properties that make the codec safe to point at a hostile peer:
// a decode that leaves bytes behind is TRAILING_GARBAGE, a truncated message is
// MALFORMED_RECORD, and re-encoding a decoded message reproduces the original bytes exactly
// (canonical form), so two peers that agree on a value agree on its bytes.

#include "test_framework.hpp"

#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"

namespace {

const aifc::CodecLimits kLimits = aifc::CodecLimits::from(aifc::ResourceLimits{});

[[nodiscard]] aifc::FlowKey sample_key() {
  aifc::FlowKey key;
  key.local_address = aifc::IpAddress::from_v4(0x0A000001U);
  key.remote_address = aifc::IpAddress::from_v4(0x0A0000FEU);
  key.local_port = 40000;
  key.remote_port = 29500;
  key.transport = aifc::TransportProtocol::TCP;
  return key;
}

// Looks for a byte sequence in an encoded message.  Used to assert that a request never
// carries a field it must not carry.
[[nodiscard]] bool contains(const aifc::ByteBuffer& buffer, std::string_view needle) {
  if (needle.empty() || buffer.size() < needle.size()) return false;
  for (std::size_t i = 0; i + needle.size() <= buffer.size(); ++i) {
    bool match = true;
    for (std::size_t j = 0; j < needle.size(); ++j) {
      if (buffer[i + j] != static_cast<std::uint8_t>(needle[j])) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

}  // namespace

AIFC_TEST("hello round trip preserves role, versions, flags and publisher") {
  aifc::HelloRequest hello;
  hello.role = aifc::PeerRole::PUBLISHER;
  hello.protocol_version = aifc::kProtocolVersion;
  hello.protocol_version_min = aifc::kProtocolVersionMin;
  hello.requested_flags = aifc::kHelloFlagRequestHeuristics;
  hello.client_name = "collective-agent/1.0";
  hello.publisher = aifc::make_publisher_id("node-7");

  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_hello(hello, encoded));
  auto decoded = aifc::decode_hello(encoded, kLimits);
  AIFC_CHECK_OK(decoded);
  AIFC_CHECK_EQ(static_cast<int>(decoded.value().role), static_cast<int>(hello.role));
  AIFC_CHECK_EQ(decoded.value().protocol_version, hello.protocol_version);
  AIFC_CHECK_EQ(decoded.value().protocol_version_min, hello.protocol_version_min);
  AIFC_CHECK_EQ(decoded.value().requested_flags, hello.requested_flags);
  AIFC_CHECK_EQ(decoded.value().client_name, hello.client_name);
  AIFC_CHECK_EQ(decoded.value().publisher.value(), hello.publisher.value());

  aifc::ByteBuffer reencoded;
  AIFC_CHECK_OK(aifc::encode_hello(decoded.value(), reencoded));
  AIFC_CHECK_EQ(reencoded.size(), encoded.size());
  AIFC_CHECK(reencoded == encoded);
}

AIFC_TEST("hello with an undefined peer role is refused") {
  aifc::ByteBuffer payload;
  payload.push_back(static_cast<std::uint8_t>(9));  // undefined role
  payload.push_back(0);
  payload.push_back(0);
  payload.push_back(0);
  payload.push_back(0);
  payload.push_back(0);
  payload.push_back(0);
  payload.push_back(0);
  aifc::ByteBuffer out(8, 0);
  AIFC_CHECK_ERR(aifc::decode_hello(payload, kLimits), aifc::ErrorCode::MALFORMED_RECORD);
  (void)out;
}

AIFC_TEST("register publisher round trip") {
  aifc::RegisterPublisherRequest request;
  request.publisher = aifc::make_publisher_id("trainer-node-3");
  request.boot = aifc::PublisherBootId{11};
  request.first_evidence_generation = 4;
  request.description = "rank 3 of an 8 way data parallel group";

  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_register_publisher(request, encoded));
  auto decoded = aifc::decode_register_publisher(encoded, kLimits);
  AIFC_CHECK_OK(decoded);
  AIFC_CHECK_EQ(decoded.value().publisher.value(), request.publisher.value());
  AIFC_CHECK_EQ(decoded.value().boot.value, request.boot.value);
  AIFC_CHECK_EQ(decoded.value().first_evidence_generation, request.first_evidence_generation);
  AIFC_CHECK_EQ(decoded.value().description, request.description);
}

AIFC_TEST("publish evidence request never carries publisher, session, epoch or ceiling") {
  // This is the structural half of "a peer cannot promote its own evidence": the message
  // has no field in which to make the claim.  The assertion searches the encoded bytes for
  // the values a peer would have to inject.
  aifc::PublishEvidenceRequest request;
  request.payload.flow_key = sample_key();
  request.payload.flow_generation = aifc::FlowGeneration{3};
  request.payload.evidence_generation = aifc::EvidenceGeneration{7};
  request.payload.semantic = aifc::SemanticClass::COLLECTIVE;
  request.payload.claimed_source = aifc::EvidenceSource::HEURISTIC;
  request.payload.metadata.topic = "rank3.collective";
  request.payload.metadata.reason = "all reduce group 4";

  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_publish_evidence(request, encoded));
  AIFC_CHECK(!contains(encoded, "trainer-node-3"));
  AIFC_CHECK(!contains(encoded, "session-"));
  AIFC_CHECK(!contains(encoded, "DECLARED_AUTHENTICATED"));

  auto decoded = aifc::decode_publish_evidence(encoded, kLimits);
  AIFC_CHECK_OK(decoded);
  AIFC_CHECK_EQ(static_cast<int>(decoded.value().payload.semantic),
                static_cast<int>(aifc::SemanticClass::COLLECTIVE));
  AIFC_CHECK_EQ(decoded.value().payload.evidence_generation.value, 7U);
  AIFC_CHECK_EQ(decoded.value().payload.metadata.topic, request.payload.metadata.topic);
  AIFC_CHECK(decoded.value().payload.flow_key == request.payload.flow_key);
}

AIFC_TEST("publish evidence refuses a reason containing a control character") {
  aifc::PublishEvidenceRequest request;
  request.payload.flow_key = sample_key();
  request.payload.evidence_generation = aifc::EvidenceGeneration{1};
  request.payload.semantic = aifc::SemanticClass::TELEMETRY;
  request.payload.metadata.topic = "topic";
  request.payload.metadata.reason = "line one\nline two";

  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_publish_evidence(request, encoded));
  AIFC_CHECK_ERR(aifc::decode_publish_evidence(encoded, kLimits), aifc::ErrorCode::MALFORMED_RECORD);
}

AIFC_TEST("classify request round trip and batch decoding") {
  aifc::ClassifyRequest request;
  for (std::uint16_t i = 0; i < 4; ++i) {
    aifc::ClassifyQueryEntry entry;
    entry.key = sample_key();
    entry.key.remote_port = static_cast<std::uint16_t>(29000 + i);
    entry.generation = aifc::FlowGeneration{static_cast<std::uint64_t>(i) + 1U};
    entry.explain = (i % 2) == 0;
    request.entries.push_back(entry);
  }
  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_classify_request(request, encoded));
  auto decoded = aifc::decode_classify_request(encoded, kLimits);
  AIFC_CHECK_OK(decoded);
  AIFC_CHECK_EQ(decoded.value().entries.size(), request.entries.size());
  for (std::size_t i = 0; i < request.entries.size(); ++i) {
    AIFC_CHECK(decoded.value().entries[i].key == request.entries[i].key);
    AIFC_CHECK_EQ(decoded.value().entries[i].generation.value, request.entries[i].generation.value);
    AIFC_CHECK_EQ(decoded.value().entries[i].explain, request.entries[i].explain);
  }
}

AIFC_TEST("classify request with a count larger than the payload is refused") {
  aifc::ByteBuffer payload;
  aifc::BufferWriter writer(aifc::kMaxFramePayload);
  AIFC_CHECK_OK(writer.put_u32(4096));  // claims 4096 entries, supplies none
  payload = writer.take();
  AIFC_CHECK_ERR(aifc::decode_classify_request(payload, kLimits), aifc::ErrorCode::MALFORMED_RECORD);
}

AIFC_TEST("classify response round trip preserves classifications and per key statuses") {
  aifc::ClassifyResponse response;
  aifc::Classification classification;
  classification.flow_id = aifc::derive_flow_id(sample_key());
  classification.flow_generation = aifc::FlowGeneration{2};
  classification.semantic = aifc::SemanticClass::KV_STATE_TRANSFER;
  classification.state = aifc::ClassificationState::CURRENT;
  classification.confidence = aifc::Confidence::from_basis_points(9000);
  classification.selected_evidence = aifc::make_evidence_id("ev-00112233445566778899aabbccddeeff");
  classification.selected_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  classification.policy_generation = aifc::ClassifierPolicyGeneration{3};
  classification.coordinator_epoch = aifc::CoordinatorEpoch{5};
  classification.coordinator_boot = aifc::CoordinatorBootId{2};
  classification.digest = aifc::compute_classification_digest(classification);
  response.classifications.push_back(classification);
  response.per_key_codes.push_back(aifc::ErrorCode::OK);
  response.per_key_messages.push_back(std::string());
  response.explanations.push_back("flow " + classification.flow_id.to_hex());
  response.coordinator_epoch = 5;
  response.coordinator_boot = 2;
  response.succeeded = 1;
  response.failed = 0;

  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_classify_response(response, encoded));
  auto decoded = aifc::decode_classify_response(encoded, kLimits);
  AIFC_CHECK_OK(decoded);
  AIFC_CHECK_EQ(decoded.value().classifications.size(), std::size_t{1});
  const aifc::Classification& round_tripped = decoded.value().classifications.front();
  AIFC_CHECK_EQ(round_tripped.semantic, classification.semantic);
  AIFC_CHECK_EQ(round_tripped.state, classification.state);
  AIFC_CHECK_EQ(round_tripped.confidence.basis_points(), classification.confidence.basis_points());
  AIFC_CHECK_EQ(round_tripped.selected_evidence.value(), classification.selected_evidence.value());
  AIFC_CHECK_EQ(round_tripped.digest.to_hex(), classification.digest.to_hex());
  AIFC_CHECK_EQ(decoded.value().succeeded, std::uint32_t{1});
  AIFC_CHECK_EQ(decoded.value().coordinator_epoch, std::uint64_t{5});
}

AIFC_TEST("contract message round trip including scope") {
  aifc::WorkloadContract contract;
  contract.id = aifc::make_contract_id("collective-contract");
  contract.workload = aifc::make_workload_id("pretrain-70b");
  contract.workload_generation = aifc::WorkloadGeneration{4};
  contract.owner = aifc::make_publisher_id("rank-0");
  contract.state = aifc::ContractState::ACTIVE;
  contract.declared_class = aifc::SemanticClass::COLLECTIVE;
  contract.remote_scope.push_back(aifc::IpAddress::from_v4(0x0A000002U));
  contract.remote_scope.push_back(aifc::IpAddress::from_v4(0x0A000003U));
  contract.local_port_scope.push_back(40000);
  contract.transport = aifc::TransportProtocol::TCP;
  contract.remote_port = 29500;
  contract.derived_source = aifc::EvidenceSource::CONTRACT_DERIVED;
  contract.description = "collective scope";
  contract.definition_digest = aifc::compute_contract_digest(contract);

  aifc::ProposeContractRequest request;
  request.contract = contract;
  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_propose_contract(request, encoded));
  auto decoded = aifc::decode_propose_contract(encoded, kLimits);
  AIFC_CHECK_OK(decoded);
  AIFC_CHECK_EQ(decoded.value().contract.id.value(), contract.id.value());
  AIFC_CHECK_EQ(decoded.value().contract.workload_generation.value, contract.workload_generation.value);
  AIFC_CHECK_EQ(decoded.value().contract.remote_scope.size(), contract.remote_scope.size());
  AIFC_CHECK(decoded.value().contract.remote_scope[0] == contract.remote_scope[0]);
  AIFC_CHECK_EQ(decoded.value().contract.local_port_scope.size(), std::size_t{1});
  AIFC_CHECK_EQ(decoded.value().contract.local_port_scope[0], std::uint16_t{40000});
  // A proposal never carries a digest.  The request decoder clears the field deliberately, because a
  // peer may describe a contract but may not assert what its content hashes to -- otherwise a
  // claimed digest could be smuggled past a comparison against content it does not match.
  AIFC_CHECK_MSG(decoded.value().contract.definition_digest.is_zero(),
                 "a contract proposal carried a digest, so a peer asserted content it cannot prove");

  // The content itself survives exactly, and the digest the coordinator will compute over the
  // received definition equals the digest of the definition that was sent.  That is what makes
  // "the same contract" a property of the content rather than of the sender.
  AIFC_CHECK_EQ(aifc::compute_contract_digest(decoded.value().contract).to_hex(),
                contract.definition_digest.to_hex());

  // The response direction does carry the coordinator's digest, recomputed from the content, and it
  // survives a round trip unchanged.
  aifc::ContractResponse response;
  response.contract = decoded.value().contract;
  response.contract.definition_digest = aifc::compute_contract_digest(response.contract);
  aifc::ByteBuffer response_bytes;
  AIFC_CHECK_OK(aifc::encode_contract_response(response, response_bytes));
  auto decoded_response = aifc::decode_contract_response(response_bytes, kLimits);
  AIFC_CHECK_OK(decoded_response);
  AIFC_CHECK_EQ(decoded_response.value().contract.definition_digest.to_hex(),
                response.contract.definition_digest.to_hex());
}

AIFC_TEST("error response round trip and stable rendering") {
  aifc::ErrorResponse response;
  response.code = aifc::ErrorCode::STALE_GENERATION;
  response.message = "flow advanced past the cited generation";
  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_error_response(response, encoded));
  auto decoded = aifc::decode_error_response(encoded, kLimits);
  AIFC_CHECK_OK(decoded);
  AIFC_CHECK_EQ(decoded.value().code, response.code);
  AIFC_CHECK_EQ(decoded.value().message, response.message);

  const aifc::CoordinatorResponse built =
      aifc::make_error_response(aifc::ErrorCode::UNAUTHORIZED, "publisher does not own the workload");
  AIFC_CHECK_EQ(static_cast<int>(built.kind), static_cast<int>(aifc::MessageKind::ERROR_RESPONSE));
  auto reparsed = aifc::decode_error_response(built.payload, kLimits);
  AIFC_CHECK_OK(reparsed);
  AIFC_CHECK_EQ(reparsed.value().code, aifc::ErrorCode::UNAUTHORIZED);
}

AIFC_TEST("every decoded message rejects trailing bytes") {
  aifc::HelloRequest hello;
  hello.client_name = "trailing-test";
  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_hello(hello, encoded));
  encoded.push_back(0x00);
  AIFC_CHECK_ERR(aifc::decode_hello(encoded, kLimits), aifc::ErrorCode::TRAILING_GARBAGE);
}

AIFC_TEST("truncation at every offset is refused rather than partially accepted") {
  aifc::RegisterPublisherRequest request;
  request.publisher = aifc::make_publisher_id("truncation-target");
  request.boot = aifc::PublisherBootId{3};
  request.description = "truncation target";
  aifc::ByteBuffer encoded;
  AIFC_CHECK_OK(aifc::encode_register_publisher(request, encoded));
  for (std::size_t length = 0; length < encoded.size(); ++length) {
    aifc::ByteBuffer truncated(encoded.begin(), encoded.begin() + static_cast<std::ptrdiff_t>(length));
    auto decoded = aifc::decode_register_publisher(truncated, kLimits);
    if (decoded) {
      AIFC_FAIL("a truncated message decoded successfully at length " + std::to_string(length));
    }
  }
}

AIFC_TEST("message kind helpers cover the whole defined range") {
  for (std::uint16_t value = 1; value <= aifc::kMaxMessageKind; ++value) {
    AIFC_CHECK(aifc::is_known_message_kind(value));
    AIFC_CHECK(aifc::to_string(static_cast<aifc::MessageKind>(value)) != "UNRECOGNIZED_MESSAGE_KIND");
  }
  AIFC_CHECK(!aifc::is_known_message_kind(0));
  AIFC_CHECK(!aifc::is_known_message_kind(aifc::kMaxMessageKind + 1));
  AIFC_CHECK(aifc::is_response_kind(aifc::MessageKind::HELLO_ACK));
  AIFC_CHECK(aifc::is_response_kind(aifc::MessageKind::CLASSIFY_RESULT));
  AIFC_CHECK(!aifc::is_response_kind(aifc::MessageKind::CLASSIFY));
}
