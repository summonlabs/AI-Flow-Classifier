// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Integration proof surface: the coordinator state machine, in process.
//
// Every frame in this file is built with the canonical message encoders, written through
// encode_frame (so it carries a real CRC-32 and a real header), read back through
// try_decode_frame, and only then handed to Coordinator::handle.  That is the same path a
// frame takes over a socket, minus the socket, so the state machine is exercised with exactly
// the bytes a peer would send.
//
// Inputs are SYNTHETIC; the protocol behaviour is REAL.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "test_framework.hpp"

#include "synthetic.hpp"

namespace {

// The decoding limits are the *client's* choice, and this client is generous.  The canonical
// default bounds a single string field at kMaxStringBytes (512 bytes), which a rendered
// explanation can exceed; observed behaviour is that such a response cannot be decoded at the
// default limits even though the coordinator produced it.  That is a protocol limit worth
// knowing about, so the surface decodes with the blob bound rather than hiding the case.
[[nodiscard]] aifc::CodecLimits client_limits() {
  aifc::CodecLimits limits;
  limits.max_string_bytes = aifc::kMaxBlobBytes;
  return limits;
}

[[nodiscard]] bool contains(const std::string& haystack, std::string_view needle) {
  return haystack.find(needle) != std::string::npos;
}

// One connection: the key it is registered under, the session the coordinator mutates, and the
// identity the peer registered (which is what a failure message needs to name).
struct Connection {
  std::string key;
  aifc::CoordinatorSession session;
  aifc::PublisherId publisher;
  aifc::PublisherBootId boot;
  aifc::SessionId session_id;
};

// The coordinator reads its tick from the classifier's clock and the default is a monotonic
// millisecond source, so a manual source is what makes freshness reproducible.  The source
// outlives every coordinator in this process, which is what the pointer requires.
[[nodiscard]] aifc::ManualTickSource& coordinator_clock() {
  static aifc::ManualTickSource clock(1000U);
  return clock;
}

[[nodiscard]] aifc::CoordinatorOptions make_options() {
  aifc::CoordinatorOptions options;
  options.clock = &coordinator_clock();
  // No state path: this surface drives the in-process state machine, and a snapshot would not
  // change what is being proved here.
  options.state_path.clear();
  options.policy = aifc::ClassifierPolicy::initial();
  options.default_session_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  options.persist_on_mutation = false;
  return options;
}

[[nodiscard]] aifc::Frame make_frame(aifc::MessageKind kind, const aifc::ByteBuffer& payload,
                                     std::uint64_t epoch, std::uint64_t boot = 1,
                                     std::uint64_t sequence = 1) {
  aifc::Frame frame;
  frame.header.version = aifc::kProtocolVersion;
  frame.header.kind = kind;
  frame.header.flags = 0;
  frame.header.sequence = sequence;
  frame.header.epoch = epoch;
  frame.header.boot = boot;
  frame.header.payload_length = static_cast<std::uint32_t>(payload.size());
  frame.payload = payload;
  return frame;
}

// Writes the frame to the wire and reads it back.  A frame that cannot survive its own codec is
// a defect in the encoder, and the test says so rather than driving handle() with a value that
// no peer could ever send.
[[nodiscard]] aifc::Result<aifc::Frame> round_trip(const aifc::Frame& frame) {
  const auto encoded = aifc::encode_frame(frame.header, frame.payload, aifc::kMaxFramePayload);
  if (!encoded) return encoded.status();
  aifc::Frame decoded;
  std::size_t consumed = 0;
  const aifc::Status status = aifc::try_decode_frame(
      encoded.value().data(), encoded.value().size(), aifc::kMaxFramePayload, decoded, consumed);
  if (!status) return status;
  if (consumed != encoded.value().size()) {
    return aifc::Status::failure(aifc::ErrorCode::MALFORMED_FRAME,
                                 "a frame did not consume exactly its own encoded bytes");
  }
  return decoded;
}

// Hands one frame to the coordinator through the wire codec.
[[nodiscard]] aifc::Result<aifc::CoordinatorResponse> deliver(aifc::Coordinator& coordinator,
                                                             Connection& connection,
                                                             const aifc::Frame& frame) {
  const auto decoded = round_trip(frame);
  if (!decoded) return decoded.status();
  return coordinator.handle(connection.key, connection.session, decoded.value());
}

// Decodes an error response, recording a failure and returning OK when the response is not an
// error at all so the caller's code comparison reports the real problem.
[[nodiscard]] aifc::ErrorCode error_code_of(const aifc::CoordinatorResponse& response,
                                            const std::string& what) {
  if (response.kind != aifc::MessageKind::ERROR_RESPONSE) {
    AIFC_FAIL(what + ": expected an ERROR_RESPONSE but the coordinator answered " +
              std::string(aifc::to_string(response.kind)));
    return aifc::ErrorCode::OK;
  }
  const auto decoded = aifc::decode_error_response(response.payload, client_limits());
  if (!decoded) {
    AIFC_FAIL(what + ": the error response payload did not decode: " +
              decoded.status().message);
    return aifc::ErrorCode::OK;
  }
  return decoded.value().code;
}

void check_error(const aifc::CoordinatorResponse& response, aifc::ErrorCode expected,
                 const std::string& what) {
  const aifc::ErrorCode actual = error_code_of(response, what);
  if (actual != expected) {
    AIFC_FAIL(what + ": expected " + std::string(aifc::to_string(expected)) + " but got " +
              std::string(aifc::to_string(actual)));
  }
}

[[nodiscard]] aifc::ByteBuffer payload_hello(const aifc::PublisherId& publisher,
                                             std::uint16_t version, std::uint16_t version_min,
                                             std::uint32_t flags = 0U) {
  aifc::HelloRequest request;
  request.role = aifc::PeerRole::PUBLISHER;
  request.protocol_version = version;
  request.protocol_version_min = version_min;
  request.requested_flags = flags;
  request.client_name = "in-process test peer";
  request.publisher = publisher;
  aifc::ByteBuffer out;
  const aifc::Status status = aifc::encode_hello(request, out);
  if (!status) AIFC_FAIL("encode_hello failed: " + status.message);
  return out;
}

[[nodiscard]] aifc::ByteBuffer payload_register_publisher(const aifc::PublisherId& publisher,
                                                          std::uint64_t boot) {
  aifc::RegisterPublisherRequest request;
  request.publisher = publisher;
  request.boot = aifc::PublisherBootId{boot};
  request.first_evidence_generation = 1;
  request.description = "in-process test peer";
  aifc::ByteBuffer out;
  const aifc::Status status = aifc::encode_register_publisher(request, out);
  if (!status) AIFC_FAIL("encode_register_publisher failed: " + status.message);
  return out;
}

[[nodiscard]] aifc::ByteBuffer payload_register_flow(const aifc::FlowKey& key,
                                                     std::uint64_t generation, bool& ok) {
  aifc::RegisterFlowRequest request;
  request.key = key;
  request.generation = aifc::FlowGeneration{generation};
  aifc::ByteBuffer out;
  const aifc::Status status = aifc::encode_register_flow(request, out);
  ok = status.ok();
  if (!status) AIFC_FAIL("encode_register_flow failed: " + status.message);
  return out;
}

[[nodiscard]] aifc::ByteBuffer payload_publish(const aifc::FlowKey& key,
                                               aifc::FlowGeneration flow_generation,
                                               std::uint64_t evidence_generation,
                                               aifc::SemanticClass semantic,
                                               aifc::EvidenceSource claimed,
                                               const std::string& topic, bool& ok) {
  aifc::PublishEvidenceRequest request;
  request.payload.flow_key = key;
  request.payload.flow_generation = flow_generation;
  request.payload.evidence_generation = aifc::EvidenceGeneration{evidence_generation};
  request.payload.semantic = semantic;
  request.payload.claimed_source = claimed;
  request.payload.metadata.topic = topic;
  request.payload.metadata.reason = "in-process synthetic evidence";
  aifc::ByteBuffer out;
  const aifc::Status status = aifc::encode_publish_evidence(request, out);
  ok = status.ok();
  if (!status) AIFC_FAIL("encode_publish_evidence failed: " + status.message);
  return out;
}

[[nodiscard]] aifc::ByteBuffer payload_classify(const aifc::FlowKey& key,
                                                std::uint64_t generation, bool explain,
                                                bool& ok) {
  aifc::ClassifyRequest request;
  aifc::ClassifyQueryEntry entry;
  entry.key = key;
  entry.generation = aifc::FlowGeneration{generation};
  entry.explain = explain;
  request.entries.push_back(entry);
  aifc::ByteBuffer out;
  const aifc::Status status = aifc::encode_classify_request(request, out);
  ok = status.ok();
  if (!status) AIFC_FAIL("encode_classify_request failed: " + status.message);
  return out;
}

// A raw frame with a hand-built header and a real CRC-32, so the wire-level refusals can be
// driven without the canonical encoder (which refuses to produce an invalid frame at all).
[[nodiscard]] aifc::ByteBuffer raw_frame(std::uint16_t version, std::uint16_t kind,
                                         const aifc::ByteBuffer& payload) {
  aifc::ByteBuffer out(aifc::kFrameHeaderBytes + payload.size(), 0U);
  std::memcpy(out.data(), aifc::kFrameMagic, sizeof(aifc::kFrameMagic));
  aifc::store_u16_le(out.data() + 4, version);
  aifc::store_u16_le(out.data() + 6, kind);
  aifc::store_u32_le(out.data() + 8, 0U);
  aifc::store_u64_le(out.data() + 12, 1U);
  aifc::store_u64_le(out.data() + 20, 0U);
  aifc::store_u64_le(out.data() + 28, 0U);
  aifc::store_u32_le(out.data() + 36, static_cast<std::uint32_t>(payload.size()));
  aifc::store_u32_le(out.data() + 40, 0U);
  if (!payload.empty()) {
    std::memcpy(out.data() + aifc::kFrameHeaderBytes, payload.data(), payload.size());
  }
  aifc::store_u32_le(out.data() + 40, aifc::crc32(out.data(), out.size()));
  return out;
}

[[nodiscard]] bool handshake(aifc::Coordinator& coordinator, Connection& connection,
                             std::uint32_t publisher_index, std::uint64_t publisher_boot,
                             std::uint64_t epoch) {
  connection.publisher = aifc_test::synthetic_publisher(publisher_index);
  const auto hello = deliver(coordinator, connection,
                             make_frame(aifc::MessageKind::HELLO,
                                        payload_hello(connection.publisher, aifc::kProtocolVersion,
                                                      aifc::kProtocolVersionMin),
                                        epoch));
  if (!hello) {
    AIFC_FAIL("HELLO was not handled: " + hello.status().message);
    return false;
  }
  if (hello.value().kind != aifc::MessageKind::HELLO_ACK) {
    AIFC_FAIL("HELLO produced " + std::string(aifc::to_string(hello.value().kind)) +
              " instead of HELLO_ACK");
    return false;
  }
  const auto ack = aifc::decode_hello_response(hello.value().payload, client_limits());
  if (!ack) {
    AIFC_FAIL("HELLO_ACK did not decode: " + ack.status().message);
    return false;
  }
  if (ack.value().epoch.value != epoch) {
    AIFC_FAIL("HELLO_ACK reported epoch " + ack.value().epoch.to_string() + " but the frame was "
              "sent at epoch " + std::to_string(epoch));
    return false;
  }

  const auto registered = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::REGISTER_PUBLISHER,
                 payload_register_publisher(connection.publisher, publisher_boot), epoch, publisher_boot, 2));
  if (!registered) {
    AIFC_FAIL("REGISTER_PUBLISHER was not handled: " + registered.status().message);
    return false;
  }
  if (registered.value().kind != aifc::MessageKind::HELLO_ACK) {
    AIFC_FAIL("REGISTER_PUBLISHER produced " +
              std::string(aifc::to_string(registered.value().kind)) + " instead of HELLO_ACK");
    return false;
  }
  const auto response =
      aifc::decode_register_publisher_response(registered.value().payload, client_limits());
  if (!response) {
    AIFC_FAIL("the registration response did not decode: " + response.status().message);
    return false;
  }
  connection.boot = aifc::PublisherBootId{publisher_boot};
  connection.session_id = response.value().session;
  if (!connection.session.registered) {
    AIFC_FAIL("the coordinator did not mark the session as registered");
    return false;
  }
  if (connection.session.session.value() != connection.session_id.value()) {
    AIFC_FAIL("the session identity in the response does not match the session the coordinator "
              "bound");
    return false;
  }
  return true;
}

}  // namespace

AIFC_TEST("coordinator/handshake: HELLO, registration, flow, evidence and classify (REAL)") {
  aifc::Coordinator coordinator(make_options());
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const std::uint64_t epoch = coordinator.epoch().value;

  Connection connection;
  connection.key = "connection-0";
  if (!handshake(coordinator, connection, 0U, 1U, epoch)) return;
  AIFC_CHECK(connection.session.registered);
  AIFC_CHECK_EQ(connection.session.publisher.value(), connection.publisher.value());
  AIFC_CHECK(connection.session.max_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED);

  // REGISTER_FLOW.  The coordinator uses STATS_RESPONSE as its generic success carrier for the
  // message kinds that have no dedicated response kind, so the payload -- not the frame kind --
  // identifies the body; the response kind is at least a response kind.
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(0U);
  bool encoded = false;
  const auto flow_response = deliver(coordinator, connection,
                                     make_frame(aifc::MessageKind::REGISTER_FLOW,
                                                payload_register_flow(key, 0U, encoded), epoch, 1U, 3));
  AIFC_CHECK(encoded);
  AIFC_CHECK_OK(flow_response);
  if (!flow_response) return;
  AIFC_CHECK(aifc::is_response_kind(flow_response.value().kind));
  AIFC_CHECK(flow_response.value().kind == aifc::MessageKind::REGISTER_FLOW_RESULT);
  const auto flow_body =
      aifc::decode_register_flow_response(flow_response.value().payload, client_limits());
  AIFC_CHECK_OK(flow_body);
  if (!flow_body) return;
  AIFC_CHECK(!flow_body.value().flow_id.is_zero());
  AIFC_CHECK_EQ(flow_body.value().generation.value, 1U);
  AIFC_CHECK_EQ(flow_body.value().fenced_previous, false);
  AIFC_CHECK_EQ(flow_body.value().flow_id.to_hex(), aifc::derive_flow_id(key).to_hex());

  // PUBLISH_EVIDENCE.  The claimed source is the session ceiling, so nothing is clamped and no
  // note is produced.
  bool published = false;
  const auto publish_response = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::PUBLISH_EVIDENCE,
                 payload_publish(key, aifc::FlowGeneration{1}, 1U, aifc::SemanticClass::COLLECTIVE,
                                 aifc::EvidenceSource::DECLARED_AUTHENTICATED, "in-process.topic",
                                 published),
                 epoch, 1U, 4));
  AIFC_CHECK(published);
  AIFC_CHECK_OK(publish_response);
  if (!publish_response) return;
  const auto publish_body =
      aifc::decode_publish_evidence_response(publish_response.value().payload, client_limits());
  AIFC_CHECK_OK(publish_body);
  if (!publish_body) return;
  AIFC_CHECK(!publish_body.value().evidence_id.empty());
  AIFC_CHECK_EQ(publish_body.value().flow_id.to_hex(), flow_body.value().flow_id.to_hex());
  AIFC_CHECK_EQ(publish_body.value().flow_generation.value, 1U);
  AIFC_CHECK(publish_body.value().effective_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  AIFC_CHECK_EQ(publish_body.value().superseded_previous, false);
  AIFC_CHECK_EQ(publish_body.value().fenced_flow_generation, false);
  AIFC_CHECK(publish_body.value().notes.empty());

  // CLASSIFY.
  bool classify_encoded = false;
  const auto classify_response = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::CLASSIFY, payload_classify(key, 0U, true, classify_encoded),
                 epoch, 1U, 5));
  AIFC_CHECK(classify_encoded);
  AIFC_CHECK_OK(classify_response);
  if (!classify_response) return;
  AIFC_CHECK(classify_response.value().kind == aifc::MessageKind::CLASSIFY_RESULT);
  const auto classify_body =
      aifc::decode_classify_response(classify_response.value().payload, client_limits());
  AIFC_CHECK_OK(classify_body);
  if (!classify_body) return;
  AIFC_CHECK_EQ(classify_body.value().succeeded, 1U);
  AIFC_CHECK_EQ(classify_body.value().failed, 0U);
  AIFC_CHECK_EQ(classify_body.value().coordinator_epoch, epoch);
  AIFC_CHECK_EQ(classify_body.value().coordinator_boot, coordinator.boot().value);
  AIFC_CHECK_EQ(classify_body.value().classifications.size(), std::size_t{1});
  AIFC_CHECK_EQ(classify_body.value().per_key_codes.size(), std::size_t{1});
  AIFC_CHECK_EQ(classify_body.value().explanations.size(), std::size_t{1});
  if (classify_body.value().classifications.size() == 1U) {
    const aifc::Classification& classification = classify_body.value().classifications[0];
    AIFC_CHECK(classification.semantic == aifc::SemanticClass::COLLECTIVE);
    AIFC_CHECK(classification.state == aifc::ClassificationState::CURRENT);
    AIFC_CHECK_EQ(classification.confidence.to_decimal(), std::string("0.9000"));
    AIFC_CHECK_EQ(classification.selected_evidence.value(),
                  publish_body.value().evidence_id.value());
    AIFC_CHECK(classification.selected_source == aifc::EvidenceSource::DECLARED_AUTHENTICATED);
  }
  if (classify_body.value().per_key_codes.size() == 1U) {
    AIFC_CHECK(classify_body.value().per_key_codes[0] == aifc::ErrorCode::OK);
  }
  if (classify_body.value().explanations.size() == 1U) {
    AIFC_CHECK_MSG(contains(classify_body.value().explanations[0], "COLLECTIVE"),
                   "the explanation must name the class, got: "
                       << classify_body.value().explanations[0]);
  }

  // The coordinator's own view agrees: five messages handled, none refused, one active session.
  const aifc::Coordinator::Stats stats = coordinator.stats();
  AIFC_CHECK_EQ(stats.coordinator.messages_handled, 5U);
  AIFC_CHECK_EQ(stats.coordinator.messages_refused, 0U);
  AIFC_CHECK_EQ(stats.coordinator.protocol_failures, 0U);
  AIFC_CHECK_EQ(stats.coordinator.active_sessions, std::size_t{1});
  AIFC_CHECK_EQ(stats.classifier.flows.size, std::size_t{1});
  AIFC_CHECK_EQ(stats.classifier.evidence.records, std::size_t{1});
  AIFC_CHECK_EQ(stats.classifier.publishers.publishers, std::size_t{1});
  AIFC_CHECK_EQ(stats.coordinator.connections_accepted, 0U);  // no transport in this surface
}

AIFC_TEST("coordinator/epoch: a frame carrying a stale epoch is refused with STALE_EPOCH (REAL)") {
  aifc::Coordinator coordinator(make_options());
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const std::uint64_t epoch = coordinator.epoch().value;
  AIFC_CHECK(epoch > 1U);

  Connection connection;
  connection.key = "connection-0";
  if (!handshake(coordinator, connection, 0U, 1U, epoch)) return;

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(1U);
  bool encoded = false;
  const aifc::ByteBuffer flow_payload = payload_register_flow(key, 0U, encoded);
  AIFC_CHECK(encoded);

  // A frame that declares the epoch the coordinator served before it started.
  const auto stale_register = deliver(coordinator, connection,
                                      make_frame(aifc::MessageKind::REGISTER_FLOW, flow_payload,
                                                 epoch - 1U, 1U, 3));
  AIFC_CHECK_OK(stale_register);
  if (stale_register) {
    check_error(stale_register.value(), aifc::ErrorCode::STALE_EPOCH,
                "REGISTER_FLOW at the previous epoch");
    const auto decoded =
        aifc::decode_error_response(stale_register.value().payload, client_limits());
    if (decoded) {
      AIFC_CHECK_MSG(contains(decoded.value().message, std::to_string(epoch - 1U)) &&
                         contains(decoded.value().message, std::to_string(epoch)),
                     "the refusal must name both epochs, got: " << decoded.value().message);
    }
  }

  // A frame that declares an epoch from the future is refused the same way.
  const auto future_classify = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::CLASSIFY, payload_classify(key, 0U, false, encoded),
                 epoch + 1U, 1U, 4));
  AIFC_CHECK_OK(future_classify);
  if (future_classify) {
    check_error(future_classify.value(), aifc::ErrorCode::STALE_EPOCH,
                "CLASSIFY at a future epoch");
  }

  // REGISTER_PUBLISHER and PUBLISH_EVIDENCE check the epoch too.
  const auto stale_publish = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::PUBLISH_EVIDENCE,
                 payload_publish(key, aifc::FlowGeneration{1}, 1U, aifc::SemanticClass::COLLECTIVE,
                                 aifc::EvidenceSource::DECLARED_AUTHENTICATED, "stale.topic",
                                 encoded),
                 epoch - 1U, 1U, 5));
  AIFC_CHECK_OK(stale_publish);
  if (stale_publish) {
    check_error(stale_publish.value(), aifc::ErrorCode::STALE_EPOCH,
                "PUBLISH_EVIDENCE at the previous epoch");
  }
  const auto stale_registration = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::REGISTER_PUBLISHER,
                 payload_register_publisher(connection.publisher, 1U), epoch - 1U, 1U, 6));
  AIFC_CHECK_OK(stale_registration);
  if (stale_registration) {
    check_error(stale_registration.value(), aifc::ErrorCode::STALE_EPOCH,
                "REGISTER_PUBLISHER at the previous epoch");
  }

  // Nothing was applied: no flow, no evidence.
  AIFC_CHECK_EQ(coordinator.classifier().stats().flows.size, std::size_t{0});
  AIFC_CHECK_EQ(coordinator.classifier().stats().evidence.records, std::size_t{0});
  AIFC_CHECK_EQ(coordinator.stats().coordinator.protocol_failures, 0U);

  // An epoch the coordinator has advanced past is stale even though the frame once matched.  The
  // advance is what a restart performs; here it is driven directly because this surface creates
  // no second process (the multiprocess surface covers a real restart).
  AIFC_CHECK_OK(coordinator.classifier().advance_epoch(aifc::CoordinatorBootId{2}));
  const std::uint64_t advanced_epoch = coordinator.epoch().value;
  AIFC_CHECK(advanced_epoch > epoch);
  const auto after_advance = deliver(coordinator, connection,
                                     make_frame(aifc::MessageKind::REGISTER_FLOW, flow_payload,
                                                epoch, 1U, 7));
  AIFC_CHECK_OK(after_advance);
  if (after_advance) {
    check_error(after_advance.value(), aifc::ErrorCode::STALE_EPOCH,
                "REGISTER_FLOW after the epoch advanced");
  }
  // The frame at the new epoch is accepted, which shows the refusals are about the epoch value
  // and not about the connection being permanently broken.
  const auto current = deliver(coordinator, connection,
                               make_frame(aifc::MessageKind::REGISTER_FLOW, flow_payload,
                                          advanced_epoch, 2U, 8));
  AIFC_CHECK_OK(current);
  if (current) {
    AIFC_CHECK(current.value().kind != aifc::MessageKind::ERROR_RESPONSE);
  }
  AIFC_CHECK_EQ(coordinator.classifier().stats().flows.size, std::size_t{1});
}

AIFC_TEST("coordinator/registration: publisher-scoped messages before registration are UNAUTHENTICATED (REAL)") {
  aifc::Coordinator coordinator(make_options());
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const std::uint64_t epoch = coordinator.epoch().value;

  // HELLO only: the handshake is complete but no publisher has been registered on this
  // connection.
  Connection connection;
  connection.key = "connection-0";
  connection.publisher = aifc_test::synthetic_publisher(0U);
  const auto hello = deliver(coordinator, connection,
                             make_frame(aifc::MessageKind::HELLO,
                                        payload_hello(connection.publisher, aifc::kProtocolVersion,
                                                      aifc::kProtocolVersionMin),
                                        epoch));
  AIFC_CHECK_OK(hello);
  if (hello) {
    AIFC_CHECK(hello.value().kind == aifc::MessageKind::HELLO_ACK);
  }
  AIFC_CHECK(!connection.session.registered);

  bool encoded = false;
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(2U);
  const aifc::ByteBuffer flow_payload = payload_register_flow(key, 0U, encoded);
  AIFC_CHECK(encoded);

  aifc::DeclareWorkloadRequest declare;
  declare.workload = aifc_test::synthetic_workload(0U);
  declare.generation = aifc::WorkloadGeneration{1};
  aifc::ByteBuffer declare_payload;
  AIFC_CHECK_OK(aifc::encode_declare_workload(declare, declare_payload));

  aifc::ContractReferenceRequest reference;
  reference.contract = aifc_test::synthetic_contract(0U);
  aifc::ByteBuffer reference_payload;
  AIFC_CHECK_OK(aifc::encode_contract_reference(reference, reference_payload));

  aifc::ProposeContractRequest propose;
  propose.contract.id = aifc_test::synthetic_contract(0U);
  propose.contract.workload = aifc_test::synthetic_workload(0U);
  propose.contract.workload_generation = aifc::WorkloadGeneration{1};
  propose.contract.declared_class = aifc::SemanticClass::COLLECTIVE;
  propose.contract.match_any_remote_address = true;
  aifc::ByteBuffer propose_payload;
  AIFC_CHECK_OK(aifc::encode_propose_contract(propose, propose_payload));

  aifc::WithdrawEvidenceRequest withdraw;
  withdraw.evidence = aifc::make_evidence_id("ev-0000000000000001");
  withdraw.reason = "not registered";
  aifc::ByteBuffer withdraw_payload;
  AIFC_CHECK_OK(aifc::encode_withdraw_evidence(withdraw, withdraw_payload));

  aifc::RevokeGenerationRequest revoke;
  revoke.flow_id = aifc::derive_flow_id(key);
  revoke.generation = aifc::FlowGeneration{1};
  revoke.reason = "not registered";
  aifc::ByteBuffer revoke_payload;
  AIFC_CHECK_OK(aifc::encode_revoke_generation(revoke, revoke_payload));

  struct Scoped {
    const char* what;
    aifc::MessageKind kind;
    aifc::ByteBuffer payload;
  };
  const Scoped scoped[] = {
      {"REGISTER_FLOW", aifc::MessageKind::REGISTER_FLOW, flow_payload},
      {"DECLARE_WORKLOAD", aifc::MessageKind::DECLARE_WORKLOAD, declare_payload},
      {"PROPOSE_CONTRACT", aifc::MessageKind::PROPOSE_CONTRACT, propose_payload},
      {"ACTIVATE_CONTRACT", aifc::MessageKind::ACTIVATE_CONTRACT, reference_payload},
      {"RETIRE_CONTRACT", aifc::MessageKind::RETIRE_CONTRACT, reference_payload},
      {"WITHDRAW_EVIDENCE", aifc::MessageKind::WITHDRAW_EVIDENCE, withdraw_payload},
      {"REVOKE_GENERATION", aifc::MessageKind::REVOKE_GENERATION, revoke_payload},
  };
  std::uint64_t sequence = 10;
  for (const Scoped& entry : scoped) {
    const auto response = deliver(coordinator, connection,
                                  make_frame(entry.kind, entry.payload, epoch, 1U, sequence++));
    AIFC_CHECK_OK(response);
    if (!response) continue;
    check_error(response.value(), aifc::ErrorCode::UNAUTHENTICATED,
                std::string(entry.what) + " before REGISTER_PUBLISHER");
    const auto decoded = aifc::decode_error_response(response.value().payload, client_limits());
    if (decoded) {
      AIFC_CHECK_MSG(contains(decoded.value().message, "REGISTER_PUBLISHER"),
                     std::string(entry.what) +
                         " must be told which message is required first, got: " +
                         decoded.value().message);
    }
  }
  // A PUBLISH_EVIDENCE frame is publisher scoped too, and needs an encodable payload.
  const auto not_registered = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::PUBLISH_EVIDENCE,
                 payload_publish(key, aifc::FlowGeneration{1}, 1U, aifc::SemanticClass::COLLECTIVE,
                                 aifc::EvidenceSource::DECLARED_AUTHENTICATED, "unregistered.topic",
                                 encoded),
                 epoch, 1U, sequence++));
  AIFC_CHECK_OK(not_registered);
  if (not_registered) {
    check_error(not_registered.value(), aifc::ErrorCode::UNAUTHENTICATED,
                "PUBLISH_EVIDENCE before REGISTER_PUBLISHER");
  }

  // Nothing was applied by any of the refused messages.
  AIFC_CHECK_EQ(coordinator.classifier().stats().flows.size, std::size_t{0});
  AIFC_CHECK_EQ(coordinator.classifier().stats().workloads.workloads, std::size_t{0});
  AIFC_CHECK_EQ(coordinator.classifier().stats().evidence.records, std::size_t{0});

  // A heartbeat is contact, not a publisher-scoped operation, and classification is deliberately
  // not publisher scoped: asking what a flow is does not require being able to say what it is.
  const auto heartbeat = deliver(coordinator, connection,
                                 make_frame(aifc::MessageKind::HEARTBEAT, aifc::ByteBuffer{}, epoch,
                                            1U, sequence++));
  AIFC_CHECK_OK(heartbeat);
  if (heartbeat) {
    AIFC_CHECK(heartbeat.value().kind == aifc::MessageKind::HELLO_ACK);
  }
  const auto stats_request =
      deliver(coordinator, connection,
              make_frame(aifc::MessageKind::STATS_REQUEST, aifc::ByteBuffer{}, epoch, 1U,
                         sequence++));
  AIFC_CHECK_OK(stats_request);
  if (stats_request) {
    AIFC_CHECK(stats_request.value().kind == aifc::MessageKind::STATS_RESPONSE);
  }
  const auto classify = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::CLASSIFY, payload_classify(key, 0U, false, encoded), epoch, 1U,
                 sequence++));
  AIFC_CHECK_OK(classify);
  if (classify) {
    // The batch itself succeeds; the per-key status says the flow is unknown.
    AIFC_CHECK(classify.value().kind == aifc::MessageKind::CLASSIFY_RESULT);
    const auto body = aifc::decode_classify_response(classify.value().payload, client_limits());
    AIFC_CHECK_OK(body);
    if (body) {
      AIFC_CHECK_EQ(body.value().succeeded, 0U);
      AIFC_CHECK_EQ(body.value().failed, 1U);
      AIFC_CHECK_EQ(body.value().per_key_codes.size(), std::size_t{1});
      if (body.value().per_key_codes.size() == 1U) {
        AIFC_CHECK(body.value().per_key_codes[0] == aifc::ErrorCode::UNKNOWN_FLOW);
      }
    }
  }

  // Completing the registration makes the same messages work.
  const auto registered = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::REGISTER_PUBLISHER,
                 payload_register_publisher(connection.publisher, 1U), epoch, 1U, sequence++));
  AIFC_CHECK_OK(registered);
  if (registered) {
    AIFC_CHECK(registered.value().kind == aifc::MessageKind::HELLO_ACK);
  }
  const auto now_allowed = deliver(coordinator, connection,
                                   make_frame(aifc::MessageKind::REGISTER_FLOW, flow_payload,
                                              epoch, 1U, sequence++));
  AIFC_CHECK_OK(now_allowed);
  if (now_allowed) {
    AIFC_CHECK(now_allowed.value().kind != aifc::MessageKind::ERROR_RESPONSE);
  }
  AIFC_CHECK_EQ(coordinator.classifier().stats().flows.size, std::size_t{1});
}

AIFC_TEST("coordinator/version: a protocol version outside the supported range is refused (REAL)") {
  aifc::Coordinator coordinator(make_options());
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const std::uint64_t epoch = coordinator.epoch().value;
  const aifc::PublisherId publisher = aifc_test::synthetic_publisher(0U);

  struct VersionCase {
    const char* what;
    std::uint16_t version;
    std::uint16_t version_min;
    bool accepted;
  };
  // A handshake succeeds when the peer's advertised range [version_min, version] intersects the
  // range this build speaks.  A peer whose maximum is above ours is compatible as long as its
  // minimum is not, so only a range that misses ours entirely is refused.
  const VersionCase cases[] = {
      {"current version, minimum 0", aifc::kProtocolVersion, 0U, true},
      {"current version, current minimum", aifc::kProtocolVersion, aifc::kProtocolVersionMin, true},
      {"version above the supported maximum with an overlapping minimum",
       static_cast<std::uint16_t>(aifc::kProtocolVersion + 1U), aifc::kProtocolVersionMin, true},
      {"version below the supported minimum", 0U, 0U, false},
      {"range entirely above the supported maximum",
       static_cast<std::uint16_t>(aifc::kProtocolVersion + 5U),
       static_cast<std::uint16_t>(aifc::kProtocolVersion + 5U), false},
      {"minimum above the supported maximum with a compatible version", aifc::kProtocolVersion,
       static_cast<std::uint16_t>(aifc::kProtocolVersion + 1U), false},
  };

  std::uint64_t sequence = 1;
  for (const VersionCase& test_case : cases) {
    Connection connection;
    connection.key = "connection-version-" + std::to_string(sequence);
    connection.publisher = publisher;
    const auto response = deliver(
        coordinator, connection,
        make_frame(aifc::MessageKind::HELLO,
                   payload_hello(publisher, test_case.version, test_case.version_min), epoch, 1U,
                   sequence));
    ++sequence;
    AIFC_CHECK_OK(response);
    if (!response) continue;
    if (test_case.accepted) {
      AIFC_CHECK_MSG(response.value().kind == aifc::MessageKind::HELLO_ACK,
                     "version case (" << test_case.what << ") must be accepted, but the "
                                      << "coordinator answered "
                                      << aifc::to_string(response.value().kind));
    } else {
      check_error(response.value(), aifc::ErrorCode::UNSUPPORTED_VERSION, test_case.what);
      const auto decoded =
          aifc::decode_error_response(response.value().payload, client_limits());
      if (decoded) {
        AIFC_CHECK_MSG(contains(decoded.value().message, std::to_string(aifc::kProtocolVersion)),
                       "the refusal must name the supported version range, got: "
                           << decoded.value().message);
      }
      // A refused handshake must not open a session.
      AIFC_CHECK(!connection.session.registered);
    }
  }
  AIFC_CHECK_EQ(coordinator.stats().coordinator.protocol_failures, 3U);

  // The wire layer refuses an out-of-range version before any handler sees it, so a peer cannot
  // even reach the handshake with a version the build does not speak.
  const aifc::ByteBuffer unsupported =
      raw_frame(static_cast<std::uint16_t>(aifc::kProtocolVersion + 1U),
                static_cast<std::uint16_t>(aifc::MessageKind::HELLO), aifc::ByteBuffer{});
  aifc::Frame decoded;
  std::size_t consumed = 0;
  const aifc::Status wire = aifc::try_decode_frame(unsupported.data(), unsupported.size(),
                                                   aifc::kMaxFramePayload, decoded, consumed);
  AIFC_CHECK(!wire.ok());
  if (!wire.ok()) {
    AIFC_CHECK_MSG(wire.code == aifc::ErrorCode::UNSUPPORTED_VERSION,
                   "the wire reader produced " << aifc::to_string(wire.code)
                                               << " instead of UNSUPPORTED_VERSION ("
                                               << wire.message << ")");
  }
  AIFC_CHECK_EQ(consumed, std::size_t{0});
}

AIFC_TEST("coordinator/protocol: an undefined message kind is refused (REAL)") {
  aifc::Coordinator coordinator(make_options());
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const std::uint64_t epoch = coordinator.epoch().value;

  // The vocabulary is closed at the wire level.
  AIFC_CHECK(aifc::is_known_message_kind(static_cast<std::uint16_t>(aifc::MessageKind::HELLO)));
  AIFC_CHECK(aifc::is_known_message_kind(aifc::kMaxMessageKind));
  AIFC_CHECK(!aifc::is_known_message_kind(0U));
  AIFC_CHECK(!aifc::is_known_message_kind(static_cast<std::uint16_t>(aifc::kMaxMessageKind + 1U)));
  AIFC_CHECK(!aifc::is_known_message_kind(9001U));
  AIFC_CHECK_EQ(aifc::to_string(static_cast<aifc::MessageKind>(9001)),
                std::string_view("UNRECOGNIZED_MESSAGE_KIND"));
  AIFC_CHECK(aifc::is_response_kind(aifc::MessageKind::HELLO_ACK));
  AIFC_CHECK(aifc::is_response_kind(aifc::MessageKind::ERROR_RESPONSE));
  AIFC_CHECK(!aifc::is_response_kind(aifc::MessageKind::HELLO));

  // The canonical encoder refuses to produce such a frame at all.
  const aifc::FrameHeader undefined_header =
      make_frame(static_cast<aifc::MessageKind>(9001), aifc::ByteBuffer{}, epoch).header;
  const auto encoded = aifc::encode_frame(undefined_header, aifc::ByteBuffer{}, aifc::kMaxFramePayload);
  AIFC_CHECK_ERR(encoded, aifc::ErrorCode::INVALID_ARGUMENT);

  // A hand-built frame that carries one anyway is refused by the reader, so it can never reach a
  // handler.
  const aifc::ByteBuffer raw = raw_frame(aifc::kProtocolVersion, 9001U, aifc::ByteBuffer{});
  aifc::Frame decoded;
  std::size_t consumed = 0;
  const aifc::Status wire = aifc::try_decode_frame(raw.data(), raw.size(), aifc::kMaxFramePayload,
                                                   decoded, consumed);
  AIFC_CHECK(!wire.ok());
  if (!wire.ok()) {
    AIFC_CHECK_MSG(wire.code == aifc::ErrorCode::MALFORMED_FRAME,
                   "the wire reader produced " << aifc::to_string(wire.code)
                                                << " instead of MALFORMED_FRAME (" << wire.message
                                                << ")");
    AIFC_CHECK_MSG(contains(wire.message, "9001"),
                   "the refusal must name the undefined kind, got: " << wire.message);
  }
  AIFC_CHECK_EQ(consumed, std::size_t{0});

  // The handler's default branch is defence in depth: a Frame value carrying an undefined kind
  // is refused explicitly rather than silently ignored.  No peer can reach this through the wire,
  // which is exactly why it is asserted here.
  Connection connection;
  connection.key = "connection-undefined";
  aifc::Frame undefined;
  undefined.header = undefined_header;
  const auto response = coordinator.handle(connection.key, connection.session, undefined);
  AIFC_CHECK_OK(response);
  if (response) {
    check_error(response.value(), aifc::ErrorCode::UNSUPPORTED_OPERATION,
                "an undefined message kind handed to handle()");
    const auto body =
        aifc::decode_error_response(response.value().payload, client_limits());
    if (body) {
      AIFC_CHECK_MSG(contains(body.value().message, "UNRECOGNIZED_MESSAGE_KIND"),
                     "the refusal must name the kind it did not understand, got: "
                         << body.value().message);
    }
  }
  AIFC_CHECK_EQ(coordinator.stats().coordinator.protocol_failures, 1U);

  // Two more wire-level refusals that a peer cannot survive: a frame that does not begin with
  // the magic, and a frame whose integrity tag does not match its contents.
  aifc::ByteBuffer not_a_frame = raw;
  not_a_frame[0] = 'X';
  const aifc::Status magic = aifc::try_decode_frame(not_a_frame.data(), not_a_frame.size(),
                                                    aifc::kMaxFramePayload, decoded, consumed);
  AIFC_CHECK(!magic.ok());
  if (!magic.ok()) {
    AIFC_CHECK_MSG(magic.code == aifc::ErrorCode::MALFORMED_FRAME,
                   "a foreign stream must fail with MALFORMED_FRAME, got "
                       << aifc::to_string(magic.code));
  }
  // The corrupted frame is built from a *valid* frame: corrupting the undefined-kind frame
  // above would be refused for its kind before the integrity tag was ever checked.
  aifc::ByteBuffer corrupted =
      raw_frame(aifc::kProtocolVersion, static_cast<std::uint16_t>(aifc::MessageKind::STATS_REQUEST),
                aifc::ByteBuffer{});
  corrupted[12] ^= 0xFFU;  // flip a byte of the connection sequence field
  const aifc::Status integrity = aifc::try_decode_frame(
      corrupted.data(), corrupted.size(), aifc::kMaxFramePayload, decoded, consumed);
  AIFC_CHECK(!integrity.ok());
  if (!integrity.ok()) {
    AIFC_CHECK_MSG(integrity.code == aifc::ErrorCode::INTEGRITY_FAILURE,
                   "a corrupted frame must fail with INTEGRITY_FAILURE, got "
                       << aifc::to_string(integrity.code));
  }
  // A valid frame still decodes after all of that.
  const auto good = round_trip(make_frame(aifc::MessageKind::STATS_REQUEST, aifc::ByteBuffer{}, epoch));
  AIFC_CHECK_OK(good);
}

AIFC_TEST("coordinator/stats: STATS_REQUEST renders the state the coordinator is actually in (REAL)") {
  aifc::Coordinator coordinator(make_options());
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const std::uint64_t epoch = coordinator.epoch().value;

  // A statistics request is not publisher scoped: an operator can ask without registering a publisher.
  // It does require a completed handshake, so that a stranger cannot probe the runtime by guessing the
  // current epoch; the case below is about what the response says, not about admission.
  Connection anonymous;
  anonymous.key = "connection-anonymous";
  if (!handshake(coordinator, anonymous, 0U, 1U, epoch)) return;
  const auto before = deliver(coordinator, anonymous,
                              make_frame(aifc::MessageKind::STATS_REQUEST, aifc::ByteBuffer{},
                                         epoch, 1U, 1));
  AIFC_CHECK_OK(before);
  if (before) {
    AIFC_CHECK(before.value().kind == aifc::MessageKind::STATS_RESPONSE);
    const auto body = aifc::decode_stats_response(before.value().payload, client_limits());
    AIFC_CHECK_OK(body);
    if (body) {
      AIFC_CHECK_MSG(contains(body.value().rendered, "epoch=" + std::to_string(epoch)),
                     "stats must report the epoch, got: " << body.value().rendered);
      AIFC_CHECK_MSG(contains(body.value().rendered, "flows=0"),
                     "stats must report the flow count, got: " << body.value().rendered);
    }
  }

  Connection connection;
  connection.key = "connection-0";
  if (!handshake(coordinator, connection, 0U, 1U, epoch)) return;
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(3U);
  bool encoded = false;
  const auto flow_response = deliver(coordinator, connection,
                                     make_frame(aifc::MessageKind::REGISTER_FLOW,
                                                payload_register_flow(key, 0U, encoded), epoch, 1U, 2));
  AIFC_CHECK_OK(flow_response);
  const auto publish_response = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::PUBLISH_EVIDENCE,
                 payload_publish(key, aifc::FlowGeneration{1}, 1U, aifc::SemanticClass::TELEMETRY,
                                 aifc::EvidenceSource::DECLARED_AUTHENTICATED, "stats.topic",
                                 encoded),
                 epoch, 1U, 3));
  AIFC_CHECK_OK(publish_response);

  const auto response = deliver(coordinator, connection,
                                make_frame(aifc::MessageKind::STATS_REQUEST, aifc::ByteBuffer{},
                                           epoch, 1U, 4));
  AIFC_CHECK_OK(response);
  if (!response) return;
  AIFC_CHECK(response.value().kind == aifc::MessageKind::STATS_RESPONSE);
  const auto body = aifc::decode_stats_response(response.value().payload, client_limits());
  AIFC_CHECK_OK(body);
  if (!body) return;

  // Every number in the rendering is compared against the coordinator's own view, so the test
  // fails if the rendering and the state ever disagree.
  const aifc::Coordinator::Stats stats = coordinator.stats();
  AIFC_CHECK_MSG(contains(body.value().rendered, "epoch=" + stats.classifier.epoch.to_string()),
                 "stats must report epoch " << stats.classifier.epoch.to_string() << ", got: "
                                            << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered,
                          "boot=" + stats.classifier.coordinator_boot.to_string()),
                 "stats must report the boot incarnation, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered,
                          "publishers=" + std::to_string(stats.classifier.publishers.publishers)),
                 "stats must report the publisher count, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered, "flows=1"),
                 "stats must report one flow, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered, "evidence=1"),
                 "stats must report one evidence record, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered,
                          "messages=" + std::to_string(stats.coordinator.messages_handled)),
                 "stats must report the handled message count, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered,
                          "refused=" + std::to_string(stats.coordinator.messages_refused)),
                 "stats must report the refused message count, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered, "decisions="),
                 "stats must report the decision count, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered, "memo="),
                 "stats must report the memo size, got: " << body.value().rendered);
  AIFC_CHECK_MSG(contains(body.value().rendered, "live="),
                 "stats must report the live publisher count, got: " << body.value().rendered);

  // The rendering is stable: the same state renders identically.
  const auto again = deliver(coordinator, connection,
                             make_frame(aifc::MessageKind::STATS_REQUEST, aifc::ByteBuffer{},
                                        epoch, 1U, 5));
  AIFC_CHECK_OK(again);
  if (again) {
    const auto second = aifc::decode_stats_response(again.value().payload, client_limits());
    AIFC_CHECK_OK(second);
    if (second) {
      // Only the message counter differs, and it differs by exactly one.
      AIFC_CHECK_MSG(contains(second.value().rendered, "messages=" +
                                                           std::to_string(stats.coordinator.messages_handled + 1U)),
                     "the second rendering must report one more handled message, got: "
                         << second.value().rendered);
    }
  }
}

AIFC_TEST("coordinator/session_end: close_session makes the session's evidence non-current (REAL)") {
  aifc::Coordinator coordinator(make_options());
  AIFC_CHECK_OK(coordinator.start(aifc::CoordinatorBootId{1}));
  const std::uint64_t epoch = coordinator.epoch().value;

  Connection connection;
  connection.key = "connection-0";
  if (!handshake(coordinator, connection, 0U, 1U, epoch)) return;
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(4U);
  bool encoded = false;
  AIFC_CHECK_OK(deliver(coordinator, connection,
                        make_frame(aifc::MessageKind::REGISTER_FLOW,
                                   payload_register_flow(key, 0U, encoded), epoch, 1U, 2)));
  const auto publish_response = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::PUBLISH_EVIDENCE,
                 payload_publish(key, aifc::FlowGeneration{1}, 1U, aifc::SemanticClass::COLLECTIVE,
                                 aifc::EvidenceSource::DECLARED_AUTHENTICATED, "closed.topic",
                                 encoded),
                 epoch, 1U, 3));
  AIFC_CHECK_OK(publish_response);
  if (!publish_response) return;
  const auto published =
      aifc::decode_publish_evidence_response(publish_response.value().payload, client_limits());
  AIFC_CHECK_OK(published);
  if (!published) return;

  // While the session is open the class is current.
  const auto before = deliver(coordinator, connection,
                              make_frame(aifc::MessageKind::CLASSIFY,
                                         payload_classify(key, 0U, true, encoded), epoch, 1U, 4));
  AIFC_CHECK_OK(before);
  if (before) {
    const auto body = aifc::decode_classify_response(before.value().payload, client_limits());
    AIFC_CHECK_OK(body);
    if (body && body.value().classifications.size() == 1U) {
      AIFC_CHECK(body.value().classifications[0].state == aifc::ClassificationState::CURRENT);
      AIFC_CHECK(body.value().classifications[0].semantic == aifc::SemanticClass::COLLECTIVE);
    }
  }
  AIFC_CHECK_EQ(coordinator.stats().coordinator.active_sessions, std::size_t{1});

  coordinator.close_session(connection.key, connection.session);

  // The connection is gone from the coordinator's table and the publisher incarnation is no
  // longer live.
  AIFC_CHECK_EQ(coordinator.stats().coordinator.active_sessions, std::size_t{0});
  const auto registration = coordinator.classifier().find_publisher(connection.publisher);
  AIFC_CHECK_OK(registration);
  if (registration) {
    AIFC_CHECK_MSG(registration.value().state == aifc::PublisherState::DEAD,
                   "the publisher state is " << aifc::to_string(registration.value().state)
                                             << " rather than DEAD");
  }

  // The evidence is marked stale with a reason that names the publisher and the incarnation,
  // and the answer follows: no class is current any more, but the record is still cited.
  const auto record = coordinator.classifier().find_evidence(published.value().evidence_id);
  AIFC_CHECK_OK(record);
  if (record) {
    AIFC_CHECK_MSG(record.value().state == aifc::EvidenceState::EVIDENCE_STALE,
                   "evidence published through a closed session is "
                       << aifc::to_string(record.value().state) << " rather than STALE");
    AIFC_CHECK_MSG(contains(record.value().state_reason, connection.publisher.value()) &&
                       contains(record.value().state_reason, connection.boot.to_string()),
                   "the reason must name the publisher and boot, got: "
                       << record.value().state_reason);
  }

  const auto after = deliver(coordinator, connection,
                             make_frame(aifc::MessageKind::CLASSIFY,
                                        payload_classify(key, 0U, true, encoded), epoch, 1U, 5));
  AIFC_CHECK_OK(after);
  if (after) {
    const auto body = aifc::decode_classify_response(after.value().payload, client_limits());
    AIFC_CHECK_OK(body);
    if (body && body.value().classifications.size() == 1U) {
      const aifc::Classification& classification = body.value().classifications[0];
      AIFC_CHECK_MSG(classification.semantic == aifc::SemanticClass::UNKNOWN,
                     "a closed session must not leave a class published, but it reported "
                         << aifc::to_string(classification.semantic));
      AIFC_CHECK(classification.state == aifc::ClassificationState::STALE);
      AIFC_CHECK_EQ(classification.confidence.to_decimal(), std::string("0.0000"));
      AIFC_CHECK_EQ(classification.citations.size(), std::size_t{1});
      if (classification.citations.size() == 1U) {
        AIFC_CHECK(classification.citations[0].disposition ==
                   aifc::EvidenceDisposition::STALE);
        AIFC_CHECK_MSG(contains(classification.citations[0].detail, connection.publisher.value()),
                       "the citation must name the publisher, got: "
                           << classification.citations[0].detail);
      }
    }
  }

  // Publishing again through the closed session is refused.  The connection key is gone, so the
  // refusal is about the session state rather than about the transport.
  const auto refused = deliver(
      coordinator, connection,
      make_frame(aifc::MessageKind::PUBLISH_EVIDENCE,
                 payload_publish(key, aifc::FlowGeneration{1}, 2U, aifc::SemanticClass::TELEMETRY,
                                 aifc::EvidenceSource::DECLARED_AUTHENTICATED, "closed.again",
                                 encoded),
                 epoch, 1U, 6));
  AIFC_CHECK_OK(refused);
  if (refused) {
    // The session binding is checked before liveness, so a closed session is refused as
    // UNAUTHENTICATED rather than PUBLISHER_DEAD.  Both are authority failures and both stop
    // the publication, which is the property under test.
    const aifc::ErrorCode code =
        error_code_of(refused.value(), "PUBLISH_EVIDENCE through a closed session");
    AIFC_CHECK_MSG(code == aifc::ErrorCode::PUBLISHER_DEAD ||
                       code == aifc::ErrorCode::UNAUTHENTICATED,
                   "a closed session must be refused as an authority failure, got "
                       << aifc::to_string(code));
    AIFC_CHECK(aifc::is_authority_failure(code));
  }
  AIFC_CHECK_EQ(coordinator.classifier().stats().evidence.records, std::size_t{1});

  // Closing a session that was never registered is a no-op rather than a crash or a failure.
  Connection unregistered;
  unregistered.key = "connection-never-registered";
  coordinator.close_session(unregistered.key, unregistered.session);
  AIFC_CHECK_EQ(coordinator.stats().coordinator.active_sessions, std::size_t{0});
  AIFC_CHECK_EQ(coordinator.classifier().stats().evidence.records, std::size_t{1});
}
