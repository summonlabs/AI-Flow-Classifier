// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Proof surface: the framed protocol over a real loopback TCP connection.
//
// REAL: this surface starts a real listening socket, connects with a real client socket,
// and exchanges real bytes through the operating system's TCP stack.  Nothing here is an
// in-process queue.
//
// SYNTHETIC: the flow metadata, publisher identities and workload names are invented by the
// test.  No AI fabric hardware, NIC, RDMA device or capture infrastructure is involved.
//
// The point of the surface is that a claim which is only true in-process does not survive
// contact with a socket: framing, partial reads, connection teardown and shutdown all
// behave differently over a real connection, and these cases exercise that.

#include "test_framework.hpp"

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "synthetic.hpp"

namespace {

// A small client that keeps the coordinator's protocol rules on the client side of the
// connection, so that the test does not depend on any in-process shortcut.
class WireClient {
 public:
  explicit WireClient(std::uint16_t port) {
    auto connected = aifc::connect_loopback(port);
    if (!connected) {
      std::fprintf(stderr, "connect failed: %s\n", aifc::render_status(connected.status()).c_str());
      std::abort();
    }
    channel_ = std::make_unique<aifc::Channel>(std::move(connected).value(),
                                               aifc::kMaxFramePayload);
  }

  aifc::Status send(aifc::MessageKind kind, const aifc::ByteBuffer& payload) {
    return channel_->send(kind, payload, epoch_, boot_);
  }

  aifc::Result<aifc::Frame> receive() { return channel_->receive(std::chrono::milliseconds(4000)); }

  void set_epoch(std::uint64_t epoch) { epoch_ = epoch; }
  void set_boot(std::uint64_t boot) { boot_ = boot; }
  [[nodiscard]] aifc::Channel& channel() { return *channel_; }

 private:
  std::unique_ptr<aifc::Channel> channel_;
  std::uint64_t epoch_ = 0;
  std::uint64_t boot_ = 0;
};

[[nodiscard]] aifc::HelloRequest hello_for(const aifc::PublisherId& publisher) {
  aifc::HelloRequest hello;
  hello.role = aifc::PeerRole::PUBLISHER;
  hello.protocol_version = aifc::kProtocolVersion;
  hello.protocol_version_min = aifc::kProtocolVersionMin;
  hello.client_name = "loopback-proof-client";
  hello.publisher = publisher;
  return hello;
}

[[nodiscard]] aifc::ByteBuffer encode_payload(const aifc::Status& status) {
  (void)status;
  return aifc::ByteBuffer{};
}

// Drives a complete handshake and publisher registration against a running service.
struct Handshake {
  aifc::SessionId session;
  aifc::CoordinatorEpoch epoch;
  aifc::CoordinatorBootId boot;
  aifc::EvidenceSource granted = aifc::EvidenceSource::HEURISTIC;
};

[[nodiscard]] Handshake handshake(WireClient& client, const aifc::PublisherId& publisher,
                                 aifc::PublisherBootId boot) {
  aifc::ByteBuffer payload;
  AIFC_CHECK_OK(aifc::encode_hello(hello_for(publisher), payload));
  auto sent = client.send(aifc::MessageKind::HELLO, payload);
  AIFC_CHECK_MSG(sent.ok(), aifc::render_status(sent));

  auto response = client.receive();
  if (!response) {
    AIFC_CHECK_MSG(false, "no HELLO_ACK: " + aifc::render_status(response.status()));
    return Handshake{};
  }
  if (response.value().header.kind != aifc::MessageKind::HELLO_ACK) {
    AIFC_CHECK_MSG(false, "expected HELLO_ACK, got " +
                              std::string(aifc::to_string(response.value().header.kind)));
    return Handshake{};
  }
  auto ack = aifc::decode_hello_response(response.value().payload,
                                        aifc::CodecLimits::from(aifc::ResourceLimits{}));
  AIFC_CHECK_OK(ack);
  client.set_epoch(ack.value().epoch.value);
  client.set_boot(ack.value().boot.value);

  aifc::RegisterPublisherRequest registration;
  registration.publisher = publisher;
  registration.boot = boot;
  registration.description = "loopback proof publisher";
  aifc::ByteBuffer registration_bytes;
  AIFC_CHECK_OK(aifc::encode_register_publisher(registration, registration_bytes));
  auto registration_sent = client.send(aifc::MessageKind::REGISTER_PUBLISHER, registration_bytes);
  AIFC_CHECK_MSG(registration_sent.ok(), aifc::render_status(registration_sent));

  auto registration_response = client.receive();
  if (!registration_response) {
    AIFC_CHECK_MSG(false, "no registration response: " +
                              aifc::render_status(registration_response.status()));
    return Handshake{};
  }
  auto decoded = aifc::decode_register_publisher_response(
      registration_response.value().payload, aifc::CodecLimits::from(aifc::ResourceLimits{}));
  AIFC_CHECK_OK(decoded);
  Handshake result;
  result.session = decoded.value().session;
  result.epoch = decoded.value().epoch;
  result.boot = decoded.value().boot;
  result.granted = decoded.value().granted_source;
  return result;
}

}  // namespace

AIFC_TEST("loopback transport: handshake, register, publish, classify over real sockets") {
  aifc::CoordinatorServiceOptions options;
  options.coordinator.policy = aifc::ClassifierPolicy::initial();
  options.port = 0;
  options.worker_threads = 2;
  aifc::CoordinatorService service(options);
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));
  AIFC_CHECK_NE(service.port(), std::uint16_t{0});

  {
    const aifc::PublisherId publisher = aifc::make_publisher_id("wire-publisher");
    WireClient client(service.port());
    const Handshake session = handshake(client, publisher, aifc::PublisherBootId{1});
    AIFC_CHECK(!session.session.empty());
    // The first incarnation serves epoch 2, not 1.  The classifier is constructed at epoch 1 and
    // Coordinator::start advances it so that the running incarnation is distinguishable from any
    // state it restored; a client should always learn the epoch from the handshake rather than
    // assume it, which is exactly what this assertion makes explicit.
    AIFC_CHECK_EQ(session.epoch.value, std::uint64_t{2});

    const aifc::FlowKey key = aifc_test::synthetic_flow_key(1);
    aifc::RegisterFlowRequest flow_request;
    flow_request.key = key;
    flow_request.generation = aifc::FlowGeneration{0};
    aifc::ByteBuffer flow_bytes;
    AIFC_CHECK_OK(aifc::encode_register_flow(flow_request, flow_bytes));
    AIFC_CHECK_OK(client.send(aifc::MessageKind::REGISTER_FLOW, flow_bytes));
    auto flow_response = client.receive();
    AIFC_CHECK_OK(flow_response);
    auto flow_decoded = aifc::decode_register_flow_response(
        flow_response.value().payload, aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(flow_decoded);
    AIFC_CHECK(flow_decoded.value().generation.valid());

    aifc::PublishEvidenceRequest publish;
    publish.payload.flow_key = key;
    publish.payload.flow_generation = flow_decoded.value().generation;
    publish.payload.evidence_generation = aifc::EvidenceGeneration{1};
    publish.payload.semantic = aifc::SemanticClass::TRAINING_SYNC;
    publish.payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    publish.payload.metadata.topic = "wire.topic";
    publish.payload.metadata.reason = "published over a real socket";
    aifc::ByteBuffer publish_bytes;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(publish, publish_bytes));
    AIFC_CHECK_OK(client.send(aifc::MessageKind::PUBLISH_EVIDENCE, publish_bytes));
    auto publish_response = client.receive();
    AIFC_CHECK_OK(publish_response);
    auto publish_decoded = aifc::decode_publish_evidence_response(
        publish_response.value().payload, aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(publish_decoded);
    AIFC_CHECK_EQ(static_cast<int>(publish_decoded.value().effective_source),
                  static_cast<int>(aifc::EvidenceSource::DECLARED_AUTHENTICATED));

    aifc::ClassifyRequest classify;
    aifc::ClassifyQueryEntry entry;
    entry.key = key;
    entry.explain = true;
    classify.entries.push_back(entry);
    aifc::ByteBuffer classify_bytes;
    AIFC_CHECK_OK(aifc::encode_classify_request(classify, classify_bytes));
    AIFC_CHECK_OK(client.send(aifc::MessageKind::CLASSIFY, classify_bytes));
    auto classify_response = client.receive();
    AIFC_CHECK_OK(classify_response);
    AIFC_CHECK_EQ(static_cast<int>(classify_response.value().header.kind),
                  static_cast<int>(aifc::MessageKind::CLASSIFY_RESULT));
    auto classify_decoded = aifc::decode_classify_response(
        classify_response.value().payload, aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(classify_decoded);
    AIFC_CHECK_EQ(classify_decoded.value().classifications.size(), std::size_t{1});
    AIFC_CHECK_EQ(static_cast<int>(classify_decoded.value().classifications.front().semantic),
                  static_cast<int>(aifc::SemanticClass::TRAINING_SYNC));
    AIFC_CHECK_EQ(classify_decoded.value().succeeded, std::uint32_t{1});
    AIFC_CHECK_EQ(classify_decoded.value().failed, std::uint32_t{0});
    AIFC_CHECK(!classify_decoded.value().explanations.empty());
  }

  AIFC_CHECK_OK(service.stop());
  AIFC_CHECK(!service.running());
}

AIFC_TEST("loopback transport: a stale epoch is refused over the wire") {
  aifc::CoordinatorServiceOptions options;
  options.port = 0;
  options.worker_threads = 1;
  aifc::CoordinatorService service(options);
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));

  {
    WireClient client(service.port());
    const Handshake session =
        handshake(client, aifc::make_publisher_id("stale-epoch-publisher"), aifc::PublisherBootId{1});
    AIFC_CHECK(!session.session.empty());

    // Claim an epoch the coordinator does not serve.
    client.set_epoch(session.epoch.value + 7);
    const aifc::FlowKey key = aifc_test::synthetic_flow_key(2);
    aifc::RegisterFlowRequest flow_request;
    flow_request.key = key;
    aifc::ByteBuffer bytes;
    AIFC_CHECK_OK(aifc::encode_register_flow(flow_request, bytes));
    AIFC_CHECK_OK(client.send(aifc::MessageKind::REGISTER_FLOW, bytes));
    auto response = client.receive();
    AIFC_CHECK_OK(response);
    AIFC_CHECK_EQ(static_cast<int>(response.value().header.kind),
                  static_cast<int>(aifc::MessageKind::ERROR_RESPONSE));
    auto error = aifc::decode_error_response(response.value().payload,
                                             aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(error);
    AIFC_CHECK_EQ(error.value().code, aifc::ErrorCode::STALE_EPOCH);
  }
  AIFC_CHECK_OK(service.stop());
}

AIFC_TEST("loopback transport: an unsupported protocol version is refused") {
  aifc::CoordinatorServiceOptions options;
  options.port = 0;
  options.worker_threads = 1;
  aifc::CoordinatorService service(options);
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));

  {
    WireClient client(service.port());
    aifc::HelloRequest hello = hello_for(aifc::make_publisher_id("old-peer"));
    hello.protocol_version = 99;
    hello.protocol_version_min = 99;
    aifc::ByteBuffer bytes;
    AIFC_CHECK_OK(aifc::encode_hello(hello, bytes));
    AIFC_CHECK_OK(client.send(aifc::MessageKind::HELLO, bytes));
    auto response = client.receive();
    AIFC_CHECK_OK(response);
    AIFC_CHECK_EQ(static_cast<int>(response.value().header.kind),
                  static_cast<int>(aifc::MessageKind::ERROR_RESPONSE));
    auto error = aifc::decode_error_response(response.value().payload,
                                             aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(error);
    AIFC_CHECK_EQ(error.value().code, aifc::ErrorCode::UNSUPPORTED_VERSION);
  }
  AIFC_CHECK_OK(service.stop());
}

AIFC_TEST("loopback transport: publishing before registering is refused with UNAUTHENTICATED") {
  aifc::CoordinatorServiceOptions options;
  options.port = 0;
  options.worker_threads = 1;
  aifc::CoordinatorService service(options);
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));

  {
    WireClient client(service.port());
    aifc::ByteBuffer hello_bytes;
    AIFC_CHECK_OK(aifc::encode_hello(hello_for(aifc::make_publisher_id("unregistered")), hello_bytes));
    AIFC_CHECK_OK(client.send(aifc::MessageKind::HELLO, hello_bytes));
    auto ack = client.receive();
    AIFC_CHECK_OK(ack);
    auto decoded = aifc::decode_hello_response(ack.value().payload,
                                              aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(decoded);
    client.set_epoch(decoded.value().epoch.value);
    client.set_boot(decoded.value().boot.value);

    aifc::PublishEvidenceRequest publish;
    publish.payload.flow_key = aifc_test::synthetic_flow_key(3);
    publish.payload.evidence_generation = aifc::EvidenceGeneration{1};
    publish.payload.semantic = aifc::SemanticClass::COLLECTIVE;
    publish.payload.metadata.topic = "before.registration";
    aifc::ByteBuffer bytes;
    AIFC_CHECK_OK(aifc::encode_publish_evidence(publish, bytes));
    AIFC_CHECK_OK(client.send(aifc::MessageKind::PUBLISH_EVIDENCE, bytes));
    auto response = client.receive();
    AIFC_CHECK_OK(response);
    auto error = aifc::decode_error_response(response.value().payload,
                                             aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(error);
    AIFC_CHECK_EQ(error.value().code, aifc::ErrorCode::UNAUTHENTICATED);
  }
  AIFC_CHECK_OK(service.stop());
}

AIFC_TEST("loopback transport: a corrupted frame closes the connection") {
  aifc::CoordinatorServiceOptions options;
  options.port = 0;
  options.worker_threads = 1;
  aifc::CoordinatorService service(options);
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));

  {
    auto connected = aifc::connect_loopback(service.port());
    AIFC_CHECK_OK(connected);
    aifc::Socket socket = std::move(connected).value();

    // A complete frame whose integrity tag does not match.  Closing the connection is the only honest
    // response, because the stream is no longer trustworthy.
    //
    // The whole frame goes in one write on purpose.  An earlier version sent a four-byte prefix, waited,
    // then sent the rest, and asserted that nothing was answered in between -- which assumes TCP
    // preserves write boundaries, and it does not: the two writes can be coalesced into one read, at
    // which point the coordinator sees a complete frame with a bad tag and correctly answers with an
    // integrity error.  The partial-frame behaviour is asserted by the frame adversarial surface, where
    // it can be tested without a socket.
    aifc::ByteBuffer bytes;
    AIFC_CHECK_OK(aifc::encode_hello(hello_for(aifc::make_publisher_id("corruptor")), bytes));
    bytes[bytes.size() - 1] = static_cast<std::uint8_t>(bytes[bytes.size() - 1] ^ 0xFFU);
    AIFC_CHECK_OK(socket.send(bytes.data(), bytes.size()));

    // The coordinator must not answer, and must close.  The window is generous because the decision is
    // made inside the connection's own receive loop rather than immediately.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(6000);
    std::uint8_t buffer[512];
    bool closed = false;
    while (std::chrono::steady_clock::now() < deadline) {
      auto readable = socket.wait_readable(std::chrono::milliseconds(200));
      if (!readable) break;
      if (!readable.value()) continue;
      auto received = socket.receive(buffer, sizeof(buffer));
      if (!received) {
        closed = true;
        break;
      }
      if (received.value() == 0) {
        closed = true;
        break;
      }
      AIFC_FAIL("the coordinator answered a frame with a bad integrity tag; an unparseable stream "
                "must not be answered at all");
      break;
    }
    AIFC_CHECK_MSG(closed, "the coordinator did not close a connection that sent a corrupt frame");
  }
  AIFC_CHECK_OK(service.stop());
}

AIFC_TEST("loopback transport: many sequential connections are served and accounted") {
  aifc::CoordinatorServiceOptions options;
  options.port = 0;
  options.worker_threads = 2;
  aifc::CoordinatorService service(options);
  AIFC_CHECK_OK(service.start(aifc::CoordinatorBootId{1}));

  constexpr std::uint32_t kConnections = 12;
  for (std::uint32_t i = 0; i < kConnections; ++i) {
    WireClient client(service.port());
    const Handshake session = handshake(client, aifc::make_publisher_id("bulk-" + std::to_string(i)),
                                        aifc::PublisherBootId{1});
    AIFC_CHECK(!session.session.empty());
    aifc::ByteBuffer stats_request;
    AIFC_CHECK_OK(client.send(aifc::MessageKind::STATS_REQUEST, stats_request));
    auto stats_response = client.receive();
    AIFC_CHECK_OK(stats_response);
    auto stats = aifc::decode_stats_response(stats_response.value().payload,
                                            aifc::CodecLimits::from(aifc::ResourceLimits{}));
    AIFC_CHECK_OK(stats);
    AIFC_CHECK(!stats.value().rendered.empty());
  }

  // Give the workers a moment to retire the last session, then stop and check accounting.
  AIFC_CHECK_OK(service.stop());
  const aifc::ServiceStats stats = service.stats();
  AIFC_CHECK_EQ(stats.active_connections, std::size_t{0});
  AIFC_CHECK_EQ(stats.queued, std::size_t{0});
  AIFC_CHECK(stats.accepted >= kConnections);
}
