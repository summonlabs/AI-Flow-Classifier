// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Proof surface: authority held by real, independent, killable OS processes.
//
// REAL: the coordinator and every publisher here are separate operating system processes started
// from their own image, communicating over real loopback TCP sockets.  Publishers and coordinators
// are killed with an immediate termination that runs no destructor and performs no flush, which is
// the failure mode an honest test has to reproduce.
//
// SYNTHETIC: the flow metadata and workload names are invented.  No AI fabric hardware, no capture
// infrastructure and no kernel bypass is involved.
//
// The claim under test is the one that cannot be tested in-process: when a publisher process dies
// abruptly, the evidence it published stops carrying current authority -- and when a coordinator dies
// abruptly and comes back, pre-restart authority is refused rather than resurrected.

#include "test_framework.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"
#include "ai_flow_classifier/io/files.hpp"
#include "process.hpp"
#include "synthetic.hpp"

namespace {

const aifc::CodecLimits kLimits = aifc::CodecLimits::from(aifc::ResourceLimits{});

aifc::Status write_text(const std::string& path, const std::string& text) {
  return aifc::atomic_replace(path, reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
}

aifc::Result<std::string> read_text(const std::string& path) {
  auto bytes = aifc::read_all(path, 64 * 1024);
  if (!bytes) return bytes.status();
  return std::string(bytes.value().begin(), bytes.value().end());
}

// Parses the canonical flow key text that the parent and child exchange.  Sharing the text rather
// than the structure keeps the child a genuine separate program: it has to agree with the parent on
// the canonical form, which is itself part of the interface under test.
aifc::Result<aifc::FlowKey> parse_key(const std::string& text) {
  const std::size_t first_space = text.find(' ');
  const std::size_t arrow = text.find(" -> ");
  if (first_space == std::string::npos || arrow == std::string::npos) {
    return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "cannot parse key: " + text);
  }
  const std::size_t local_colon = text.find(':', first_space + 1);
  const std::size_t remote_colon = text.find(':', arrow + 4);
  if (local_colon == std::string::npos || remote_colon == std::string::npos) {
    return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "cannot parse key ports");
  }
  aifc::Result<aifc::TransportProtocol> transport =
      aifc::parse_transport_protocol(text.substr(0, first_space));
  if (!transport) return transport.status();
  auto octets = [](const std::string& host, std::uint32_t& out) -> aifc::Status {
    std::uint32_t value = 0;
    std::uint32_t octet = 0;
    std::uint32_t count = 0;
    bool in_digits = false;
    for (std::size_t i = 0; i <= host.size(); ++i) {
      const bool end = i == host.size();
      const char ch = end ? '.' : host[i];
      if (ch == '.') {
        if (!in_digits) {
          return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "empty address octet");
        }
        value = (value << 8) | octet;
        octet = 0;
        in_digits = false;
        ++count;
        continue;
      }
      if (ch < '0' || ch > '9') {
        return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "address is not numeric");
      }
      octet = octet * 10U + static_cast<std::uint32_t>(ch - '0');
      if (octet > 255U) {
        return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "address octet too large");
      }
      in_digits = true;
    }
    if (count != 4) {
      return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "address needs four octets");
    }
    out = value;
    return aifc::Status::success();
  };
  auto port = [](const std::string& digits, std::uint16_t& out) -> aifc::Status {
    if (digits.empty()) {
      return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "empty port");
    }
    std::uint32_t value = 0;
    for (char ch : digits) {
      if (ch < '0' || ch > '9') {
        return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "port is not numeric");
      }
      value = value * 10U + static_cast<std::uint32_t>(ch - '0');
      if (value > 65535U) {
        return aifc::Status::failure(aifc::ErrorCode::MALFORMED_INPUT, "port too large");
      }
    }
    out = static_cast<std::uint16_t>(value);
    return aifc::Status::success();
  };
  aifc::FlowKey key;
  key.transport = transport.value();
  std::uint32_t local_address = 0;
  std::uint32_t remote_address = 0;
  aifc::Status status =
      octets(text.substr(first_space + 1, local_colon - first_space - 1), local_address);
  if (!status) return status;
  status = octets(text.substr(arrow + 4, remote_colon - arrow - 4), remote_address);
  if (!status) return status;
  key.local_address = aifc::IpAddress::from_v4(local_address);
  key.remote_address = aifc::IpAddress::from_v4(remote_address);
  status = port(text.substr(local_colon + 1, arrow - local_colon - 1), key.local_port);
  if (!status) return status;
  status = port(text.substr(remote_colon + 1), key.remote_port);
  if (!status) return status;
  return key;
}

struct ChildArguments {
  std::string state_path;
  std::string port_file;
  std::string mode;
  std::string flow_key_text;
  std::uint32_t publishes = 1;
};

aifc::Result<ChildArguments> parse_child_arguments(int argc, char** argv) {
  ChildArguments arguments;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    const bool has_value = i + 1 < argc;
    if (argument == "--aifc-child-mode" && has_value) {
      arguments.mode = argv[++i];
    } else if (argument == "--aifc-child-state" && has_value) {
      arguments.state_path = argv[++i];
    } else if (argument == "--aifc-child-port-file" && has_value) {
      arguments.port_file = argv[++i];
    } else if (argument == "--aifc-child-flow" && has_value) {
      arguments.flow_key_text = argv[++i];
    } else if (argument == "--aifc-child-publishes" && has_value) {
      arguments.publishes = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    }
  }
  if (arguments.mode.empty()) {
    return aifc::Status::failure(aifc::ErrorCode::INVALID_ARGUMENT, "a child needs a mode");
  }
  return arguments;
}

// --- child roles -----------------------------------------------------------

int run_coordinator_child(const ChildArguments& arguments) {
  aifc::CoordinatorServiceOptions options;
  options.coordinator.policy = aifc::ClassifierPolicy::initial();
  options.coordinator.state_path = arguments.state_path;
  options.coordinator.persist_on_mutation = true;
  options.port = 0;
  options.worker_threads = 2;
  aifc::CoordinatorService service(options);
  const aifc::Status started = service.start(aifc::CoordinatorBootId{1});
  if (!started) {
    std::fprintf(stderr, "child coordinator failed to start: %s\n",
                 aifc::render_status(started).c_str());
    return 2;
  }
  const aifc::Status written = write_text(arguments.port_file, std::to_string(service.port()));
  if (!written) {
    std::fprintf(stderr, "child could not publish its port: %s\n", written.message.c_str());
    return 3;
  }
  std::printf("child coordinator listening on %u epoch %s\n",
              static_cast<unsigned>(service.port()),
              service.coordinator().epoch().to_string().c_str());
  std::fflush(stdout);
  // Wait to be killed.  No cleanup runs here by design; that is the failure mode under test.
  for (;;) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

int connect_child(const ChildArguments& arguments, aifc::Channel& channel_out,
                  std::uint16_t& port_out) {
  auto bytes = aifc::read_all(arguments.port_file, 64);
  if (!bytes) {
    std::fprintf(stderr, "child could not read the port file: %s\n",
                 aifc::render_status(bytes.status()).c_str());
    return 5;
  }
  const std::string port_text(bytes.value().begin(), bytes.value().end());
  port_out = static_cast<std::uint16_t>(std::strtoul(port_text.c_str(), nullptr, 10));
  if (port_out == 0) {
    std::fprintf(stderr, "child read an empty port\n");
    return 6;
  }
  auto connected = aifc::connect_loopback(port_out);
  if (!connected) {
    std::fprintf(stderr, "child could not connect to %u: %s\n",
                 static_cast<unsigned>(port_out),
                 aifc::render_status(connected.status()).c_str());
    return 7;
  }
  channel_out = aifc::Channel(std::move(connected).value(), aifc::kMaxFramePayload);
  return 0;
}

int run_publisher_child(const ChildArguments& arguments) {
  aifc::Result<aifc::FlowKey> key = parse_key(arguments.flow_key_text);
  if (!key) {
    std::fprintf(stderr, "child could not parse the flow key: %s\n",
                 aifc::render_status(key.status()).c_str());
    return 4;
  }
  aifc::Channel channel;
  std::uint16_t port = 0;
  if (const int code = connect_child(arguments, channel, port); code != 0) return code;

  std::uint64_t epoch = 0;
  std::uint64_t boot = 0;
  {
    aifc::HelloRequest hello;
    hello.role = aifc::PeerRole::PUBLISHER;
    hello.client_name = "multiprocess child publisher";
    hello.publisher = aifc::make_publisher_id("killed-publisher");
    aifc::ByteBuffer hello_bytes;
    if (!aifc::encode_hello(hello, hello_bytes)) return 9;
    if (!channel.send(aifc::MessageKind::HELLO, hello_bytes, 0, 0)) return 9;
    auto ack = channel.receive(std::chrono::milliseconds(5000));
    if (!ack) return 9;
    auto decoded_ack = aifc::decode_hello_response(ack.value().payload, kLimits);
    if (!decoded_ack) return 9;
    epoch = decoded_ack.value().epoch.value;
    boot = decoded_ack.value().boot.value;

    aifc::RegisterPublisherRequest registration;
    registration.publisher = hello.publisher;
    registration.boot = aifc::PublisherBootId{1};
    registration.description = "multiprocess child publisher";
    aifc::ByteBuffer registration_bytes;
    if (!aifc::encode_register_publisher(registration, registration_bytes)) return 9;
    if (!channel.send(aifc::MessageKind::REGISTER_PUBLISHER, registration_bytes, epoch, boot)) {
      return 9;
    }
    auto registration_response = channel.receive(std::chrono::milliseconds(5000));
    if (!registration_response) return 9;
    auto decoded =
        aifc::decode_register_publisher_response(registration_response.value().payload, kLimits);
    if (!decoded) return 9;
  }

  aifc::RegisterFlowRequest flow_request;
  flow_request.key = key.value();
  aifc::ByteBuffer flow_bytes;
  if (!aifc::encode_register_flow(flow_request, flow_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::REGISTER_FLOW, flow_bytes, epoch, boot)) return 9;
  auto flow_response = channel.receive(std::chrono::milliseconds(5000));
  if (!flow_response) return 9;
  auto flow_decoded = aifc::decode_register_flow_response(flow_response.value().payload, kLimits);
  if (!flow_decoded) return 9;

  for (std::uint32_t i = 0; i < arguments.publishes; ++i) {
    aifc::PublishEvidenceRequest publish;
    publish.payload.flow_key = key.value();
    publish.payload.flow_generation = flow_decoded.value().generation;
    publish.payload.evidence_generation = aifc::EvidenceGeneration{i + 1};
    publish.payload.semantic = aifc::SemanticClass::MODEL_STATE_TRANSFER;
    publish.payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    publish.payload.metadata.topic = "multiprocess.topic";
    publish.payload.metadata.reason = "published by a real child process";
    aifc::ByteBuffer publish_bytes;
    if (!aifc::encode_publish_evidence(publish, publish_bytes)) return 10;
    if (!channel.send(aifc::MessageKind::PUBLISH_EVIDENCE, publish_bytes, epoch, boot)) return 10;
    auto response = channel.receive(std::chrono::milliseconds(5000));
    if (!response) return 10;
    auto decoded = aifc::decode_publish_evidence_response(response.value().payload, kLimits);
    if (!decoded) return 10;
    if (decoded.value().evidence_id.empty()) return 10;
  }

  std::printf("child publisher published %u record(s); waiting to be killed\n",
              arguments.publishes);
  std::fflush(stdout);
  for (;;) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

// Presents an epoch learned before a coordinator restart, on top of a fresh handshake.
int run_stale_epoch_child(const ChildArguments& arguments) {
  aifc::Result<aifc::FlowKey> key = parse_key(arguments.flow_key_text);
  if (!key) return 4;
  aifc::Channel channel;
  std::uint16_t port = 0;
  if (const int code = connect_child(arguments, channel, port); code != 0) return code;

  aifc::HelloRequest hello;
  hello.role = aifc::PeerRole::PUBLISHER;
  hello.client_name = "stale epoch child";
  hello.publisher = aifc::make_publisher_id("stale-epoch-publisher");
  aifc::ByteBuffer hello_bytes;
  if (!aifc::encode_hello(hello, hello_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::HELLO, hello_bytes, 0, 0)) return 9;
  auto ack = channel.receive(std::chrono::milliseconds(5000));
  if (!ack) return 9;
  auto decoded_ack = aifc::decode_hello_response(ack.value().payload, kLimits);
  if (!decoded_ack) return 9;
  const std::uint64_t current_epoch = decoded_ack.value().epoch.value;
  const std::uint64_t current_boot = decoded_ack.value().boot.value;

  aifc::RegisterPublisherRequest registration;
  registration.publisher = hello.publisher;
  registration.boot = aifc::PublisherBootId{1};
  registration.description = "stale epoch child";
  aifc::ByteBuffer registration_bytes;
  if (!aifc::encode_register_publisher(registration, registration_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::REGISTER_PUBLISHER, registration_bytes, current_epoch,
                    current_boot)) {
    return 9;
  }
  auto registration_response = channel.receive(std::chrono::milliseconds(5000));
  if (!registration_response) return 9;

  aifc::RegisterFlowRequest flow_request;
  flow_request.key = key.value();
  aifc::ByteBuffer flow_bytes;
  if (!aifc::encode_register_flow(flow_request, flow_bytes)) return 9;
  const std::uint64_t stale_epoch = current_epoch > 1 ? current_epoch - 1 : current_epoch + 1;
  if (!channel.send(aifc::MessageKind::REGISTER_FLOW, flow_bytes, stale_epoch, current_boot)) {
    return 9;
  }
  auto response = channel.receive(std::chrono::milliseconds(5000));
  if (!response) return 9;
  if (response.value().header.kind != aifc::MessageKind::ERROR_RESPONSE) {
    std::fprintf(stderr, "the coordinator accepted a stale epoch claim\n");
    return 10;
  }
  auto error = aifc::decode_error_response(response.value().payload, kLimits);
  if (!error) return 9;
  std::printf("child observed refusal: %s\n",
              std::string(aifc::to_string(error.value().code)).c_str());
  std::fflush(stdout);
  return error.value().code == aifc::ErrorCode::STALE_EPOCH ? 0 : 11;
}

// Presents epoch 1 / boot 1 without a handshake, the way a publisher would after reading its own
// pre-restart cache.  Used to prove authority is not reachable from persisted numbers.
int run_cached_epoch_child(const ChildArguments& arguments) {
  aifc::Result<aifc::FlowKey> key = parse_key(arguments.flow_key_text);
  if (!key) return 4;
  aifc::Channel channel;
  std::uint16_t port = 0;
  if (const int code = connect_child(arguments, channel, port); code != 0) return code;

  aifc::HelloRequest hello;
  hello.role = aifc::PeerRole::PUBLISHER;
  hello.client_name = "cached epoch child";
  hello.publisher = aifc::make_publisher_id("cached-epoch-publisher");
  aifc::ByteBuffer hello_bytes;
  if (!aifc::encode_hello(hello, hello_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::HELLO, hello_bytes, 1, 1)) return 9;
  auto ack = channel.receive(std::chrono::milliseconds(5000));
  if (!ack) return 9;

  aifc::RegisterFlowRequest flow_request;
  flow_request.key = key.value();
  aifc::ByteBuffer flow_bytes;
  if (!aifc::encode_register_flow(flow_request, flow_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::REGISTER_FLOW, flow_bytes, 1, 1)) return 9;
  auto response = channel.receive(std::chrono::milliseconds(5000));
  if (!response) return 9;
  if (response.value().header.kind != aifc::MessageKind::ERROR_RESPONSE) {
    std::fprintf(stderr, "the coordinator accepted cached pre-restart authority\n");
    return 10;
  }
  auto error = aifc::decode_error_response(response.value().payload, kLimits);
  if (!error) return 9;
  std::printf("child observed refusal for cached authority: %s\n",
              std::string(aifc::to_string(error.value().code)).c_str());
  std::fflush(stdout);
  return error.value().code == aifc::ErrorCode::STALE_EPOCH ? 0 : 11;
}

// Queries the coordinator for the number of CURRENT citations on one flow.  Used by the parent to
// observe, from outside, what the coordinator believes.
std::size_t count_current_citations(std::uint16_t port, const aifc::FlowKey& key) {
  auto connected = aifc::connect_loopback(port);
  if (!connected) return static_cast<std::size_t>(-1);
  aifc::Channel channel(std::move(connected).value(), aifc::kMaxFramePayload);
  aifc::HelloRequest hello;
  hello.role = aifc::PeerRole::CLIENT;
  hello.client_name = "multiprocess observer";
  aifc::ByteBuffer hello_bytes;
  if (!aifc::encode_hello(hello, hello_bytes)) return static_cast<std::size_t>(-1);
  if (!channel.send(aifc::MessageKind::HELLO, hello_bytes, 0, 0)) {
    return static_cast<std::size_t>(-1);
  }
  auto ack = channel.receive(std::chrono::milliseconds(4000));
  if (!ack) return static_cast<std::size_t>(-1);
  auto decoded_ack = aifc::decode_hello_response(ack.value().payload, kLimits);
  if (!decoded_ack) return static_cast<std::size_t>(-1);

  aifc::ClassifyRequest request;
  aifc::ClassifyQueryEntry entry;
  entry.key = key;
  entry.explain = true;
  request.entries.push_back(entry);
  aifc::ByteBuffer classify_bytes;
  if (!aifc::encode_classify_request(request, classify_bytes)) return static_cast<std::size_t>(-1);
  if (!channel.send(aifc::MessageKind::CLASSIFY, classify_bytes, decoded_ack.value().epoch.value,
                    decoded_ack.value().boot.value)) {
    return static_cast<std::size_t>(-1);
  }
  auto response = channel.receive(std::chrono::milliseconds(4000));
  if (!response) return static_cast<std::size_t>(-1);
  auto decoded = aifc::decode_classify_response(response.value().payload, kLimits);
  if (!decoded) return static_cast<std::size_t>(-1);
  if (decoded.value().classifications.size() != 1) return static_cast<std::size_t>(-1);
  std::size_t current = 0;
  for (const aifc::EvidenceCitation& citation :
       decoded.value().classifications.front().citations) {
    if (citation.state == aifc::EvidenceState::EVIDENCE_CURRENT) ++current;
  }
  return current;
}

struct CoordinatorChild {
  aifc_test::ChildProcess process;
  std::uint16_t port = 0;
};

// Starts a coordinator incarnation and waits until it has published the port it is serving.
//
// The tag distinguishes incarnations within one case, and the port file is cleared *before* the wait:
// a restart case that read the previous incarnation's port file would connect to nobody and report a
// failure that has nothing to do with what it is testing.
CoordinatorChild start_coordinator_child(const aifc_test::ScratchDirectory& scratch,
                                         const std::string& tag = "primary") {
  CoordinatorChild child;
  const std::string port_file = scratch.file("coordinator-" + tag + ".port");
  // The removal is retried: a process that has just been terminated can hold its inherited handles
  // open for a moment, and a removal that silently failed would leave the previous incarnation's port
  // number in place for this one to read.
  for (int attempt = 0; attempt < 40 && aifc::path_exists(port_file); ++attempt) {
    (void)aifc::remove_file(port_file);
    if (!aifc::path_exists(port_file)) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  if (aifc::path_exists(port_file)) {
    AIFC_CHECK_MSG(false, "could not clear the stale port file " + port_file);
    return child;
  }
  auto spawned = aifc_test::ChildProcess::spawn(
      aifc_test::executable_path(), aifc_test::kChildModeArgument,
      {"--aifc-child-mode", "coordinator", "--aifc-child-state", scratch.file("coordinator.state"),
       "--aifc-child-port-file", port_file},
      std::string(), scratch.file("coordinator-" + tag + ".out"));
  if (!spawned) {
    AIFC_CHECK_MSG(false,
                   "could not spawn the child coordinator: " + aifc::render_status(spawned.status()));
    return child;
  }
  child.process = std::move(spawned).value();
  const bool appeared =
      aifc_test::wait_until([&]() { return aifc::path_exists(port_file); }, 400, 25);
  if (!appeared) {
    AIFC_CHECK_MSG(false, "the child coordinator never published a port; its output was:\n" +
                              child.process.output());
    return child;
  }
  auto port_text = read_text(port_file);
  if (!port_text) {
    AIFC_CHECK_MSG(false, "could not read the child coordinator's port file");
    return child;
  }
  child.port = static_cast<std::uint16_t>(std::strtoul(port_text.value().c_str(), nullptr, 10));
  AIFC_CHECK_NE(child.port, std::uint16_t{0});
  return child;
}

aifc_test::ChildProcess spawn_child(const aifc_test::ScratchDirectory& scratch,
                                    const std::string& port_file, const std::string& flow_key,
                                    const std::string& name, const std::string& mode = "publisher",
                                    std::uint32_t publishes = 1) {
  auto spawned = aifc_test::ChildProcess::spawn(
      aifc_test::executable_path(), aifc_test::kChildModeArgument,
      {"--aifc-child-mode", mode, "--aifc-child-port-file", port_file, "--aifc-child-flow",
       flow_key, "--aifc-child-state", scratch.file("unused.state"), "--aifc-child-publishes",
       std::to_string(publishes)},
      std::string(), scratch.file(name + ".out"));
  if (!spawned) {
    AIFC_CHECK_MSG(false,
                   "could not spawn child " + name + ": " + aifc::render_status(spawned.status()));
    return aifc_test::ChildProcess{};
  }
  return std::move(spawned).value();
}

bool wait_for_current_citations(std::uint16_t port, const aifc::FlowKey& key, std::size_t expected) {
  // The polling interval is deliberately not tight: each poll is a real connection and a real
  // handshake, so hammering the coordinator would measure the test rather than the runtime.
  return aifc_test::wait_until(
      [&]() { return count_current_citations(port, key) == expected; }, 120, 100);
}

}  // namespace

extern int aifc_run_child_role(int argc, char** argv);
int aifc_run_child_role(int argc, char** argv);

int aifc_run_child_role(int argc, char** argv) {
  auto arguments = parse_child_arguments(argc, argv);
  if (!arguments) {
    std::fprintf(stderr, "child argument error: %s\n",
                 aifc::render_status(arguments.status()).c_str());
    return 1;
  }
  const std::string mode = arguments.value().mode;
  if (mode == "coordinator") return run_coordinator_child(arguments.value());
  if (mode == "publisher") return run_publisher_child(arguments.value());
  if (mode == "stale-epoch") return run_stale_epoch_child(arguments.value());
  if (mode == "cached-epoch") return run_cached_epoch_child(arguments.value());
  std::fprintf(stderr, "unknown child mode: %s\n", mode.c_str());
  return 1;
}

AIFC_TEST("multiprocess: a killed publisher loses current authority") {
  aifc_test::ScratchDirectory scratch("multiprocess-kill");
  CoordinatorChild coordinator = start_coordinator_child(scratch);
  if (coordinator.port == 0) return;
  const std::string port_file = scratch.file("coordinator-primary.port");

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7001);
  aifc_test::ChildProcess publisher =
      spawn_child(scratch, port_file, key.to_string(), "publisher");
  if (!publisher.running()) {
    (void)coordinator.process.kill();
    return;
  }

  if (!wait_for_current_citations(coordinator.port, key, 1)) {
    AIFC_FAIL("the child publisher's evidence never became current; publisher output:\n" +
              publisher.output() + "\ncoordinator output:\n" + coordinator.process.output());
    (void)publisher.kill();
    (void)coordinator.process.kill();
    return;
  }

  // Kill it.  No destructor runs, no flush happens and no goodbye is sent.
  AIFC_CHECK_OK(publisher.kill());

  if (!wait_for_current_citations(coordinator.port, key, 0)) {
    AIFC_FAIL("a killed publisher's evidence stayed current; coordinator output:\n" +
              coordinator.process.output());
  }

  AIFC_CHECK_OK(coordinator.process.kill());
  AIFC_CHECK(!coordinator.process.output().empty());
}

AIFC_TEST("multiprocess: a coordinator restart refuses authority cached from before it") {
  aifc_test::ScratchDirectory scratch("multiprocess-restart");
  CoordinatorChild first = start_coordinator_child(scratch);
  if (first.port == 0) return;
  const std::string port_file = scratch.file("coordinator-primary.port");

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7002);
  aifc_test::ChildProcess publisher =
      spawn_child(scratch, port_file, key.to_string(), "publisher-before-restart");
  if (!publisher.running()) {
    (void)first.process.kill();
    return;
  }
  AIFC_CHECK(wait_for_current_citations(first.port, key, 1));
  AIFC_CHECK_OK(publisher.kill());

  // Kill the coordinator abruptly, wait for the process to be gone, then bring a new incarnation up
  // on the same state path.  The second incarnation gets its own port file so that failing to observe
  // the new port cannot be confused with reading the old one.
  AIFC_CHECK_OK(first.process.kill());

  CoordinatorChild second = start_coordinator_child(scratch, "second");
  if (second.port == 0) return;
  const std::string second_port_file = scratch.file("coordinator-second.port");

  aifc_test::ChildProcess cached =
      spawn_child(scratch, second_port_file, key.to_string(), "cached-epoch", "cached-epoch");
  if (cached.running()) {
    auto exit_code = cached.wait();
    if (!exit_code) {
      AIFC_FAIL("could not reap the cached-epoch child");
    } else {
      AIFC_CHECK_MSG(exit_code.value() == 0,
                     "a publisher presenting pre-restart authority was not refused; child "
                     "output:\n" + cached.output());
    }
  }

  aifc_test::ChildProcess stale =
      spawn_child(scratch, second_port_file, key.to_string(), "stale-epoch", "stale-epoch");
  if (stale.running()) {
    auto stale_exit = stale.wait();
    if (!stale_exit) {
      AIFC_FAIL("could not reap the stale-epoch child");
    } else {
      AIFC_CHECK_MSG(stale_exit.value() == 0,
                     "a stale epoch frame was not refused; child output:\n" + stale.output());
    }
  }

  // The flow's pre-restart evidence must not be current under the new incarnation.
  AIFC_CHECK(wait_for_current_citations(second.port, key, 0));
  AIFC_CHECK_OK(second.process.kill());
}

AIFC_TEST("multiprocess: an abrupt coordinator death leaves recoverable durable state") {
  aifc_test::ScratchDirectory scratch("multiprocess-recovery");
  CoordinatorChild first = start_coordinator_child(scratch);
  if (first.port == 0) return;
  const std::string port_file = scratch.file("coordinator-primary.port");
  const std::string state_file = scratch.file("coordinator.state");

  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7003);
  aifc_test::ChildProcess publisher =
      spawn_child(scratch, port_file, key.to_string(), "publisher-recovery");
  if (!publisher.running()) {
    (void)first.process.kill();
    return;
  }
  AIFC_CHECK(wait_for_current_citations(first.port, key, 1));
  AIFC_CHECK_OK(publisher.kill());

  // The durable state must exist before the kill, or this case would be about a snapshot that was
  // never written rather than about recovery.
  AIFC_CHECK(aifc::path_exists(state_file));
  AIFC_CHECK_OK(first.process.kill());

  auto snapshot = aifc::read_snapshot_file(state_file, aifc::SnapshotLimits{});
  if (!snapshot) {
    AIFC_FAIL("durable state was not readable after an abrupt coordinator death: " +
              aifc::render_status(snapshot.status()));
    return;
  }
  AIFC_CHECK(!snapshot.value().publishers.empty());
  AIFC_CHECK(!snapshot.value().flows.empty());

  CoordinatorChild second = start_coordinator_child(scratch, "second");
  if (second.port == 0) {
    AIFC_CHECK(false);
    return;
  }
  // After the restart the flow's evidence must not be current: the publisher is gone and the epoch
  // advanced.
  AIFC_CHECK(wait_for_current_citations(second.port, key, 0));
  AIFC_CHECK_OK(second.process.kill());
}
