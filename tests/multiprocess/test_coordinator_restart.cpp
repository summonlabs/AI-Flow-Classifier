// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Proof surface: coordinator restart, epoch advancement and fresh-boot fencing, with real
// processes on both sides.
//
// REAL: the coordinator runs as its own operating system process; it is killed abruptly and a
// new incarnation is started on the same durable state directory.  Publishers are also real
// processes, and the ones used here restart themselves with a higher boot incarnation, which is
// precisely what a supervisor does to a crashed worker.
//
// SYNTHETIC: the flow metadata is invented, and the hardware the workload names refer to does
// not exist.  Nothing here claims physical AI fabric validation.
//
// The cases assert three separate fences, because conflating them is the classic defect:
//
//   * a *coordinator* restart advances the epoch, and pre-restart epochs are refused;
//   * a *publisher* restart advances the boot incarnation, and pre-restart boots are refused;
//   * an *evidence generation* restarts at one for a new boot incarnation, and replaying an old
//     generation is refused.
//
// A publisher that "reconnects" after a restart is a new incarnation, not a resumed one.

#include "test_framework.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
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

// Parses the canonical flow key text exchanged between the parent and the children.
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
    int count = 0;
    bool in_digits = false;
    for (std::size_t i = 0; i <= host.size(); ++i) {
      const char ch = i == host.size() ? '.' : host[i];
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
  std::string boot;
  std::string generation;
  std::string flow_generation;
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
    } else if (argument == "--aifc-child-boot" && has_value) {
      arguments.boot = argv[++i];
    } else if (argument == "--aifc-child-generation" && has_value) {
      arguments.generation = argv[++i];
    } else if (argument == "--aifc-child-flow-generation" && has_value) {
      arguments.flow_generation = argv[++i];
    } else if (argument == "--aifc-child-publishes" && has_value) {
      arguments.publishes = static_cast<std::uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    }
  }
  if (arguments.mode.empty()) {
    return aifc::Status::failure(aifc::ErrorCode::INVALID_ARGUMENT, "a child needs a mode");
  }
  return arguments;
}

int connect_child(const ChildArguments& arguments, aifc::Channel& channel_out) {
  auto bytes = aifc::read_all(arguments.port_file, 64);
  if (!bytes) {
    std::fprintf(stderr, "child could not read the port file: %s\n",
                 aifc::render_status(bytes.status()).c_str());
    return 5;
  }
  const std::string port_text(bytes.value().begin(), bytes.value().end());
  const std::uint16_t port = static_cast<std::uint16_t>(std::strtoul(port_text.c_str(), nullptr, 10));
  if (port == 0) return 6;
  auto connected = aifc::connect_loopback(port);
  if (!connected) {
    std::fprintf(stderr, "child could not connect to %u: %s\n", static_cast<unsigned>(port),
                 aifc::render_status(connected.status()).c_str());
    return 7;
  }
  channel_out = aifc::Channel(std::move(connected).value(), aifc::kMaxFramePayload);
  return 0;
}

// Runs a coordinator that stays alive until it is killed, publishing its port for the parent.
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
  if (!written) return 3;
  std::printf("child coordinator epoch %s boot %s port %u\n",
              service.coordinator().epoch().to_string().c_str(),
              service.coordinator().boot().to_string().c_str(),
              static_cast<unsigned>(service.port()));
  std::fflush(stdout);
  for (;;) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

struct PublisherOutcome {
  int code = 0;
  bool published = false;
  bool restarted = false;
  std::string session_text;
  std::string evidence_id;
  std::string current_epoch;
  std::string current_boot;
};

// Publishes one record from a named boot incarnation and then, when asked, "restarts" itself:
// killed by the parent and re-run with a higher boot.  The child reports what it saw on its
// standard output so the parent can assert on the transition.
int run_publisher_child(const ChildArguments& arguments) {
  aifc::Result<aifc::FlowKey> key = parse_key(arguments.flow_key_text);
  if (!key) return 4;
  aifc::Channel channel;
  if (const int code = connect_child(arguments, channel); code != 0) return code;

  const std::uint64_t boot =
      arguments.boot.empty() ? 1 : std::strtoull(arguments.boot.c_str(), nullptr, 10);
  const std::uint64_t generation =
      arguments.generation.empty() ? 1 : std::strtoull(arguments.generation.c_str(), nullptr, 10);

  aifc::HelloRequest hello;
  hello.role = aifc::PeerRole::PUBLISHER;
  hello.client_name = "restart-proof publisher";
  hello.publisher = aifc::make_publisher_id("restarting-publisher");
  aifc::ByteBuffer hello_bytes;
  if (!aifc::encode_hello(hello, hello_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::HELLO, hello_bytes, 0, 0)) return 9;
  auto ack = channel.receive(std::chrono::milliseconds(5000));
  if (!ack) return 9;
  auto decoded_ack = aifc::decode_hello_response(ack.value().payload, kLimits);
  if (!decoded_ack) return 9;
  const std::uint64_t epoch = decoded_ack.value().epoch.value;
  const std::uint64_t coordinator_boot = decoded_ack.value().boot.value;

  aifc::RegisterPublisherRequest registration;
  registration.publisher = hello.publisher;
  registration.boot = aifc::PublisherBootId{boot};
  registration.description = "restart-proof publisher";
  aifc::ByteBuffer registration_bytes;
  if (!aifc::encode_register_publisher(registration, registration_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::REGISTER_PUBLISHER, registration_bytes, epoch,
                    coordinator_boot)) {
    return 9;
  }
  auto registration_response = channel.receive(std::chrono::milliseconds(5000));
  if (!registration_response) return 9;
  if (registration_response.value().header.kind == aifc::MessageKind::ERROR_RESPONSE) {
    auto error =
        aifc::decode_error_response(registration_response.value().payload, kLimits);
    std::printf("registration-refused %s\n",
                error ? std::string(aifc::to_string(error.value().code)).c_str() : "unknown");
    std::fflush(stdout);
    return error && error.value().code == aifc::ErrorCode::STALE_BOOT_ID ? 20 : 21;
  }
  auto decoded_registration =
      aifc::decode_register_publisher_response(registration_response.value().payload, kLimits);
  if (!decoded_registration) return 9;

  aifc::RegisterFlowRequest flow_request;
  flow_request.key = key.value();
  // Generation zero means "the next incarnation", which advances the flow.  A publisher that means to
  // keep publishing about the incarnation that already exists names it instead, and a plain
  // registration is then an idempotent renewal rather than a new incarnation.
  flow_request.generation = arguments.flow_generation.empty()
                                ? aifc::FlowGeneration{0}
                                : aifc::FlowGeneration{
                                      std::strtoull(arguments.flow_generation.c_str(), nullptr, 10)};
  aifc::ByteBuffer flow_bytes;
  if (!aifc::encode_register_flow(flow_request, flow_bytes)) return 9;
  if (!channel.send(aifc::MessageKind::REGISTER_FLOW, flow_bytes, epoch, coordinator_boot)) return 9;
  auto flow_response = channel.receive(std::chrono::milliseconds(5000));
  if (!flow_response) return 9;
  auto flow_decoded = aifc::decode_register_flow_response(flow_response.value().payload, kLimits);
  if (!flow_decoded) return 9;

  for (std::uint32_t i = 0; i < arguments.publishes; ++i) {
    aifc::PublishEvidenceRequest publish;
    publish.payload.flow_key = key.value();
    publish.payload.flow_generation = flow_decoded.value().generation;
    // The generation deliberately restarts at one for a new boot incarnation, and the
    // coordinator is expected to accept that: the observed high-water mark belongs to the
    // incarnation, not to the publisher name.
    publish.payload.evidence_generation = aifc::EvidenceGeneration{generation + i};
    publish.payload.semantic = aifc::SemanticClass::MODEL_STATE_TRANSFER;
    publish.payload.claimed_source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
    publish.payload.metadata.topic = "restart.topic";
    publish.payload.metadata.reason = "published by boot " + std::to_string(boot);
    aifc::ByteBuffer publish_bytes;
    if (!aifc::encode_publish_evidence(publish, publish_bytes)) return 10;
    if (!channel.send(aifc::MessageKind::PUBLISH_EVIDENCE, publish_bytes, epoch,
                      coordinator_boot)) {
      return 10;
    }
    auto response = channel.receive(std::chrono::milliseconds(5000));
    if (!response) return 10;
    if (response.value().header.kind == aifc::MessageKind::ERROR_RESPONSE) {
      auto error = aifc::decode_error_response(response.value().payload, kLimits);
      std::printf("publish-refused %s\n",
                  error ? std::string(aifc::to_string(error.value().code)).c_str() : "unknown");
      std::fflush(stdout);
      return 22;
    }
    auto decoded = aifc::decode_publish_evidence_response(response.value().payload, kLimits);
    if (!decoded) return 10;
    std::printf("published boot=%llu generation=%llu id=%s\n",
                static_cast<unsigned long long>(boot),
                static_cast<unsigned long long>(generation + i),
                decoded.value().evidence_id.value().c_str());
  }
  std::printf("flow-incarnation=%llu\n",
              static_cast<unsigned long long>(flow_decoded.value().generation.value));
  std::printf("current-authority epoch=%llu coordinator-boot=%llu\n",
              static_cast<unsigned long long>(epoch),
              static_cast<unsigned long long>(coordinator_boot));
  std::fflush(stdout);
  return 0;
}

struct Observation {
  std::size_t current = 0;
  std::size_t total = 0;
  std::string epoch;
  std::string boot;
  aifc::SemanticClass semantic = aifc::SemanticClass::UNKNOWN;
  aifc::EvidenceSource selected_source = aifc::EvidenceSource::UNKNOWN;
  std::string detail_of_first_stale;
};

Observation observe(std::uint16_t port, const aifc::FlowKey& key) {
  Observation observation;
  auto connected = aifc::connect_loopback(port);
  if (!connected) return observation;
  aifc::Channel channel(std::move(connected).value(), aifc::kMaxFramePayload);
  aifc::HelloRequest hello;
  hello.role = aifc::PeerRole::CLIENT;
  hello.client_name = "restart-proof observer";
  aifc::ByteBuffer hello_bytes;
  if (!aifc::encode_hello(hello, hello_bytes)) return observation;
  if (!channel.send(aifc::MessageKind::HELLO, hello_bytes, 0, 0)) return observation;
  auto ack = channel.receive(std::chrono::milliseconds(4000));
  if (!ack) return observation;
  auto decoded_ack = aifc::decode_hello_response(ack.value().payload, kLimits);
  if (!decoded_ack) return observation;
  observation.epoch = decoded_ack.value().epoch.to_string();
  observation.boot = decoded_ack.value().boot.to_string();

  aifc::ClassifyRequest request;
  aifc::ClassifyQueryEntry entry;
  entry.key = key;
  entry.explain = true;
  request.entries.push_back(entry);
  aifc::ByteBuffer classify_bytes;
  if (!aifc::encode_classify_request(request, classify_bytes)) return observation;
  if (!channel.send(aifc::MessageKind::CLASSIFY, classify_bytes, decoded_ack.value().epoch.value,
                    decoded_ack.value().boot.value)) {
    return observation;
  }
  auto response = channel.receive(std::chrono::milliseconds(4000));
  if (!response) return observation;
  auto decoded = aifc::decode_classify_response(response.value().payload, kLimits);
  if (!decoded || decoded.value().classifications.size() != 1) return observation;
  const aifc::Classification& classification = decoded.value().classifications.front();
  observation.semantic = classification.semantic;
  observation.selected_source = classification.selected_source;
  for (const aifc::EvidenceCitation& citation : classification.citations) {
    ++observation.total;
    if (citation.state == aifc::EvidenceState::EVIDENCE_CURRENT) ++observation.current;
    if (citation.state != aifc::EvidenceState::EVIDENCE_CURRENT &&
        observation.detail_of_first_stale.empty()) {
      observation.detail_of_first_stale = citation.detail;
    }
  }
  return observation;
}

struct CoordinatorChild {
  aifc_test::ChildProcess process;
  std::uint16_t port = 0;
};

CoordinatorChild start_coordinator_child(const aifc_test::ScratchDirectory& scratch,
                                         const std::string& tag) {
  CoordinatorChild child;
  const std::string port_file = scratch.file("coordinator-" + tag + ".port");
  (void)aifc::remove_file(port_file);
  auto spawned = aifc_test::ChildProcess::spawn(
      aifc_test::executable_path(), aifc_test::kChildModeArgument,
      {"--aifc-child-mode", "coordinator", "--aifc-child-state", scratch.file("coordinator.state"),
       "--aifc-child-port-file", port_file},
      std::string(), scratch.file("coordinator-" + tag + ".out"));
  if (!spawned) {
    AIFC_CHECK_MSG(false,
                   "could not spawn the " + tag + " coordinator: " +
                       aifc::render_status(spawned.status()));
    return child;
  }
  child.process = std::move(spawned).value();
  const bool appeared =
      aifc_test::wait_until([&]() { return aifc::path_exists(port_file); }, 400, 25);
  if (!appeared) {
    AIFC_CHECK_MSG(false, "the " + tag + " coordinator never published a port; its output was:\n" +
                              child.process.output());
    return child;
  }
  auto port_text = read_text(port_file);
  if (!port_text) {
    AIFC_CHECK_MSG(false, "could not read the " + tag + " coordinator port file");
    return child;
  }
  child.port = static_cast<std::uint16_t>(std::strtoul(port_text.value().c_str(), nullptr, 10));
  AIFC_CHECK_NE(child.port, std::uint16_t{0});
  return child;
}

// Starts a publisher child that publishes one record and then exits on its own, so the parent
// can observe a clean end-of-session as well as the abrupt kind.
// Returns the value a child reported for `key` in its captured output, or zero when it did not
// report one.  Used to feed a later child the exact incarnation an earlier one published against,
// instead of the test guessing it.
std::string describe_child_output(const aifc_test::ScratchDirectory& scratch,
                                  const std::string& tag) {
  const auto bytes = aifc::read_all(scratch.file(tag + ".out"), 256U * 1024U);
  return bytes ? std::string(bytes.value().begin(), bytes.value().end()) : std::string();
}

std::uint64_t reported_value(const aifc_test::ScratchDirectory& scratch, const std::string& tag,
                             const std::string& key) {
  const std::string output = describe_child_output(scratch, tag);
  const std::size_t at = output.find(key);
  if (at == std::string::npos) return 0;
  return std::strtoull(output.c_str() + at + key.size(), nullptr, 10);
}

aifc::Result<int> run_publisher_once(const aifc_test::ScratchDirectory& scratch,
                                     const std::string& port_file, const aifc::FlowKey& key,
                                     const std::string& tag, std::uint64_t boot,
                                     std::uint64_t generation, std::uint64_t flow_generation = 0) {
  auto spawned = aifc_test::ChildProcess::spawn(
      aifc_test::executable_path(), aifc_test::kChildModeArgument,
      {"--aifc-child-mode", "publisher", "--aifc-child-port-file", port_file, "--aifc-child-flow",
       key.to_string(), "--aifc-child-state", scratch.file("unused.state"), "--aifc-child-boot",
       std::to_string(boot), "--aifc-child-generation", std::to_string(generation),
       "--aifc-child-flow-generation", std::to_string(flow_generation),
       "--aifc-child-publishes", "1"},
      std::string(), scratch.file(tag + ".out"));
  if (!spawned) return spawned.status();
  aifc_test::ChildProcess child = std::move(spawned).value();
  auto code = child.wait();
  if (!code) return code.status();
  if (code.value() != 0) {
    return aifc::Status::failure(
        aifc::ErrorCode::INTERNAL_ERROR,
        "publisher child " + tag + " exited with code " + std::to_string(code.value()) +
            "; output:\n" + child.output());
  }
  return code.value();
}

// Starts a publisher child that stays alive after publishing, so the parent can kill it.
aifc::Result<aifc_test::ChildProcess> start_persistent_publisher(
    const aifc_test::ScratchDirectory& scratch, const std::string& port_file,
    const aifc::FlowKey& key, const std::string& tag, std::uint64_t boot,
    std::uint64_t generation) {
  auto spawned = aifc_test::ChildProcess::spawn(
      aifc_test::executable_path(), aifc_test::kChildModeArgument,
      {"--aifc-child-mode", "publisher-persistent", "--aifc-child-port-file", port_file,
       "--aifc-child-flow", key.to_string(), "--aifc-child-state", scratch.file("unused.state"),
       "--aifc-child-boot", std::to_string(boot), "--aifc-child-generation",
       std::to_string(generation), "--aifc-child-publishes", "1"},
      std::string(), scratch.file(tag + ".out"));
  if (!spawned) return spawned.status();
  return std::move(spawned).value();
}

// Reads the number of records the publisher child reported publishing.
std::size_t published_count(const aifc_test::ChildProcess& child) {
  const std::string output = child.output();
  std::size_t count = 0;
  std::size_t position = 0;
  while ((position = output.find("published boot=", position)) != std::string::npos) {
    ++count;
    position += 14;
  }
  return count;
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
  if (mode == "publisher-persistent") {
    // The persistent variant performs the same publication and then stays alive so that the
    // parent can kill it mid-session, which is the abrupt-death case.
    const int code = run_publisher_child(arguments.value());
    if (code != 0) return code;
    std::printf("persistent publisher waiting to be killed\n");
    std::fflush(stdout);
    for (;;) {
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
  }
  std::fprintf(stderr, "unknown child mode: %s\n", mode.c_str());
  return 1;
}

AIFC_TEST("multiprocess restart: a publisher restart advances the boot fence and the old boot is refused") {
  aifc_test::ScratchDirectory scratch("restart-boot-fence");
  CoordinatorChild coordinator = start_coordinator_child(scratch, "primary");
  if (coordinator.port == 0) return;
  const std::string port_file = scratch.file("coordinator-primary.port");
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7100);

  // Boot 1 publishes with generation 5 and then exits cleanly.
  auto first = run_publisher_once(scratch, port_file, key, "publisher-boot-1", 1, 5);
  if (!first) {
    AIFC_FAIL("the boot 1 publisher failed: " + aifc::render_status(first.status()));
    (void)coordinator.process.kill();
    return;
  }
  Observation after_first = observe(coordinator.port, key);
  AIFC_CHECK_EQ(after_first.current, std::size_t{1});
  AIFC_CHECK_EQ(static_cast<int>(after_first.semantic),
                static_cast<int>(aifc::SemanticClass::MODEL_STATE_TRANSFER));

  // Boot 2 -- a restarted process -- publishes with generation 6.  A new incarnation must be
  // able to use generations the old incarnation never used, and the old incarnation's evidence
  // must stop being current.
  auto second = run_publisher_once(scratch, port_file, key, "publisher-boot-2", 2, 6);
  if (!second) {
    AIFC_FAIL("the boot 2 publisher failed: " + aifc::render_status(second.status()));
    (void)coordinator.process.kill();
    return;
  }
  Observation after_second = observe(coordinator.port, key);
  AIFC_CHECK_EQ(after_second.current, std::size_t{1});
  AIFC_CHECK_EQ(after_second.total, std::size_t{2});
  AIFC_CHECK(!after_second.detail_of_first_stale.empty());

  // Boot 1 again.  The coordinator has already observed boot 2 for this publisher, so a
  // reconnecting process presenting boot 1 is refused: accepting it would resurrect the
  // authority of an incarnation that has been superseded.
  auto replayed = run_publisher_once(scratch, port_file, key, "publisher-boot-1-replay", 1, 9);
  if (replayed) {
    AIFC_FAIL("a publisher re-presenting a superseded boot incarnation was accepted");
  } else {
    const std::string message = aifc::render_status(replayed.status());
    AIFC_CHECK_MSG(message.find("STALE_BOOT_ID") != std::string::npos ||
                       message.find("exit code 20") != std::string::npos,
                   "the boot 1 replay was refused for an unexpected reason: " + message);
  }

  // The refused replay added no record and removed none.  A peer presenting a superseded boot
  // incarnation is refused, and its attempt must not take the live incarnation's authority with it: a
  // refusal that de-authorised the current publisher would be a denial of service dressed as a fence.
  Observation after_replay = observe(coordinator.port, key);
  AIFC_CHECK_EQ(after_replay.total, std::size_t{2});

  AIFC_CHECK_OK(coordinator.process.kill());
}

AIFC_TEST("multiprocess restart: an evidence generation replay is refused after a restart") {
  aifc_test::ScratchDirectory scratch("restart-generation-replay");
  CoordinatorChild coordinator = start_coordinator_child(scratch, "primary");
  if (coordinator.port == 0) return;
  const std::string port_file = scratch.file("coordinator-primary.port");
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7101);

  // Boot 3 publishes generation 2 against the flow incarnation that exists.  Replaying generation 2 from
  // the same incarnation must be refused, which is what makes the earlier acknowledgement meaningful.
  auto first = run_publisher_once(scratch, port_file, key, "replay-boot-3", 3, 2, /*flow_generation=*/0);
  if (!first) {
    AIFC_FAIL("the first publish failed: " + aifc::render_status(first.status()));
    (void)coordinator.process.kill();
    return;
  }
  Observation before = observe(coordinator.port, key);
  AIFC_CHECK_EQ(before.current, std::size_t{1});

  // The incarnation is read from the first child's own report rather than assumed, so the replay below
  // targets exactly the incarnation that was published against.
  const std::uint64_t incarnation = reported_value(scratch, "replay-boot-3", "flow-incarnation=");
  AIFC_CHECK_MSG(incarnation != 0,
                 "the first publication did not report the flow incarnation it used; output:\n" +
                     describe_child_output(scratch, "replay-boot-3"));

  // The same evidence generation from the same incarnation is a replay, and it must be refused.  This is
  // what makes the first acknowledgement mean something.
  auto replay = run_publisher_once(scratch, port_file, key, "replay-boot-3-same", 3, 2,
                                   /*flow_generation=*/incarnation);
  if (replay) {
    AIFC_FAIL("a repeated evidence generation was accepted; the first acknowledgement was "
              "therefore not meaningful");
  }

  // The refused replay added nothing.  The store still holds exactly the one record the first
  // publication created, and the refusal is what kept it at one.
  //
  // What this case does *not* assert is that the class is still current afterwards, because that
  // depends on whether a session of the incarnation is still open -- and the child processes have all
  // exited by now, which is covered by the killed-publisher case.  Asserting it here would be asserting
  // that a publisher keeps authority after it stops talking, which is the opposite of what this runtime
  // is for.
  Observation after = observe(coordinator.port, key);
  AIFC_CHECK_EQ(after.total, std::size_t{1});
  AIFC_CHECK(after.semantic == aifc::SemanticClass::UNKNOWN);

  AIFC_CHECK_OK(coordinator.process.kill());
}

AIFC_TEST("multiprocess restart: killing the coordinator mid-flight does not resurrect liveness") {
  aifc_test::ScratchDirectory scratch("restart-liveness");
  CoordinatorChild first = start_coordinator_child(scratch, "before");
  if (first.port == 0) return;
  const std::string port_file = scratch.file("coordinator-before.port");
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7102);

  auto publisher = start_persistent_publisher(scratch, port_file, key, "persistent-boot-4", 4, 1);
  if (!publisher) {
    AIFC_FAIL("could not start the persistent publisher: " +
              aifc::render_status(publisher.status()));
    (void)first.process.kill();
    return;
  }
  aifc_test::ChildProcess publisher_process = std::move(publisher).value();

  const bool became_current = aifc_test::wait_until(
      [&]() { return observe(first.port, key).current == 1; }, 200, 50);
  if (!became_current) {
    AIFC_FAIL("the publisher never produced a current record; publisher output:\n" +
              publisher_process.output());
    (void)publisher_process.kill();
    (void)first.process.kill();
    return;
  }
  AIFC_CHECK(published_count(publisher_process) >= 1);

  const std::string epoch_before = observe(first.port, key).epoch;

  // Kill the coordinator while the publisher is still connected.  The publisher is then in the
  // classic ambiguous-completion position: it has an acknowledgement for a write, but the
  // process that issued the acknowledgement is gone.
  AIFC_CHECK_OK(first.process.kill());

  // The publisher's socket is now dead.  Kill it too, then bring the coordinator back.
  AIFC_CHECK_OK(publisher_process.kill());

  CoordinatorChild second = start_coordinator_child(scratch, "after");
  if (second.port == 0) return;

  const Observation after_restart = observe(second.port, key);
  AIFC_CHECK_MSG(after_restart.epoch != epoch_before,
                 "the coordinator epoch did not advance across the restart: still " +
                     after_restart.epoch);
  // Liveness must not have been resurrected: the pre-restart record cannot be current.
  AIFC_CHECK_EQ(after_restart.current, std::size_t{0});
  AIFC_CHECK_MSG(!after_restart.detail_of_first_stale.empty(),
                 "the stale record carried no reason, so an operator could not tell why the "
                 "class changed");

  AIFC_CHECK_OK(second.process.kill());
}

AIFC_TEST("multiprocess restart: a publisher must learn the new epoch rather than assume it") {
  aifc_test::ScratchDirectory scratch("restart-epoch-learn");
  CoordinatorChild first = start_coordinator_child(scratch, "first");
  if (first.port == 0) return;
  const std::string port_file = scratch.file("coordinator-first.port");
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7103);

  auto initial = run_publisher_once(scratch, port_file, key, "epoch-learn-boot-1", 1, 1);
  if (!initial) {
    AIFC_FAIL("the initial publish failed: " + aifc::render_status(initial.status()));
    (void)first.process.kill();
    return;
  }
  const std::string epoch_one = observe(first.port, key).epoch;
  AIFC_CHECK_OK(first.process.kill());

  CoordinatorChild second = start_coordinator_child(scratch, "second");
  if (second.port == 0) return;
  const std::string second_port_file = scratch.file("coordinator-second.port");
  const std::string epoch_two = observe(second.port, key).epoch;
  AIFC_CHECK_MSG(epoch_one != epoch_two,
                 "the second incarnation reported the same epoch as the first");

  // A publisher that reconnects and performs a fresh handshake publishes successfully: the
  // epoch is learned, not assumed.
  auto republished = run_publisher_once(scratch, second_port_file, key, "epoch-learn-boot-2", 2, 2);
  if (!republished) {
    AIFC_FAIL("a fresh handshake after the restart did not allow publishing: " +
              aifc::render_status(republished.status()));
  } else {
    Observation observation = observe(second.port, key);
    AIFC_CHECK_EQ(observation.current, std::size_t{1});
    AIFC_CHECK_EQ(observation.epoch, epoch_two);
    AIFC_CHECK_EQ(static_cast<int>(observation.selected_source),
                  static_cast<int>(aifc::EvidenceSource::DECLARED_AUTHENTICATED));
  }

  AIFC_CHECK_OK(second.process.kill());
}
