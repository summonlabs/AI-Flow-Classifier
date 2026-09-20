// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "cli.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"

namespace aifc::cli {
namespace {

[[nodiscard]] int exit_code_for(const Status& status) {
  switch (classify(status.code)) {
    case ErrorClass::AUTHORITY:
      return static_cast<int>(ExitCode::kAuthorityError);
    case ErrorClass::INTEGRITY:
      return static_cast<int>(ExitCode::kIntegrityError);
    case ErrorClass::LIFECYCLE:
      return static_cast<int>(ExitCode::kNotRunning);
    default:
      return static_cast<int>(ExitCode::kRuntimeError);
  }
}

[[nodiscard]] int exit_code_for(ErrorCode code) {
  Status status;
  status.code = code;
  return exit_code_for(status);
}

[[nodiscard]] std::string quote_json(std::string_view value) {
  std::string out;
  out.reserve(value.size() + 2);
  for (char ch : value) {
    switch (ch) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default: {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20U) {
          char buffer[8] = {};
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned>(byte));
          out += buffer;
        } else {
          out.push_back(ch);
        }
      }
    }
  }
  out.push_back('"');
  return out;
}

// --- minimal JSON input ----------------------------------------------------

// A deliberately small JSON reader.  The tool accepts a policy file and a scenario file;
// both are structured, so a real parser is warranted rather than a regex.  It is
// strict: trailing content, duplicate keys and unknown shapes are errors.
class JsonReader {
 public:
  explicit JsonReader(std::string_view text) : text_(text) {}

  enum class Kind { kNull, kBool, kNumber, kString, kArray, kObject };

  struct Value {
    Kind kind = Kind::kNull;
    bool boolean = false;
    double number = 0;
    std::string text;
    std::vector<Value> array;
    std::vector<std::pair<std::string, Value>> object;

    [[nodiscard]] const Value* find(std::string_view key) const {
      for (const auto& entry : object) {
        if (entry.first == key) return &entry.second;
      }
      return nullptr;
    }
    [[nodiscard]] bool is_null() const noexcept { return kind == Kind::kNull; }
    [[nodiscard]] std::string as_string() const { return text; }
    [[nodiscard]] std::uint64_t as_u64() const {
      return number < 0 ? 0 : static_cast<std::uint64_t>(number);
    }
    [[nodiscard]] bool as_bool() const { return boolean; }
  };

  [[nodiscard]] Result<Value> parse() {
    skip_space();
    Value value;
    Status status = parse_value(value, 0);
    if (!status) return status;
    skip_space();
    if (position_ != text_.size()) {
      return Status::failure(ErrorCode::TRAILING_GARBAGE,
                             "input contains trailing content after the top-level value");
    }
    return value;
  }

 private:
  [[nodiscard]] Status fail(std::string message) const {
    return Status::failure(ErrorCode::MALFORMED_INPUT,
                           std::move(message) + " at byte " + std::to_string(position_));
  }

  void skip_space() {
    while (position_ < text_.size()) {
      const char ch = text_[position_];
      if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
        ++position_;
        continue;
      }
      break;
    }
  }

  [[nodiscard]] Status parse_value(Value& out, int depth) {
    if (depth > 32) return fail("nesting is too deep");
    skip_space();
    if (position_ >= text_.size()) return fail("unexpected end of input");
    const char ch = text_[position_];
    if (ch == '{') return parse_object(out, depth);
    if (ch == '[') return parse_array(out, depth);
    if (ch == '"') {
      out.kind = Kind::kString;
      return parse_string(out.text);
    }
    if (ch == 't' || ch == 'f') {
      const std::string_view literal = ch == 't' ? std::string_view("true") : std::string_view("false");
      if (text_.compare(position_, literal.size(), literal) != 0) return fail("bad literal");
      out.kind = Kind::kBool;
      out.boolean = ch == 't';
      position_ += literal.size();
      return Status::success();
    }
    if (ch == 'n') {
      if (text_.compare(position_, 4, "null") != 0) return fail("bad literal");
      out.kind = Kind::kNull;
      position_ += 4;
      return Status::success();
    }
    if (ch == '-' || (ch >= '0' && ch <= '9')) return parse_number(out);
    return fail("unexpected character");
  }

  [[nodiscard]] Status parse_number(Value& out) {
    const std::size_t start = position_;
    if (position_ < text_.size() && text_[position_] == '-') ++position_;
    bool digits = false;
    while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') {
      ++position_;
      digits = true;
    }
    if (position_ < text_.size() && text_[position_] == '.') {
      ++position_;
      while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
    }
    if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
      ++position_;
      if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-')) ++position_;
      while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9') ++position_;
    }
    if (!digits) return fail("number has no digits");
    out.kind = Kind::kNumber;
    out.number = std::strtod(std::string(text_.substr(start, position_ - start)).c_str(), nullptr);
    return Status::success();
  }

  [[nodiscard]] Status parse_string(std::string& out) {
    if (text_[position_] != '"') return fail("expected a string");
    ++position_;
    out.clear();
    while (position_ < text_.size()) {
      const char ch = text_[position_++];
      if (ch == '"') return Status::success();
      if (ch != '\\') {
        out.push_back(ch);
        continue;
      }
      if (position_ >= text_.size()) return fail("unterminated escape");
      const char escape = text_[position_++];
      switch (escape) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          if (position_ + 4 > text_.size()) return fail("truncated unicode escape");
          unsigned code = 0;
          for (int i = 0; i < 4; ++i) {
            const char digit = text_[position_++];
            code <<= 4U;
            if (digit >= '0' && digit <= '9') code |= static_cast<unsigned>(digit - '0');
            else if (digit >= 'a' && digit <= 'f') code |= static_cast<unsigned>(digit - 'a' + 10);
            else if (digit >= 'A' && digit <= 'F') code |= static_cast<unsigned>(digit - 'A' + 10);
            else return fail("bad unicode escape");
          }
          // Only the ASCII range is accepted.  An identifier or reason with a non-ASCII
          // character is refused rather than transcoded, because the identity rules are
          // deliberately restricted to [a-z0-9._:-].
          if (code > 0x7FU) {
            return Status::failure(ErrorCode::MALFORMED_INPUT,
                                   "non-ASCII escapes are not accepted in this tool's inputs");
          }
          out.push_back(static_cast<char>(code));
          break;
        }
        default:
          return fail("unrecognised escape");
      }
    }
    return fail("unterminated string");
  }

  [[nodiscard]] Status parse_array(Value& out, int depth) {
    out.kind = Kind::kArray;
    ++position_;  // '['
    skip_space();
    if (position_ < text_.size() && text_[position_] == ']') {
      ++position_;
      return Status::success();
    }
    for (;;) {
      Value element;
      Status status = parse_value(element, depth + 1);
      if (!status) return status;
      out.array.push_back(std::move(element));
      skip_space();
      if (position_ >= text_.size()) return fail("unterminated array");
      if (text_[position_] == ',') {
        ++position_;
        continue;
      }
      if (text_[position_] == ']') {
        ++position_;
        return Status::success();
      }
      return fail("expected ',' or ']'");
    }
  }

  [[nodiscard]] Status parse_object(Value& out, int depth) {
    out.kind = Kind::kObject;
    ++position_;  // '{'
    skip_space();
    if (position_ < text_.size() && text_[position_] == '}') {
      ++position_;
      return Status::success();
    }
    for (;;) {
      skip_space();
      std::string key;
      Status status = parse_string(key);
      if (!status) return status;
      for (const auto& entry : out.object) {
        if (entry.first == key) {
          return Status::failure(ErrorCode::DUPLICATE_IDENTITY,
                                 "duplicate key '" + key + "' in an input object");
        }
      }
      skip_space();
      if (position_ >= text_.size() || text_[position_] != ':') return fail("expected ':'");
      ++position_;
      Value value;
      status = parse_value(value, depth + 1);
      if (!status) return status;
      out.object.emplace_back(std::move(key), std::move(value));
      skip_space();
      if (position_ >= text_.size()) return fail("unterminated object");
      if (text_[position_] == ',') {
        ++position_;
        continue;
      }
      if (text_[position_] == '}') {
        ++position_;
        return Status::success();
      }
      return fail("expected ',' or '}'");
    }
  }

  std::string_view text_;
  std::size_t position_ = 0;
};

// --- rendering -------------------------------------------------------------

void print_error(const Status& status) {
  std::cerr << "error: " << render_status(status) << "\n";
}

void print_error(ErrorCode code, const std::string& message) {
  Status status;
  status.code = code;
  status.message = message;
  print_error(status);
}

void print_classification(const ClassificationResult& result, bool json) {
  if (json) {
    std::cout << render_classification_json(result.classification) << "\n";
    return;
  }
  const Classification& classification = result.classification;
  std::cout << "semantic_class  " << to_string(classification.semantic) << "\n";
  std::cout << "state           " << to_string(classification.state) << "\n";
  std::cout << "confidence      " << classification.confidence.to_decimal() << "\n";
  std::cout << "flow_id         " << classification.flow_id.to_hex() << "\n";
  std::cout << "generation      " << classification.flow_generation.to_string() << "\n";
  std::cout << "selected        "
            << (classification.selected_evidence.empty() ? std::string("<none>")
                                                         : classification.selected_evidence.value())
            << " source " << to_string(classification.selected_source) << "\n";
  std::cout << "policy          generation " << classification.policy_generation.to_string()
            << " digest " << classification.policy_digest.to_hex() << "\n";
  std::cout << "history         " << (result.historical ? "historical" : "current") << "\n";
  std::cout << "decision_digest " << classification.digest.to_hex() << "\n";
}

// --- commands --------------------------------------------------------------

[[nodiscard]] Status read_file(std::string_view path, std::string& out) {
  std::ifstream stream(std::string(path), std::ios::binary);
  if (!stream) {
    return Status::failure(ErrorCode::NOT_FOUND, "cannot open " + std::string(path));
  }
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  out = buffer.str();
  return Status::success();
}

[[nodiscard]] Result<ClassifierPolicy> load_policy(const std::string& path) {
  std::string text;
  Status status = read_file(path, text);
  if (!status) return status;
  Result<JsonReader::Value> parsed = JsonReader(text).parse();
  if (!parsed) return parsed.status();
  const JsonReader::Value& root = parsed.value();
  if (root.kind != JsonReader::Kind::kObject) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "a policy file must contain a JSON object");
  }
  ClassifierPolicy policy = ClassifierPolicy::initial();
  if (const JsonReader::Value* generation = root.find("generation")) {
    policy.generation = ClassifierPolicyGeneration{generation->as_u64()};
  }
  if (const JsonReader::Value* allow = root.find("allow_heuristic_evidence")) {
    policy.allow_heuristic_evidence = allow->as_bool();
  }
  if (const JsonReader::Value* window = root.find("default_freshness_window")) {
    policy.default_freshness_window = window->as_u64();
  }
  if (const JsonReader::Value* penalty = root.find("contradiction_penalty")) {
    policy.contradiction_penalty = static_cast<std::uint32_t>(penalty->as_u64());
  }
  if (const JsonReader::Value* threshold = root.find("minimum_publishable_confidence")) {
    policy.minimum_publishable_confidence = static_cast<std::uint32_t>(threshold->as_u64());
  }
  if (const JsonReader::Value* considered = root.find("max_evidence_considered")) {
    policy.max_evidence_considered = static_cast<std::uint32_t>(considered->as_u64());
  }
  if (const JsonReader::Value* adapters = root.find("heuristic_adapters")) {
    if (adapters->kind != JsonReader::Kind::kArray) {
      return Status::failure(ErrorCode::MALFORMED_INPUT, "heuristic_adapters must be an array");
    }
    for (const JsonReader::Value& element : adapters->array) {
      if (element.kind != JsonReader::Kind::kObject) {
        return Status::failure(ErrorCode::MALFORMED_INPUT,
                               "each heuristic adapter must be a JSON object");
      }
      HeuristicAdapterPolicy adapter;
      const JsonReader::Value* name = element.find("name");
      if (name == nullptr) {
        return Status::failure(ErrorCode::MALFORMED_INPUT, "a heuristic adapter needs a name");
      }
      adapter.name = name->as_string();
      if (const JsonReader::Value* enabled = element.find("enabled")) {
        adapter.enabled = enabled->as_bool();
      }
      if (const JsonReader::Value* maximum = element.find("max_basis_points")) {
        adapter.max_basis_points = static_cast<std::uint32_t>(maximum->as_u64());
      }
      if (const JsonReader::Value* priority = element.find("priority")) {
        adapter.priority = static_cast<std::uint32_t>(priority->as_u64());
      }
      policy.heuristic_adapters.push_back(std::move(adapter));
    }
  }
  if (const JsonReader::Value* hints = root.find("port_hints")) {
    if (hints->kind != JsonReader::Kind::kArray) {
      return Status::failure(ErrorCode::MALFORMED_INPUT, "port_hints must be an array");
    }
    for (const JsonReader::Value& element : hints->array) {
      if (element.kind != JsonReader::Kind::kObject) {
        return Status::failure(ErrorCode::MALFORMED_INPUT, "each port hint must be a JSON object");
      }
      PortHint hint;
      const JsonReader::Value* transport = element.find("transport");
      const JsonReader::Value* port = element.find("port");
      const JsonReader::Value* semantic = element.find("semantic_class");
      if (transport == nullptr || port == nullptr || semantic == nullptr) {
        return Status::failure(ErrorCode::MALFORMED_INPUT,
                               "a port hint needs transport, port and semantic_class");
      }
      Result<TransportProtocol> parsed_transport = parse_transport_protocol(transport->as_string());
      if (!parsed_transport) return parsed_transport.status();
      hint.transport = parsed_transport.value();
      hint.port = static_cast<std::uint16_t>(port->as_u64());
      Result<SemanticClass> parsed_semantic = parse_semantic_class(semantic->as_string());
      if (!parsed_semantic) return parsed_semantic.status();
      hint.semantic = parsed_semantic.value();
      if (const JsonReader::Value* basis = element.find("basis_points")) {
        hint.basis_points = static_cast<std::uint32_t>(basis->as_u64());
      }
      if (const JsonReader::Value* adapter = element.find("adapter")) {
        hint.adapter = adapter->as_string();
      }
      policy.port_hints.push_back(std::move(hint));
    }
  }
  return ClassifierPolicy::canonicalize(std::move(policy));
}

[[nodiscard]] std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> out;
  std::string current;
  for (char ch : text) {
    if (ch == separator) {
      out.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  if (!current.empty()) out.push_back(current);
  return out;
}

// Parses "proto/address:port", the canonical flow key text accepted by the tool.
[[nodiscard]] Result<FlowKey> parse_flow_key(const std::string& text) {
  const std::size_t slash = text.find('/');
  const std::size_t arrow = text.find("->");
  if (slash == std::string::npos || arrow == std::string::npos || arrow < slash) {
    return Status::failure(ErrorCode::MALFORMED_INPUT,
                           "a flow key must read PROTO/LOCAL:PORT->REMOTE:PORT");
  }
  Result<TransportProtocol> transport = parse_transport_protocol(text.substr(0, slash));
  if (!transport) return transport.status();
  const std::string local = text.substr(slash + 1, arrow - slash - 1);
  const std::string remote = text.substr(arrow + 2);
  const std::size_t local_colon = local.rfind(':');
  const std::size_t remote_colon = remote.rfind(':');
  if (local_colon == std::string::npos || remote_colon == std::string::npos) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "both endpoints need a port");
  }
  auto parse_v4 = [](const std::string& host, std::uint32_t& out) -> Status {
    const std::vector<std::string> parts = split(host, '.');
    if (parts.size() != 4) {
      return Status::failure(ErrorCode::MALFORMED_INPUT,
                             "only dotted-quad addresses are accepted by this tool");
    }
    std::uint32_t value = 0;
    for (const std::string& part : parts) {
      if (part.empty() || part.size() > 3) {
        return Status::failure(ErrorCode::MALFORMED_INPUT, "bad address octet");
      }
      std::uint32_t octet = 0;
      for (char ch : part) {
        if (ch < '0' || ch > '9') {
          return Status::failure(ErrorCode::MALFORMED_INPUT, "bad address octet");
        }
        octet = octet * 10U + static_cast<std::uint32_t>(ch - '0');
      }
      if (octet > 255U) return Status::failure(ErrorCode::MALFORMED_INPUT, "address octet out of range");
      value = (value << 8) | octet;
    }
    out = value;
    return Status::success();
  };
  std::uint32_t local_address = 0;
  std::uint32_t remote_address = 0;
  Status status = parse_v4(local.substr(0, local_colon), local_address);
  if (!status) return status;
  status = parse_v4(remote.substr(0, remote_colon), remote_address);
  if (!status) return status;
  auto parse_port = [](const std::string& text_port, std::uint16_t& out) -> Status {
    if (text_port.empty() || text_port.size() > 5) {
      return Status::failure(ErrorCode::MALFORMED_INPUT, "bad port");
    }
    std::uint32_t value = 0;
    for (char ch : text_port) {
      if (ch < '0' || ch > '9') return Status::failure(ErrorCode::MALFORMED_INPUT, "bad port");
      value = value * 10U + static_cast<std::uint32_t>(ch - '0');
    }
    if (value > 65535U) return Status::failure(ErrorCode::MALFORMED_INPUT, "port out of range");
    out = static_cast<std::uint16_t>(value);
    return Status::success();
  };
  FlowKey key;
  key.transport = transport.value();
  key.local_address = IpAddress::from_v4(local_address);
  key.remote_address = IpAddress::from_v4(remote_address);
  status = parse_port(local.substr(local_colon + 1), key.local_port);
  if (!status) return status;
  status = parse_port(remote.substr(remote_colon + 1), key.remote_port);
  if (!status) return status;
  return key;
}

// --- scenario execution ----------------------------------------------------

struct ScenarioContext {
  std::unique_ptr<Coordinator> coordinator;
  std::map<std::string, SessionEnvelope> sessions;
  std::map<std::string, FlowRecord> flows;
  std::vector<std::string> output;
};

[[nodiscard]] Result<SessionEnvelope> ensure_session(ScenarioContext& context,
                                                     const std::string& publisher,
                                                     std::uint64_t boot,
                                                     const std::string& session,
                                                     const std::string& source,
                                                     const std::string& description) {
  const auto existing = context.sessions.find(publisher);
  if (existing != context.sessions.end()) return existing->second;
  Result<std::string> publisher_id = canonicalize_identity(publisher);
  if (!publisher_id) return publisher_id.status();
  Result<EvidenceSource> parsed_source = parse_evidence_source(source);
  if (!parsed_source) return parsed_source.status();
  Result<PublisherRegistration> registration = context.coordinator->classifier().register_publisher(
      make_publisher_id(publisher_id.value()), PublisherBootId{boot}, parsed_source.value(),
      SessionId(session), description);
  if (!registration) return registration.status();
  SessionEnvelope envelope = make_session_envelope(registration.value(), 0);
  context.sessions.emplace(publisher, envelope);
  return envelope;
}

[[nodiscard]] Result<int> run_scenario(const Options& options) {
  if (options.positional.empty()) {
    return Status::failure(ErrorCode::INVALID_ARGUMENT, "a scenario file is required");
  }
  std::string text;
  Status status = read_file(options.positional.front(), text);
  if (!status) return status;
  Result<JsonReader::Value> parsed = JsonReader(text).parse();
  if (!parsed) return parsed.status();
  const JsonReader::Value& root = parsed.value();
  if (root.kind != JsonReader::Kind::kObject) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "a scenario file must contain a JSON object");
  }

  CoordinatorOptions coordinator_options;
  coordinator_options.policy = ClassifierPolicy::initial();
  {
    const JsonReader::Value* policy_path = root.find("policy_path");
    if (policy_path != nullptr) {
      Result<ClassifierPolicy> policy = load_policy(policy_path->as_string());
      if (!policy) return policy.status();
      coordinator_options.policy = policy.value();
    }
  }
  if (!options.state_path.empty()) {
    coordinator_options.state_path = options.state_path;
  } else if (const JsonReader::Value* state = root.find("state_path")) {
    coordinator_options.state_path = state->as_string();
  }
  if (options.verbose) {
    coordinator_options.logger.set_sink([](const LogRecord& record) {
      std::cerr << "[" << to_string(record.level) << "] " << record.component << ": " << record.message
                << "\n";
    });
    coordinator_options.logger.set_clock([]() { return static_cast<std::uint64_t>(0); });
    coordinator_options.logger.set_level(LogLevel::kDebug);
  }
  Coordinator coordinator(coordinator_options);
  status = coordinator.start(CoordinatorBootId{1});
  if (!status) return status;

  ScenarioContext context;
  context.coordinator = nullptr;  // the coordinator above is stack owned

  const JsonReader::Value* steps = root.find("steps");
  if (steps == nullptr || steps->kind != JsonReader::Kind::kArray) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "a scenario needs a steps array");
  }

  std::map<std::string, SessionEnvelope> sessions;
  std::map<std::string, FlowRecord> flows;
  std::string last_classification_json;

  int exit_code = static_cast<int>(ExitCode::kOk);
  for (const JsonReader::Value& step : steps->array) {
    if (step.kind != JsonReader::Kind::kObject) {
      return Status::failure(ErrorCode::MALFORMED_INPUT, "each step must be a JSON object");
    }
    const JsonReader::Value* action = step.find("action");
    if (action == nullptr) {
      return Status::failure(ErrorCode::MALFORMED_INPUT, "each step needs an action");
    }
    const std::string name = action->as_string();
    ScenarioContext* ctx = nullptr;
    (void)ctx;

    if (name == "register_publisher") {
      const JsonReader::Value* publisher = step.find("publisher");
      if (publisher == nullptr) return Status::failure(ErrorCode::MALFORMED_INPUT, "publisher required");
      const JsonReader::Value* boot = step.find("boot");
      const JsonReader::Value* session = step.find("session");
      const JsonReader::Value* source = step.find("source");
      Result<std::string> publisher_id = canonicalize_identity(publisher->as_string());
      if (!publisher_id) return publisher_id.status();
      const std::string source_name = source != nullptr ? source->as_string() : "DECLARED_AUTHENTICATED";
      Result<EvidenceSource> parsed_source = parse_evidence_source(source_name);
      if (!parsed_source) return parsed_source.status();
      const std::string session_name =
          session != nullptr ? session->as_string() : "session-" + publisher_id.value();
      Result<std::string> session_id = canonicalize_identity(session_name);
      if (!session_id) return session_id.status();
      Result<PublisherRegistration> registration = coordinator.classifier().register_publisher(
          make_publisher_id(publisher_id.value()),
          PublisherBootId{boot != nullptr ? boot->as_u64() : 1}, parsed_source.value(),
          SessionId(session_id.value()), "cli scenario publisher");
      if (!registration) {
        print_error(registration.status());
        return exit_code_for(registration.status());
      }
      sessions[publisher_id.value()] = make_session_envelope(registration.value(), 0);
      continue;
    }

    if (name == "register_flow") {
      const JsonReader::Value* key_value = step.find("flow_key");
      if (key_value == nullptr) return Status::failure(ErrorCode::MALFORMED_INPUT, "flow_key required");
      Result<FlowKey> key = parse_flow_key(key_value->as_string());
      if (!key) return key.status();
      const JsonReader::Value* generation = step.find("generation");
      Result<FlowRegistration> registration = coordinator.classifier().register_flow(
          key.value(), FlowGeneration{generation != nullptr ? generation->as_u64() : 0}, SessionId("cli"));
      if (!registration) {
        print_error(registration.status());
        return exit_code_for(registration.status());
      }
      const std::string id = registration.value().record.id.to_hex();
      flows[id] = registration.value().record;
      flows[key_value->as_string()] = registration.value().record;
      continue;
    }

    if (name == "publish_evidence") {
      const JsonReader::Value* publisher = step.find("publisher");
      const JsonReader::Value* key_value = step.find("flow_key");
      const JsonReader::Value* semantic = step.find("semantic_class");
      if (publisher == nullptr || key_value == nullptr || semantic == nullptr) {
        return Status::failure(ErrorCode::MALFORMED_INPUT,
                               "publish_evidence needs publisher, flow_key and semantic_class");
      }
      Result<std::string> publisher_id = canonicalize_identity(publisher->as_string());
      if (!publisher_id) return publisher_id.status();
      auto session = sessions.find(publisher_id.value());
      if (session == sessions.end()) {
        return Status::failure(ErrorCode::UNAUTHENTICATED,
                               "publisher " + publisher_id.value() + " has no session in this scenario");
      }
      Result<FlowKey> key = parse_flow_key(key_value->as_string());
      if (!key) return key.status();
      auto flow = flows.find(key_value->as_string());
      if (flow == flows.end()) {
        return Status::failure(ErrorCode::UNKNOWN_FLOW, "the flow has not been registered");
      }
      Result<SemanticClass> parsed_semantic = parse_semantic_class(semantic->as_string());
      if (!parsed_semantic) return parsed_semantic.status();
      const JsonReader::Value* generation = step.find("evidence_generation");
      const JsonReader::Value* topic = step.find("topic");
      const JsonReader::Value* source = step.find("source");
      EvidencePayload payload;
      payload.flow_key = key.value();
      payload.flow_generation = flow->second.generation;
      payload.evidence_generation =
          EvidenceGeneration{generation != nullptr ? generation->as_u64() : 1};
      payload.semantic = parsed_semantic.value();
      payload.metadata.topic = topic != nullptr ? topic->as_string() : "cli.topic";
      payload.metadata.reason = "cli scenario evidence";
      if (source != nullptr) {
        Result<EvidenceSource> parsed_source = parse_evidence_source(source->as_string());
        if (!parsed_source) return parsed_source.status();
        payload.claimed_source = parsed_source.value();
      } else {
        payload.claimed_source = session->second.max_source;
      }
      const JsonReader::Value* window = step.find("freshness_window");
      if (window != nullptr) payload.freshness_window = window->as_u64();
      Result<EvidenceSubmissionOutcome> outcome =
          coordinator.classifier().submit_evidence(session->second, payload);
      if (!outcome) {
        print_error(outcome.status());
        return exit_code_for(outcome.status());
      }
      continue;
    }

    if (name == "classify") {
      const JsonReader::Value* key_value = step.find("flow_key");
      if (key_value == nullptr) return Status::failure(ErrorCode::MALFORMED_INPUT, "flow_key required");
      Result<FlowKey> key = parse_flow_key(key_value->as_string());
      if (!key) return key.status();
      ClassificationQuery query;
      query.flow_key = key.value();
      query.explain = true;
      const JsonReader::Value* generation = step.find("generation");
      if (generation != nullptr) query.flow_generation = FlowGeneration{generation->as_u64()};
      query.accept_current_generation = query.flow_generation.value == 0;
      Result<ClassificationResult> classified = coordinator.classifier().classify(query);
      if (!classified) {
        print_error(classified.status());
        return exit_code_for(classified.status());
      }
      print_classification(classified.value(), options.output_format == "json");
      last_classification_json = render_classification_json(classified.value().classification);
      if (options.explain && options.output_format != "json") {
        std::cout << classified.value().explanation << "\n";
      }
      if (classified.value().classification.semantic == SemanticClass::UNKNOWN) {
        exit_code = static_cast<int>(ExitCode::kUnknownClass);
      }
      continue;
    }

    if (name == "revoke_generation") {
      const JsonReader::Value* publisher = step.find("publisher");
      if (publisher == nullptr) return Status::failure(ErrorCode::MALFORMED_INPUT, "publisher required");
      Result<std::string> publisher_id = canonicalize_identity(publisher->as_string());
      if (!publisher_id) return publisher_id.status();
      auto session = sessions.find(publisher_id.value());
      if (session == sessions.end()) {
        return Status::failure(ErrorCode::UNAUTHENTICATED, "publisher has no session");
      }
      const JsonReader::Value* flow_id = step.find("flow_id");
      const JsonReader::Value* generation = step.find("generation");
      if (flow_id == nullptr || generation == nullptr) {
        return Status::failure(ErrorCode::MALFORMED_INPUT, "flow_id and generation required");
      }
      // The flow id is 32 hex characters; only hex is accepted so that a typo is a
      // refusal rather than a silently different flow.
      const std::string hex = flow_id->as_string();
      if (hex.size() != 32) {
        return Status::failure(ErrorCode::MALFORMED_INPUT, "a flow id must be 32 hex characters");
      }
      Id128 id;
      auto hex_value = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
      };
      for (std::size_t i = 0; i < 16; ++i) {
        const int high = hex_value(hex[i * 2]);
        const int low = hex_value(hex[i * 2 + 1]);
        if (high < 0 || low < 0) {
          return Status::failure(ErrorCode::MALFORMED_INPUT, "a flow id must be hexadecimal");
        }
        const auto byte = static_cast<std::uint8_t>((high << 4) | low);
        if (i < 8) {
          id.hi = (id.hi << 8) | byte;
        } else {
          id.lo = (id.lo << 8) | byte;
        }
      }
      const JsonReader::Value* reason = step.find("reason");
      Status revoked = coordinator.classifier().revoke_generation(
          session->second, id, FlowGeneration{generation->as_u64()},
          reason != nullptr ? reason->as_string() : std::string("revoked by scenario"));
      if (!revoked) {
        print_error(revoked);
        return exit_code_for(revoked);
      }
      continue;
    }

    if (name == "end_session") {
      const JsonReader::Value* publisher = step.find("publisher");
      if (publisher == nullptr) return Status::failure(ErrorCode::MALFORMED_INPUT, "publisher required");
      Result<std::string> publisher_id = canonicalize_identity(publisher->as_string());
      if (!publisher_id) return publisher_id.status();
      auto session = sessions.find(publisher_id.value());
      if (session == sessions.end()) continue;
      Status ended = coordinator.classifier().end_publisher_session(session->second.publisher,
                                                                   session->second.publisher_boot);
      if (!ended) {
        print_error(ended);
        return exit_code_for(ended);
      }
      sessions.erase(session);
      continue;
    }

    if (name == "persist") {
      Status persisted = coordinator.persist();
      if (!persisted) {
        print_error(persisted);
        return exit_code_for(persisted);
      }
      continue;
    }

    if (name == "advance_epoch") {
      const JsonReader::Value* boot = step.find("boot");
      Result<CoordinatorEpoch> advanced =
          coordinator.classifier().advance_epoch(CoordinatorBootId{boot != nullptr ? boot->as_u64() : 2});
      if (!advanced) {
        print_error(advanced.status());
        return exit_code_for(advanced.status());
      }
      continue;
    }

    return Status::failure(ErrorCode::UNSUPPORTED_OPERATION, "unknown scenario action: " + name);
  }

  status = coordinator.stop();
  if (!status) {
    print_error(status);
    return exit_code_for(status);
  }
  return exit_code;
}

}  // namespace

std::string usage() {
  return R"(AI Flow Classifier 1.0.0

Usage:
  ai-flow-classifier version
  ai-flow-classifier banner
  ai-flow-classifier vocabularies
  ai-flow-classifier classes
  ai-flow-classifier policy-check <policy.json>
  ai-flow-classifier scenario <scenario.json> [--state PATH] [--json] [--explain] [--verbose]

Options:
  --state PATH   durable coordinator state file used by the scenario runner
  --json         render classifications as canonical JSON instead of a text block
  --explain      print the full evidence explanation after each classification
  --verbose      emit structured diagnostics on stderr

Exit codes:
   0  success
   3  a classification was produced and the semantic class is UNKNOWN
  64  usage error
  65  integrity or format failure
  69  the coordinator is not in a state where the request is meaningful
  70  other runtime failure
  77  authority failure (stale generation, dead publisher, unauthenticated, ...)

The tool owns no classification logic: every value it prints was decided by the
library.
)";
}

int run(const std::vector<std::string>& arguments) {
  if (arguments.empty()) {
    std::cerr << usage();
    return static_cast<int>(ExitCode::kUsageError);
  }
  Options options;
  std::vector<std::string> positional;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    const std::string& argument = arguments[i];
    if (argument == "--state") {
      if (i + 1 >= arguments.size()) {
        std::cerr << "--state needs a path\n";
        return static_cast<int>(ExitCode::kUsageError);
      }
      options.state_path = arguments[++i];
      continue;
    }
    if (argument == "--json") {
      options.output_format = "json";
      continue;
    }
    if (argument == "--explain") {
      options.explain = true;
      continue;
    }
    if (argument == "--verbose") {
      options.verbose = true;
      continue;
    }
    if (argument == "--help" || argument == "-h") {
      std::cout << usage();
      return static_cast<int>(ExitCode::kOk);
    }
    if (argument.rfind("--", 0) == 0) {
      std::cerr << "unknown option: " << argument << "\n";
      return static_cast<int>(ExitCode::kUsageError);
    }
    positional.push_back(argument);
  }
  options.positional = positional;
  if (positional.empty()) {
    std::cerr << usage();
    return static_cast<int>(ExitCode::kUsageError);
  }
  options.command = positional.front();

  if (options.command == "version") {
    std::cout << product_version_string() << "\n";
    return static_cast<int>(ExitCode::kOk);
  }
  if (options.command == "banner") {
    std::cout << product_banner() << "\n";
    return static_cast<int>(ExitCode::kOk);
  }
  if (options.command == "classes") {
    for (SemanticClass value : all_builtin_classes()) {
      std::cout << to_string(value) << "\n";
    }
    return static_cast<int>(ExitCode::kOk);
  }
  if (options.command == "vocabularies") {
    std::cout << "semantic classes:\n";
    for (SemanticClass value : all_builtin_classes()) {
      std::cout << "  " << to_string(value) << "\n";
    }
    std::cout << "evidence sources (strongest first):\n";
    const EvidenceSource sources[] = {
        EvidenceSource::DECLARED_AUTHENTICATED, EvidenceSource::CONTRACT_DERIVED,
        EvidenceSource::COORDINATOR_CORRELATED, EvidenceSource::TOPOLOGY_CORRELATED,
        EvidenceSource::HEURISTIC, EvidenceSource::UNKNOWN};
    for (EvidenceSource source : sources) {
      std::cout << "  " << to_string(source) << " rank "
                << static_cast<unsigned>(source_rank(source)) << " confidence "
                << source_confidence(source).to_decimal() << "\n";
    }
    std::cout << "evidence states:\n";
    const EvidenceState states[] = {
        EvidenceState::EVIDENCE_CURRENT, EvidenceState::EVIDENCE_STALE,
        EvidenceState::EVIDENCE_SUPERSEDED, EvidenceState::EVIDENCE_REVOKED,
        EvidenceState::EVIDENCE_INSUFFICIENT, EvidenceState::EVIDENCE_REJECTED};
    for (EvidenceState state : states) {
      std::cout << "  " << to_string(state) << "\n";
    }
    std::cout << "classification states:\n";
    const ClassificationState classification_states[] = {
        ClassificationState::UNKNOWN,     ClassificationState::CURRENT,
        ClassificationState::CORROBORATED, ClassificationState::CONTRADICTED,
        ClassificationState::STALE,       ClassificationState::INSUFFICIENT,
        ClassificationState::REVOKED};
    for (ClassificationState state : classification_states) {
      std::cout << "  " << to_string(state) << "\n";
    }
    return static_cast<int>(ExitCode::kOk);
  }
  if (options.command == "policy-check") {
    if (positional.size() < 2) {
      std::cerr << "policy-check needs a policy file\n";
      return static_cast<int>(ExitCode::kUsageError);
    }
    Result<ClassifierPolicy> policy = load_policy(positional[1]);
    if (!policy) {
      print_error(policy.status());
      return exit_code_for(policy.status());
    }
    const Digest256 digest = compute_policy_digest(policy.value());
    std::cout << "policy_generation " << policy.value().generation.to_string() << "\n";
    std::cout << "policy_digest     " << digest.to_hex() << "\n";
    std::cout << "heuristics        "
              << (policy.value().allow_heuristic_evidence ? "permitted" : "refused") << "\n";
    std::cout << "adapters          " << policy.value().heuristic_adapters.size() << "\n";
    std::cout << "port_hints        " << policy.value().port_hints.size() << "\n";
    std::cout << "contradiction_penalty_bp " << policy.value().contradiction_penalty << "\n";
    std::cout << "minimum_publishable_bp   " << policy.value().minimum_publishable_confidence
              << "\n";
    return static_cast<int>(ExitCode::kOk);
  }
  if (options.command == "scenario") {
    std::vector<std::string> scenario_positional(positional.begin() + 1, positional.end());
    Options scenario_options = options;
    scenario_options.positional = std::move(scenario_positional);
    Result<int> result = run_scenario(scenario_options);
    if (!result) {
      print_error(result.status());
      return exit_code_for(result.status());
    }
    return result.value();
  }

  std::cerr << "unknown command: " << options.command << "\n\n" << usage();
  return static_cast<int>(ExitCode::kUsageError);
}

}  // namespace aifc::cli
