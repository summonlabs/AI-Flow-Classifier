// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Unit proof surface: domain vocabulary, identities, provenance and digests.
//
// Capability labels: REAL means the shipped implementation is exercised; SYNTHETIC means the
// inputs are invented here.  Nothing in this file observes real traffic or real hardware.

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "test_framework.hpp"

#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow_key.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/semantic_class.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

#include "synthetic.hpp"

namespace {

[[nodiscard]] std::string status_text(const aifc::Status& status) {
  return std::string(aifc::to_string(status.code)) + " (" + status.message + ")";
}

// Every canonical semantic class name, in the canonical order.  Kept here rather than derived
// from the library so that a rename in the library fails this test instead of agreeing with it.
constexpr std::string_view kBuiltinNames[] = {
    "UNKNOWN",     "COLLECTIVE",     "TRAINING_SYNC",        "INFERENCE_REQUEST",
    "PREFILL_DECODE_HANDOFF", "KV_STATE_TRANSFER", "MODEL_STATE_TRANSFER", "SHUFFLE",
    "CHECKPOINT",  "STORAGE_DATA",   "CONTROL_PLANE",        "TELEMETRY",
};

[[nodiscard]] aifc::EvidenceRecord make_record(const aifc::EvidenceId& id) {
  aifc::EvidenceRecord record;
  record.id = id;
  record.publisher = aifc::make_publisher_id("publisher-1");
  record.publisher_boot = aifc::PublisherBootId{3};
  record.session = aifc::SessionId("session-1");
  record.accepted_epoch = aifc::CoordinatorEpoch{2};
  record.accepted_boot = aifc::CoordinatorBootId{9};
  record.workload = aifc::make_workload_id("workload-1");
  record.workload_generation = aifc::WorkloadGeneration{4};
  record.contract = aifc::make_contract_id("contract-1");
  record.flow_id = aifc::Id128{0x1111111111111111ULL, 0x2222222222222222ULL};
  record.flow_generation = aifc::FlowGeneration{2};
  record.generation = aifc::EvidenceGeneration{5};
  record.accepted_seq = 17;
  record.accepted_tick = 100;
  record.fresh_until = 4196;
  record.semantic = aifc::SemanticClass::COLLECTIVE;
  record.source = aifc::EvidenceSource::DECLARED_AUTHENTICATED;
  record.state = aifc::EvidenceState::EVIDENCE_CURRENT;
  record.confidence = aifc::Confidence::from_basis_points(9000U);
  record.metadata.topic = "workload.rank.7.collective";
  record.metadata.binding = 42;
  record.metadata.reason = "synthetic reason";
  record.metadata.contract = aifc::make_contract_id("contract-1");
  record.state_reason = "synthetic state reason";
  record.content_digest = aifc::compute_evidence_digest(record);
  return record;
}

[[nodiscard]] aifc::WorkloadContract make_contract() {
  aifc::WorkloadContract contract;
  contract.id = aifc::make_contract_id("contract-1");
  contract.workload = aifc::make_workload_id("workload-1");
  contract.workload_generation = aifc::WorkloadGeneration{3};
  contract.owner = aifc::make_publisher_id("publisher-1");
  contract.state = aifc::ContractState::ACTIVE;
  contract.declared_class = aifc::SemanticClass::KV_STATE_TRANSFER;
  contract.match_any_remote_address = true;
  contract.transport = aifc::TransportProtocol::TCP;
  contract.remote_port = 2049;
  contract.derived_source = aifc::EvidenceSource::CONTRACT_DERIVED;
  contract.description = "synthetic contract";
  return contract;
}

[[nodiscard]] aifc::ClassifierPolicy make_policy_with_adapters(bool reversed) {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.allow_heuristic_evidence = true;
  aifc::HeuristicAdapterPolicy alpha;
  alpha.name = "adapter-alpha";
  alpha.enabled = true;
  alpha.max_basis_points = 1500U;
  alpha.priority = 2;
  aifc::HeuristicAdapterPolicy beta;
  beta.name = "adapter-beta";
  beta.enabled = false;
  beta.max_basis_points = 900U;
  beta.priority = 1;
  // A third adapter exists so that the second port hint below can name a declared adapter.  A hint
  // that names nothing is now refused by canonicalize, because it would be configuration that can
  // never fire, and this fixture is about ordering rather than about dangling configuration.
  aifc::HeuristicAdapterPolicy gamma;
  gamma.name = "adapter-gamma";
  gamma.enabled = true;
  gamma.max_basis_points = 700U;
  gamma.priority = 0;
  if (reversed) {
    policy.heuristic_adapters = {gamma, beta, alpha};
  } else {
    policy.heuristic_adapters = {alpha, beta, gamma};
  }
  aifc::PortHint first;
  first.transport = aifc::TransportProtocol::TCP;
  first.port = 2049;
  first.semantic = aifc::SemanticClass::STORAGE_DATA;
  first.basis_points = 800U;
  first.adapter = "adapter-beta";
  aifc::PortHint second;
  second.transport = aifc::TransportProtocol::UDP;
  second.port = 4791;
  second.semantic = aifc::SemanticClass::TELEMETRY;
  second.basis_points = 300U;
  second.adapter = "adapter-gamma";
  if (reversed) {
    policy.port_hints = {second, first};
  } else {
    policy.port_hints = {first, second};
  }
  return policy;
}

}  // namespace

// ---------------------------------------------------------------------------
// Semantic classes
// ---------------------------------------------------------------------------

AIFC_TEST("domain/semantic_class: parse, decode and round trip (REAL)") {
  const std::vector<aifc::SemanticClass>& builtins = aifc::all_builtin_classes();
  AIFC_CHECK_EQ(builtins.size(), std::size_t{12});
  for (std::size_t index = 0; index < builtins.size(); ++index) {
    const aifc::SemanticClass value = builtins[index];
    AIFC_CHECK_MSG(index < 12U, "unexpected extra built-in class at index " << index);
    if (index < 12U) {
      AIFC_CHECK_MSG(aifc::to_string(value) == kBuiltinNames[index],
                     "built-in class " << index << " renders as \"" << aifc::to_string(value)
                                       << "\" but the canonical name is \"" << kBuiltinNames[index]
                                       << "\"");
    }
    AIFC_CHECK_MSG(static_cast<std::uint16_t>(value) == index,
                   "built-in class " << index << " has code "
                                     << static_cast<unsigned>(static_cast<std::uint16_t>(value)));
    // Round trip through the canonical name.
    const auto parsed = aifc::parse_semantic_class(aifc::to_string(value));
    AIFC_CHECK_MSG(parsed.ok(), "parse_semantic_class(\"" << aifc::to_string(value)
                                                          << "\") failed: "
                                                          << status_text(parsed.status()));
    if (parsed.ok()) {
      AIFC_CHECK_MSG(parsed.value() == value,
                     "round trip of \"" << aifc::to_string(value) << "\" produced \""
                                        << aifc::to_string(parsed.value()) << "\"");
    }
    // Round trip through the numeric code.
    const auto decoded = aifc::decode_semantic_class(static_cast<std::uint16_t>(value));
    AIFC_CHECK_MSG(decoded.ok(), "decode_semantic_class(" << index << ") failed");
    if (decoded.ok()) {
      AIFC_CHECK_MSG(decoded.value() == value,
                     "decode_semantic_class(" << index << ") produced \""
                                              << aifc::to_string(decoded.value()) << "\"");
    }
  }

  AIFC_CHECK(aifc::is_unknown(aifc::SemanticClass::UNKNOWN));
  AIFC_CHECK(!aifc::is_unknown(aifc::SemanticClass::COLLECTIVE));
  AIFC_CHECK_EQ(static_cast<std::uint16_t>(aifc::SemanticClass::kExtensionBase), 256U);
  AIFC_CHECK_EQ(aifc::kMaxExtensionClasses, 64U);

  // A code that is not a built-in is UNKNOWN with ok(): the code is understood, the class is
  // not.  This is the only path that may produce UNKNOWN from the wire.
  const std::uint16_t unknown_codes[] = {12U, 13U, 255U, 256U, 257U, 4096U, 65535U};
  for (const std::uint16_t code : unknown_codes) {
    const auto decoded = aifc::decode_semantic_class(code);
    AIFC_CHECK_MSG(decoded.ok(), "decode_semantic_class(" << code << ") must succeed with UNKNOWN");
    if (decoded.ok()) {
      AIFC_CHECK_MSG(decoded.value() == aifc::SemanticClass::UNKNOWN,
                     "decode_semantic_class(" << code << ") produced \""
                                              << aifc::to_string(decoded.value())
                                              << "\" instead of UNKNOWN");
    }
  }

  // An extension code is never produced by decoding a label.
  AIFC_CHECK_ERR(aifc::parse_semantic_class("EXTENSION"), aifc::ErrorCode::MALFORMED_INPUT);
}

AIFC_TEST("domain/semantic_class: near-miss labels are MALFORMED_INPUT and never UNKNOWN (REAL)") {
  // The property being pinned: UNKNOWN is a legitimate classification, so it must never be
  // reachable by misspelling a real class.  Each of these is one character or one convention
  // away from a canonical label.
  const std::string_view near_misses[] = {
      "collective",             // lower case
      "Collective",             // mixed case
      "COLLECTIVE ",            // trailing space
      " COLLECTIVE",            // leading space
      "COLLECTIVE\t",           // trailing tab
      "COLLECTIVE\n",           // trailing newline
      "KV STATE TRANSFER",      // spaces instead of underscores
      "KV-STATE-TRANSFER",      // hyphens instead of underscores
      "KV_STATE_TRANSFER ",     // trailing space on a two-word class
      "kv_state_transfer",      // lower case two-word class
      "TRAINING-SYNC",          // hyphen
      "TRAININGSYNC",           // missing separator
      "INFERENCE",              // prefix of a real class
      "INFERENCE_REQUESTS",     // plural
      "PREFILL_DECODE",         // prefix
      "MODEL_STATE",            // prefix
      "CHECKPOINTS",            // plural
      "CONTROLPLANE",           // missing separator
      "UNKNOWN ",               // padded UNKNOWN
      "unknown",                // lower case UNKNOWN
      "",                       // empty
      "\xE2\x80\x8B" "COLLECTIVE",  // zero width space prefix
  };
  for (const std::string_view input : near_misses) {
    const auto parsed = aifc::parse_semantic_class(input);
    AIFC_CHECK_MSG(!parsed.ok(),
                   "parse_semantic_class must refuse the " << input.size() << " byte label \""
                                                           << input << "\"");
    if (!parsed.ok()) {
      AIFC_CHECK_MSG(parsed.code() == aifc::ErrorCode::MALFORMED_INPUT,
                     "parse_semantic_class(\"" << input << "\") produced "
                                               << std::string(aifc::to_string(parsed.code()))
                                               << " (" << parsed.status().message
                                               << ") instead of MALFORMED_INPUT");
      // Explicitly: the failure path must not carry a UNKNOWN value.
      AIFC_CHECK_MSG(parsed.value() == aifc::SemanticClass::UNKNOWN,
                     "a refused label must leave the value at the default UNKNOWN rather than a "
                     "stronger class");
    }
  }

  // Every canonical name, spelled correctly, is still accepted: the refusal above is about
  // spelling, not about the vocabulary being closed.
  for (const std::string_view name : kBuiltinNames) {
    AIFC_CHECK_MSG(aifc::parse_semantic_class(name).ok(),
                   "canonical label \"" << name << "\" must be accepted");
  }
}

// ---------------------------------------------------------------------------
// Evidence sources
// ---------------------------------------------------------------------------

AIFC_TEST("domain/evidence: source rank, confidence constants and predicates (REAL)") {
  AIFC_CHECK_EQ(aifc::kEvidenceSourceCount, std::size_t{6});

  // The complete ordering, weakest first.  Written out so that a change to the ranking fails
  // here with a readable message rather than silently changing a decision.
  const aifc::EvidenceSource weakest_to_strongest[] = {
      aifc::EvidenceSource::UNKNOWN,
      aifc::EvidenceSource::HEURISTIC,
      aifc::EvidenceSource::TOPOLOGY_CORRELATED,
      aifc::EvidenceSource::COORDINATOR_CORRELATED,
      aifc::EvidenceSource::CONTRACT_DERIVED,
      aifc::EvidenceSource::DECLARED_AUTHENTICATED,
  };
  const std::uint8_t expected_ranks[] = {0U, 1U, 2U, 3U, 4U, 5U};
  const std::uint32_t expected_confidence[] = {0U, 2000U, 5000U, 7000U, 8000U, 9000U};
  for (std::size_t index = 0; index < 6U; ++index) {
    const aifc::EvidenceSource source = weakest_to_strongest[index];
    AIFC_CHECK_MSG(aifc::source_rank(source) == expected_ranks[index],
                   "source " << aifc::to_string(source) << " has rank "
                             << static_cast<unsigned>(aifc::source_rank(source))
                             << " but the documented rank is "
                             << static_cast<unsigned>(expected_ranks[index]));
    AIFC_CHECK_MSG(aifc::source_confidence(source).basis_points() == expected_confidence[index],
                   "source " << aifc::to_string(source) << " justifies "
                             << aifc::source_confidence(source).basis_points()
                             << " basis points but the constant is " << expected_confidence[index]);
    if (index > 0U) {
      AIFC_CHECK_MSG(aifc::source_rank(weakest_to_strongest[index - 1U]) <
                         aifc::source_rank(source),
                     "source ranks are not strictly increasing at index " << index);
    }
  }
  // Every source has a distinct rank, so precedence never has a tie to break.
  AIFC_CHECK_EQ(aifc::source_rank(aifc::EvidenceSource::UNKNOWN), 0U);
  AIFC_CHECK_EQ(aifc::source_rank(static_cast<aifc::EvidenceSource>(200U)), 0U);
  AIFC_CHECK_EQ(aifc::source_confidence(static_cast<aifc::EvidenceSource>(200U)).basis_points(), 0U);
  AIFC_CHECK_EQ(aifc::to_string(static_cast<aifc::EvidenceSource>(200U)), std::string_view("UNRECOGNIZED_SOURCE"));

  // The canonical names.
  const std::string_view names[] = {"UNKNOWN",      "DECLARED_AUTHENTICATED",
                                    "CONTRACT_DERIVED", "COORDINATOR_CORRELATED",
                                    "TOPOLOGY_CORRELATED", "HEURISTIC"};
  for (const std::string_view name : names) {
    const auto parsed = aifc::parse_evidence_source(name);
    AIFC_CHECK_MSG(parsed.ok(), "parse_evidence_source(\"" << name << "\") failed: "
                                                           << status_text(parsed.status()));
    if (parsed.ok()) {
      AIFC_CHECK_MSG(aifc::to_string(parsed.value()) == name,
                     "round trip of source \"" << name << "\" produced \""
                                               << aifc::to_string(parsed.value()) << "\"");
    }
  }
  AIFC_CHECK_ERR(aifc::parse_evidence_source("declared_authenticated"),
                 aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_evidence_source("TRUSTED"), aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK_ERR(aifc::parse_evidence_source(""), aifc::ErrorCode::MALFORMED_INPUT);

  // Authoritative means "may participate in a contradiction".  Only a declaration and a
  // contract-derived statement qualify; a heuristic guess disagreeing is a guess that lost.
  AIFC_CHECK(aifc::source_is_authoritative(aifc::EvidenceSource::DECLARED_AUTHENTICATED));
  AIFC_CHECK(aifc::source_is_authoritative(aifc::EvidenceSource::CONTRACT_DERIVED));
  AIFC_CHECK(!aifc::source_is_authoritative(aifc::EvidenceSource::COORDINATOR_CORRELATED));
  AIFC_CHECK(!aifc::source_is_authoritative(aifc::EvidenceSource::TOPOLOGY_CORRELATED));
  AIFC_CHECK(!aifc::source_is_authoritative(aifc::EvidenceSource::HEURISTIC));
  AIFC_CHECK(!aifc::source_is_authoritative(aifc::EvidenceSource::UNKNOWN));

  AIFC_CHECK(aifc::source_is_heuristic(aifc::EvidenceSource::HEURISTIC));
  for (std::size_t index = 0; index < 6U; ++index) {
    if (weakest_to_strongest[index] != aifc::EvidenceSource::HEURISTIC) {
      AIFC_CHECK_MSG(!aifc::source_is_heuristic(weakest_to_strongest[index]),
                     "source " << aifc::to_string(weakest_to_strongest[index])
                               << " must not be classified as heuristic");
    }
  }

  // Liveness dependency: an observation made *by* a session loses currentness with it; a
  // contract-derived statement is not an observation and does not.
  AIFC_CHECK(aifc::source_requires_live_session(aifc::EvidenceSource::DECLARED_AUTHENTICATED));
  AIFC_CHECK(aifc::source_requires_live_session(aifc::EvidenceSource::COORDINATOR_CORRELATED));
  AIFC_CHECK(aifc::source_requires_live_session(aifc::EvidenceSource::TOPOLOGY_CORRELATED));
  AIFC_CHECK(!aifc::source_requires_live_session(aifc::EvidenceSource::CONTRACT_DERIVED));
  AIFC_CHECK(!aifc::source_requires_live_session(aifc::EvidenceSource::HEURISTIC));
  AIFC_CHECK(!aifc::source_requires_live_session(aifc::EvidenceSource::UNKNOWN));

  // Evidence states and their canonical names.
  const std::string_view state_names[] = {"NONE",    "CURRENT",      "STALE", "SUPERSEDED",
                                          "REVOKED", "INSUFFICIENT", "REJECTED"};
  for (const std::string_view name : state_names) {
    const auto parsed = aifc::parse_evidence_state(name);
    AIFC_CHECK_MSG(parsed.ok(), "parse_evidence_state(\"" << name << "\") failed: "
                                                          << status_text(parsed.status()));
    if (parsed.ok()) {
      AIFC_CHECK_MSG(aifc::to_string(parsed.value()) == name,
                     "round trip of state \"" << name << "\" produced \""
                                              << aifc::to_string(parsed.value()) << "\"");
    }
  }
  AIFC_CHECK_ERR(aifc::parse_evidence_state("current"), aifc::ErrorCode::MALFORMED_INPUT);
  AIFC_CHECK(aifc::state_carries_authority(aifc::EvidenceState::EVIDENCE_CURRENT));
  AIFC_CHECK(!aifc::state_carries_authority(aifc::EvidenceState::EVIDENCE_STALE));
  AIFC_CHECK(!aifc::state_carries_authority(aifc::EvidenceState::EVIDENCE_SUPERSEDED));
}

AIFC_TEST("domain/evidence: decoding an unknown source code is never stronger than UNKNOWN (REAL)") {
  // Codes 0..5 are the defined sources; anything else must be UNKNOWN, and the result must be
  // ok() because "this build does not know that code" is a value, not a parse failure.
  const aifc::EvidenceSource expected[] = {
      aifc::EvidenceSource::UNKNOWN,
      aifc::EvidenceSource::DECLARED_AUTHENTICATED,
      aifc::EvidenceSource::CONTRACT_DERIVED,
      aifc::EvidenceSource::COORDINATOR_CORRELATED,
      aifc::EvidenceSource::TOPOLOGY_CORRELATED,
      aifc::EvidenceSource::HEURISTIC,
  };
  for (std::uint32_t code = 0; code < 6U; ++code) {
    const auto decoded = aifc::decode_evidence_source(code);
    AIFC_CHECK_MSG(decoded.ok(), "decode_evidence_source(" << code << ") must succeed");
    if (decoded.ok()) {
      AIFC_CHECK_MSG(decoded.value() == expected[code],
                     "decode_evidence_source(" << code << ") produced "
                                               << aifc::to_string(decoded.value()) << " instead of "
                                               << aifc::to_string(expected[code]));
    }
  }

  // Every other code, including the ones that would be "stronger" if a code were mapped by
  // raw numeric order.
  std::vector<std::uint32_t> unknown_codes;
  for (std::uint32_t code = 6U; code < 300U; ++code) unknown_codes.push_back(code);
  unknown_codes.push_back(1000U);
  unknown_codes.push_back(0x7FFFFFFFU);
  unknown_codes.push_back(0xFFFFFFFFU);
  for (const std::uint32_t code : unknown_codes) {
    const auto decoded = aifc::decode_evidence_source(code);
    AIFC_CHECK_MSG(decoded.ok(), "decode_evidence_source(" << code << ") must succeed");
    if (decoded.ok()) {
      AIFC_CHECK_MSG(decoded.value() == aifc::EvidenceSource::UNKNOWN,
                     "decode_evidence_source(" << code << ") produced \""
                                               << aifc::to_string(decoded.value())
                                               << "\" instead of UNKNOWN");
      AIFC_CHECK_MSG(!aifc::source_is_authoritative(decoded.value()),
                     "an unknown source code must never decode to an authoritative source; code "
                         << code << " produced " << aifc::to_string(decoded.value()));
      AIFC_CHECK_MSG(aifc::source_confidence(decoded.value()).is_zero(),
                     "an unknown source code must never carry confidence; code "
                         << code << " produced "
                         << aifc::source_confidence(decoded.value()).basis_points());
    }
  }
}

// ---------------------------------------------------------------------------
// Addresses and flow keys
// ---------------------------------------------------------------------------

AIFC_TEST("domain/flow_key: v4-mapped rendering, v6 compression and one key per address (REAL)") {
  // REAL: this is the shipped renderer, not a platform inet_ntop.
  const aifc::IpAddress loopback = aifc::IpAddress::from_v4(0x7F000001U);
  AIFC_CHECK(loopback.is_v4_mapped());
  AIFC_CHECK_EQ(loopback.to_string(), std::string("127.0.0.1"));
  AIFC_CHECK(!loopback.is_zero());

  const aifc::IpAddress zero_v4 = aifc::IpAddress::from_v4(0x00000000U);
  AIFC_CHECK(zero_v4.is_v4_mapped());
  AIFC_CHECK_EQ(zero_v4.to_string(), std::string("0.0.0.0"));
  AIFC_CHECK_EQ(aifc::IpAddress::from_v4(0xFFFFFFFFU).to_string(), std::string("255.255.255.255"));
  AIFC_CHECK_EQ(aifc::IpAddress::from_v4(0xC0A80101U).to_string(), std::string("192.168.1.1"));

  const auto v6 = [](std::uint16_t a, std::uint16_t b, std::uint16_t c, std::uint16_t d,
                     std::uint16_t e, std::uint16_t f, std::uint16_t g, std::uint16_t h) {
    std::array<std::uint8_t, 16> raw{};
    const std::uint16_t groups[8] = {a, b, c, d, e, f, g, h};
    for (std::size_t i = 0; i < 8U; ++i) {
      raw[i * 2U] = static_cast<std::uint8_t>((groups[i] >> 8) & 0xFFU);
      raw[i * 2U + 1U] = static_cast<std::uint8_t>(groups[i] & 0xFFU);
    }
    return aifc::IpAddress::from_v6(raw);
  };

  AIFC_CHECK_EQ(v6(0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U).to_string(), std::string("::"));
  AIFC_CHECK_EQ(v6(0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U).to_string(), std::string("::1"));
  AIFC_CHECK_EQ(v6(0x2001U, 0x0DB8U, 0U, 0U, 0U, 0U, 0U, 1U).to_string(),
                std::string("2001:db8::1"));
  AIFC_CHECK_EQ(v6(0xFE80U, 0U, 0U, 0U, 0U, 0U, 0U, 0U).to_string(), std::string("fe80::"));
  AIFC_CHECK_EQ(v6(0x2001U, 0x0DB8U, 0U, 0U, 0U, 0xFF00U, 0x0042U, 0x8329U).to_string(),
                std::string("2001:db8::ff00:42:8329"));
  // A single zero group is not compressed (RFC 5952 keeps the colon form for a run of one).
  AIFC_CHECK_EQ(v6(0x2001U, 0x0DB8U, 0U, 1U, 1U, 1U, 1U, 1U).to_string(),
                std::string("2001:db8:0:1:1:1:1:1"));
  AIFC_CHECK_EQ(v6(0x2001U, 0x0DB8U, 1U, 2U, 3U, 4U, 5U, 6U).to_string(),
                std::string("2001:db8:1:2:3:4:5:6"));
  // The longest run wins when there are two candidates.
  AIFC_CHECK_EQ(v6(0x2001U, 0U, 0U, 1U, 0U, 0U, 0U, 0U).to_string(),
                std::string("2001:0:0:1::"));
  // Leading zeros inside a group are dropped but the group is never empty.
  AIFC_CHECK_EQ(v6(0x0001U, 0x0002U, 0x0003U, 0x0004U, 0x0005U, 0x0006U, 0x0007U, 0x0008U)
                    .to_string(),
                std::string("1:2:3:4:5:6:7:8"));
  AIFC_CHECK(!v6(0x2001U, 0x0DB8U, 0U, 0U, 0U, 0U, 0U, 1U).is_v4_mapped());
  AIFC_CHECK(!v6(0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U).is_v4_mapped());

  // Two spellings of one address must not create two keys.  The two construction routes are
  // the v4 route and the raw 16 byte route; there is no textual IPv6 parser in this build
  // (UNSUPPORTED), so those are the only two spellings that exist.
  const std::uint32_t host_order = 0x0A0B0C0DU;
  const aifc::IpAddress from_v4_route = aifc::IpAddress::from_v4(host_order);
  const aifc::IpAddress from_bytes_route = aifc::IpAddress::from_bytes(from_v4_route.bytes);
  const aifc::IpAddress from_v6_route = aifc::IpAddress::from_v6(from_v4_route.bytes);
  AIFC_CHECK(from_v4_route == from_bytes_route);
  AIFC_CHECK(from_v4_route == from_v6_route);
  AIFC_CHECK_EQ(from_v4_route.to_string(), from_v6_route.to_string());

  aifc::FlowKey first;
  first.local_address = aifc::IpAddress::from_v4(0x7F000001U);
  first.remote_address = from_v4_route;
  first.local_port = 40000U;
  first.remote_port = 2049U;
  first.transport = aifc::TransportProtocol::TCP;

  aifc::FlowKey second = first;
  second.remote_address = from_v6_route;  // the other spelling of the same address

  AIFC_CHECK(first == second);
  AIFC_CHECK(!(first < second));
  AIFC_CHECK(!(second < first));
  AIFC_CHECK_EQ(std::hash<aifc::FlowKey>{}(first), std::hash<aifc::FlowKey>{}(second));
  AIFC_CHECK_EQ(aifc::derive_flow_id(first).to_hex(), aifc::derive_flow_id(second).to_hex());

  std::unordered_set<aifc::FlowKey> keys;
  keys.insert(first);
  keys.insert(second);
  AIFC_CHECK_MSG(keys.size() == 1U,
                 "two spellings of one address produced " << keys.size() << " distinct flow keys");

  // The key rendering is stable and names the transport.
  AIFC_CHECK_EQ(first.to_string(), std::string("TCP 127.0.0.1:40000 -> 10.11.12.13:2049"));
  AIFC_CHECK_EQ(aifc::to_string(aifc::TransportProtocol::RDMA), std::string_view("RDMA"));
  const auto transport = aifc::parse_transport_protocol("SCTP");
  AIFC_CHECK_OK(transport);
  AIFC_CHECK(transport.value() == aifc::TransportProtocol::SCTP);
  AIFC_CHECK_ERR(aifc::parse_transport_protocol("tcp"), aifc::ErrorCode::MALFORMED_INPUT);
  const auto decoded_transport = aifc::decode_transport_protocol(99U);
  AIFC_CHECK_OK(decoded_transport);
  AIFC_CHECK_MSG(decoded_transport.value() == aifc::TransportProtocol::UNKNOWN,
                 "an unknown transport code must decode to UNKNOWN rather than defaulting to TCP");
}

AIFC_TEST("domain/flow_key: derive_flow_id is injective and stable (REAL)") {
  // Stability: the identity is a pure function of the canonical key, so two independent
  // callers (two processes, or two calls) agree.
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(7U);
  const aifc::Id128 first = aifc::derive_flow_id(key);
  const aifc::Id128 second = aifc::derive_flow_id(key);
  AIFC_CHECK_EQ(first.to_hex(), second.to_hex());
  AIFC_CHECK(!first.is_zero());
  AIFC_CHECK_EQ(aifc::derive_flow_id(aifc_test::synthetic_flow_key(7U)).to_hex(), first.to_hex());
  AIFC_CHECK_NE(aifc::derive_flow_id(aifc_test::synthetic_flow_key(8U)).to_hex(), first.to_hex());

  // Injectivity over distinct keys: every one of a large synthetic set maps to a distinct
  // identity.  Each key differs from its neighbour in exactly one field, so a derivation that
  // ignored a field would collide immediately.
  std::unordered_set<std::string> ids;
  std::size_t produced = 0;
  for (std::uint32_t index = 0; index < 512U; ++index) {
    const aifc::FlowKey candidate = aifc_test::synthetic_flow_key(index);
    const std::string hex = aifc::derive_flow_id(candidate).to_hex();
    AIFC_CHECK_MSG(ids.insert(hex).second,
                   "derive_flow_id collided at index " << index << " on key \""
                                                       << candidate.to_string() << "\" ("
                                                       << hex << ")");
    ++produced;
  }
  AIFC_CHECK_EQ(produced, std::size_t{512});
  AIFC_CHECK_EQ(ids.size(), produced);

  // Each component participates: changing exactly one field changes the identity.
  const aifc::FlowKey base = aifc_test::synthetic_flow_key(3U);
  const std::string base_hex = aifc::derive_flow_id(base).to_hex();
  struct Variant {
    const char* what;
    aifc::FlowKey key;
  };
  aifc::FlowKey other_transport = base;
  other_transport.transport = aifc::TransportProtocol::UDP;
  aifc::FlowKey other_local_port = base;
  other_local_port.local_port = static_cast<std::uint16_t>(base.local_port + 1U);
  aifc::FlowKey other_remote_port = base;
  other_remote_port.remote_port = static_cast<std::uint16_t>(base.remote_port + 1U);
  aifc::FlowKey other_local_address = base;
  other_local_address.local_address = aifc::IpAddress::from_v4(0x7F000002U);
  aifc::FlowKey other_remote_address = base;
  other_remote_address.remote_address =
      aifc::IpAddress::from_v4(0x7F00FFFFU);
  const Variant variants[] = {
      {"transport", other_transport},
      {"local_port", other_local_port},
      {"remote_port", other_remote_port},
      {"local_address", other_local_address},
      {"remote_address", other_remote_address},
  };
  for (const Variant& variant : variants) {
    AIFC_CHECK_MSG(variant.key != base, "the " << variant.what << " variant must differ from the base key");
    AIFC_CHECK_MSG(aifc::derive_flow_id(variant.key).to_hex() != base_hex,
                   "changing the " << variant.what << " of key \"" << base.to_string()
                                   << "\" did not change the derived identity " << base_hex);
  }

  // The hash used by the registry never disagrees with equality on these keys.
  for (std::uint32_t index = 0; index < 256U; ++index) {
    const aifc::FlowKey left = aifc_test::synthetic_flow_key(index);
    const aifc::FlowKey right = aifc_test::synthetic_flow_key(index);
    AIFC_CHECK_MSG(left == right, "synthetic_flow_key(" << index << ") is not deterministic");
    AIFC_CHECK_MSG(std::hash<aifc::FlowKey>{}(left) == std::hash<aifc::FlowKey>{}(right),
                   "equal keys at index " << index << " hashed differently");
  }
}

// ---------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------

AIFC_TEST("domain/evidence: compute_evidence_digest sensitivity and insensitivity (REAL)") {
  const aifc::EvidenceRecord baseline = make_record(aifc::make_evidence_id("ev-0000000000000001"));
  const aifc::Digest256 baseline_digest = aifc::compute_evidence_digest(baseline);
  AIFC_CHECK(!baseline_digest.is_zero());
  AIFC_CHECK_EQ(aifc::compute_evidence_digest(baseline).to_hex(), baseline_digest.to_hex());

  // Every field that affects what the record *says* must change the digest.  A digest that
  // ignored one of these would make two different declarations look like a replay of one.
  struct Sensitive {
    const char* what;
    aifc::EvidenceRecord record;
  };
  aifc::EvidenceRecord id_changed = baseline;
  id_changed.id = aifc::make_evidence_id("ev-0000000000000002");
  aifc::EvidenceRecord publisher_changed = baseline;
  publisher_changed.publisher = aifc::make_publisher_id("publisher-2");
  aifc::EvidenceRecord boot_changed = baseline;
  boot_changed.publisher_boot = aifc::PublisherBootId{4};
  aifc::EvidenceRecord workload_changed = baseline;
  workload_changed.workload = aifc::make_workload_id("workload-2");
  aifc::EvidenceRecord workload_generation_changed = baseline;
  workload_generation_changed.workload_generation = aifc::WorkloadGeneration{5};
  aifc::EvidenceRecord contract_changed = baseline;
  contract_changed.contract = aifc::make_contract_id("contract-2");
  aifc::EvidenceRecord flow_hi_changed = baseline;
  flow_hi_changed.flow_id.hi += 1U;
  aifc::EvidenceRecord flow_lo_changed = baseline;
  flow_lo_changed.flow_id.lo += 1U;
  aifc::EvidenceRecord flow_generation_changed = baseline;
  flow_generation_changed.flow_generation = aifc::FlowGeneration{3};
  aifc::EvidenceRecord generation_changed = baseline;
  generation_changed.generation = aifc::EvidenceGeneration{6};
  aifc::EvidenceRecord semantic_changed = baseline;
  semantic_changed.semantic = aifc::SemanticClass::KV_STATE_TRANSFER;
  aifc::EvidenceRecord source_changed = baseline;
  source_changed.source = aifc::EvidenceSource::CONTRACT_DERIVED;
  aifc::EvidenceRecord confidence_changed = baseline;
  confidence_changed.confidence = aifc::Confidence::from_basis_points(8000U);
  aifc::EvidenceRecord topic_changed = baseline;
  topic_changed.metadata.topic = "workload.rank.8.collective";
  aifc::EvidenceRecord binding_changed = baseline;
  binding_changed.metadata.binding = 43;
  aifc::EvidenceRecord reason_changed = baseline;
  reason_changed.metadata.reason = "another reason";
  aifc::EvidenceRecord metadata_contract_changed = baseline;
  metadata_contract_changed.metadata.contract = aifc::make_contract_id("contract-2");
  aifc::EvidenceRecord freshness_changed = baseline;
  freshness_changed.fresh_until = 9999;

  const Sensitive sensitive[] = {
      {"id", id_changed},
      {"publisher", publisher_changed},
      {"publisher_boot", boot_changed},
      {"workload", workload_changed},
      {"workload_generation", workload_generation_changed},
      {"contract", contract_changed},
      {"flow_id.hi", flow_hi_changed},
      {"flow_id.lo", flow_lo_changed},
      {"flow_generation", flow_generation_changed},
      {"generation", generation_changed},
      {"semantic", semantic_changed},
      {"source", source_changed},
      {"confidence", confidence_changed},
      {"metadata.topic", topic_changed},
      {"metadata.binding", binding_changed},
      {"metadata.reason", reason_changed},
      {"metadata.contract", metadata_contract_changed},
      {"fresh_until", freshness_changed},
  };
  for (const Sensitive& entry : sensitive) {
    const aifc::Digest256 digest = aifc::compute_evidence_digest(entry.record);
    AIFC_CHECK_MSG(digest != baseline_digest,
                   "changing " << entry.what
                               << " did not change the evidence content digest " << baseline_digest.to_hex());
  }

  // The acceptance bookkeeping describes where the record sits, not what it says, so it must
  // not change the digest.  This is what makes a replay of the same publication detectable as
  // "the same record" rather than as "a different record".
  aifc::EvidenceRecord bookkeeping = baseline;
  bookkeeping.accepted_seq = 999999;
  bookkeeping.accepted_tick = 123456;
  bookkeeping.state = aifc::EvidenceState::EVIDENCE_STALE;
  bookkeeping.state_reason = "a completely different reason";
  bookkeeping.session = aifc::SessionId("session-99");
  bookkeeping.accepted_epoch = aifc::CoordinatorEpoch{77};
  bookkeeping.accepted_boot = aifc::CoordinatorBootId{88};
  AIFC_CHECK_MSG(aifc::compute_evidence_digest(bookkeeping) == baseline_digest,
                 "acceptance bookkeeping changed the evidence digest: "
                     << aifc::compute_evidence_digest(bookkeeping).to_hex() << " != "
                     << baseline_digest.to_hex());
}

AIFC_TEST("domain: contract and policy digests cover content and not declaration order (REAL)") {
  const aifc::WorkloadContract baseline = make_contract();
  const aifc::Digest256 baseline_digest = aifc::compute_contract_digest(baseline);
  AIFC_CHECK(!baseline_digest.is_zero());
  AIFC_CHECK_EQ(aifc::compute_contract_digest(baseline).to_hex(), baseline_digest.to_hex());

  aifc::WorkloadContract class_changed = baseline;
  class_changed.declared_class = aifc::SemanticClass::COLLECTIVE;
  aifc::WorkloadContract port_changed = baseline;
  port_changed.remote_port = 2050;
  aifc::WorkloadContract transport_changed = baseline;
  transport_changed.transport = aifc::TransportProtocol::UDP;
  aifc::WorkloadContract any_remote_changed = baseline;
  any_remote_changed.match_any_remote_address = false;
  aifc::WorkloadContract source_changed = baseline;
  source_changed.derived_source = aifc::EvidenceSource::TOPOLOGY_CORRELATED;
  aifc::WorkloadContract description_changed = baseline;
  description_changed.description = "another description";
  aifc::WorkloadContract id_changed = baseline;
  id_changed.id = aifc::make_contract_id("contract-2");
  aifc::WorkloadContract workload_changed = baseline;
  workload_changed.workload = aifc::make_workload_id("workload-2");
  aifc::WorkloadContract workload_generation_changed = baseline;
  workload_generation_changed.workload_generation = aifc::WorkloadGeneration{9};
  aifc::WorkloadContract owner_changed = baseline;
  owner_changed.owner = aifc::make_publisher_id("publisher-2");
  aifc::WorkloadContract scope_changed = baseline;
  scope_changed.remote_scope.push_back(aifc::IpAddress::from_v4(0x0A0B0C0DU));
  aifc::WorkloadContract local_port_scope_changed = baseline;
  local_port_scope_changed.local_port_scope.push_back(40000U);

  struct ContractMutation {
    const char* what;
    aifc::WorkloadContract contract;
  };
  const ContractMutation mutations[] = {
      {"declared_class", class_changed},
      {"remote_port", port_changed},
      {"transport", transport_changed},
      {"match_any_remote_address", any_remote_changed},
      {"derived_source", source_changed},
      {"description", description_changed},
      {"id", id_changed},
      {"workload", workload_changed},
      {"workload_generation", workload_generation_changed},
      {"owner", owner_changed},
      {"remote_scope", scope_changed},
      {"local_port_scope", local_port_scope_changed},
  };
  for (const ContractMutation& mutation : mutations) {
    AIFC_CHECK_MSG(aifc::compute_contract_digest(mutation.contract) != baseline_digest,
                   "changing the contract " << mutation.what
                                            << " did not change its definition digest");
  }

  // Lifecycle position is not content.
  aifc::WorkloadContract lifecycle = baseline;
  lifecycle.state = aifc::ContractState::RETIRED;
  lifecycle.created_tick = 11;
  lifecycle.activated_tick = 22;
  lifecycle.retired_tick = 33;
  lifecycle.definition_digest = aifc::Digest256{};  // the digest of the definition, not content
  AIFC_CHECK_MSG(aifc::compute_contract_digest(lifecycle) == baseline_digest,
                 "contract lifecycle fields changed the definition digest");

  // Policy digest: the generation is excluded, content is included, and declaration order is
  // not content.
  aifc::ClassifierPolicy forward = make_policy_with_adapters(false);
  aifc::ClassifierPolicy reversed = make_policy_with_adapters(true);
  const auto canonical_forward = aifc::ClassifierPolicy::canonicalize(forward);
  const auto canonical_reversed = aifc::ClassifierPolicy::canonicalize(reversed);
  AIFC_CHECK_OK(canonical_forward);
  AIFC_CHECK_OK(canonical_reversed);
  if (canonical_forward && canonical_reversed) {
    AIFC_CHECK_MSG(aifc::compute_policy_digest(canonical_forward.value()) ==
                       aifc::compute_policy_digest(canonical_reversed.value()),
                   "two policies that differ only in declaration order have different digests");
    // The fixture declares three adapters so that every declared hint can name a real one; a hint that
  // names an undeclared adapter is refused by canonicalize rather than accepted as inert configuration.
  AIFC_CHECK_EQ(canonical_forward.value().heuristic_adapters.size(), std::size_t{3});
    if (canonical_forward.value().heuristic_adapters.size() == 2U) {
      AIFC_CHECK_EQ(canonical_forward.value().heuristic_adapters[0].name, std::string("adapter-alpha"));
      AIFC_CHECK_EQ(canonical_forward.value().heuristic_adapters[1].name, std::string("adapter-beta"));
    }
  }

  aifc::ClassifierPolicy generation_only = make_policy_with_adapters(false);
  generation_only.generation = aifc::ClassifierPolicyGeneration{99};
  AIFC_CHECK_MSG(aifc::compute_policy_digest(generation_only) ==
                     aifc::compute_policy_digest(forward),
                 "the policy generation must not participate in the policy digest");

  aifc::ClassifierPolicy content_changed = make_policy_with_adapters(false);
  content_changed.contradiction_penalty = 1234U;
  AIFC_CHECK_MSG(aifc::compute_policy_digest(content_changed) !=
                     aifc::compute_policy_digest(forward),
                 "changing contradiction_penalty did not change the policy digest");
  aifc::ClassifierPolicy limits_changed = make_policy_with_adapters(false);
  limits_changed.limits.max_flows = 7U;
  AIFC_CHECK_MSG(aifc::compute_policy_digest(limits_changed) !=
                     aifc::compute_policy_digest(forward),
                 "changing a resource limit did not change the policy digest");
  aifc::ClassifierPolicy threshold_changed = make_policy_with_adapters(false);
  threshold_changed.minimum_publishable_confidence = 2500U;
  AIFC_CHECK_MSG(aifc::compute_policy_digest(threshold_changed) !=
                     aifc::compute_policy_digest(forward),
                 "changing the publishable threshold did not change the policy digest");
}

AIFC_TEST("domain/workload: contract_covers scope matching (REAL)") {
  const aifc::FlowKey key = aifc_test::synthetic_flow_key(11U);  // TCP, ports 40011 / 20011

  aifc::WorkloadContract contract = make_contract();
  contract.transport = aifc::TransportProtocol::UNKNOWN;
  contract.remote_port = 0;
  contract.match_any_remote_address = true;
  contract.remote_scope.clear();
  contract.local_port_scope.clear();
  AIFC_CHECK_MSG(aifc::contract_covers(contract, key),
                 "an unconstrained scope must cover \"" << key.to_string() << "\"");

  // Transport: UNKNOWN means "any"; a concrete mismatch excludes.
  contract.transport = aifc::TransportProtocol::TCP;
  AIFC_CHECK(aifc::contract_covers(contract, key));
  contract.transport = aifc::TransportProtocol::UDP;
  AIFC_CHECK(!aifc::contract_covers(contract, key));
  contract.transport = aifc::TransportProtocol::RDMA;
  AIFC_CHECK(!aifc::contract_covers(contract, key));

  // Remote port: zero means "any"; a concrete mismatch excludes.
  contract.transport = aifc::TransportProtocol::UNKNOWN;
  contract.remote_port = key.remote_port;
  AIFC_CHECK(aifc::contract_covers(contract, key));
  contract.remote_port = static_cast<std::uint16_t>(key.remote_port + 1U);
  AIFC_CHECK_MSG(!aifc::contract_covers(contract, key),
                 "remote_port " << contract.remote_port << " must not cover a key whose remote port is "
                                << key.remote_port);
  contract.remote_port = 0;

  // Remote address set: used only when match_any_remote_address is false.
  contract.match_any_remote_address = false;
  contract.remote_scope.clear();
  AIFC_CHECK_MSG(!aifc::contract_covers(contract, key),
                 "an empty address scope with match_any_remote_address=false covers nothing");
  contract.remote_scope.push_back(aifc::IpAddress::from_v4(0x0A0B0C0DU));
  AIFC_CHECK(!aifc::contract_covers(contract, key));
  contract.remote_scope.push_back(key.remote_address);
  AIFC_CHECK(aifc::contract_covers(contract, key));
  contract.match_any_remote_address = true;
  contract.remote_scope.clear();
  AIFC_CHECK(aifc::contract_covers(contract, key));

  // Local port set: empty means "any"; a non-empty set must contain the local port.
  contract.local_port_scope.clear();
  AIFC_CHECK(aifc::contract_covers(contract, key));
  contract.local_port_scope.push_back(key.local_port);
  AIFC_CHECK(aifc::contract_covers(contract, key));
  contract.local_port_scope[0] = static_cast<std::uint16_t>(key.local_port + 1U);
  AIFC_CHECK_MSG(!aifc::contract_covers(contract, key),
                 "a local port scope that excludes " << key.local_port << " must not cover the key");
  contract.local_port_scope.push_back(key.local_port);
  AIFC_CHECK(aifc::contract_covers(contract, key));

  // A completely constrained contract covers exactly the flow it names and nothing else.
  aifc::WorkloadContract narrow = make_contract();
  narrow.transport = key.transport;
  narrow.remote_port = key.remote_port;
  narrow.match_any_remote_address = false;
  narrow.remote_scope = {key.remote_address};
  narrow.local_port_scope = {key.local_port};
  AIFC_CHECK(aifc::contract_covers(narrow, key));
  aifc::FlowKey neighbour = key;
  neighbour.remote_port = static_cast<std::uint16_t>(key.remote_port + 1U);
  AIFC_CHECK(!aifc::contract_covers(narrow, neighbour));
  neighbour = key;
  neighbour.local_port = static_cast<std::uint16_t>(key.local_port + 1U);
  AIFC_CHECK(!aifc::contract_covers(narrow, neighbour));
  neighbour = key;
  neighbour.remote_address = aifc::IpAddress::from_v4(0x7F00FFFEU);
  AIFC_CHECK(!aifc::contract_covers(narrow, neighbour));
  neighbour = key;
  neighbour.transport = aifc::TransportProtocol::UDP;
  AIFC_CHECK(!aifc::contract_covers(narrow, neighbour));
}
