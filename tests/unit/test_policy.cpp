// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Unit proof surface: classifier policy construction, canonicalisation and digests.
//
// A policy is the complete description of how a decision is reached, so a policy that says
// two contradictory things must be refused rather than silently neutralised.  Every refusal
// below names the case, the expected code and the code that was actually produced.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "test_framework.hpp"

#include "ai_flow_classifier/domain/policy.hpp"

namespace {

[[nodiscard]] std::string status_text(const aifc::Status& status) {
  return std::string(aifc::to_string(status.code)) + " (" + status.message + ")";
}

[[nodiscard]] aifc::HeuristicAdapterPolicy adapter(std::string name, bool enabled,
                                                   std::uint32_t max_basis_points,
                                                   std::uint32_t priority) {
  aifc::HeuristicAdapterPolicy policy;
  policy.name = std::move(name);
  policy.enabled = enabled;
  policy.max_basis_points = max_basis_points;
  policy.priority = priority;
  return policy;
}

[[nodiscard]] aifc::PortHint hint(aifc::TransportProtocol transport, std::uint16_t port,
                                  aifc::SemanticClass semantic, std::uint32_t basis_points,
                                  std::string adapter_name) {
  aifc::PortHint port_hint;
  port_hint.transport = transport;
  port_hint.port = port;
  port_hint.semantic = semantic;
  port_hint.basis_points = basis_points;
  port_hint.adapter = std::move(adapter_name);
  return port_hint;
}

// A policy with heuristics enabled and two adapters plus two hints.
[[nodiscard]] aifc::ClassifierPolicy valid_policy(bool reversed_order) {
  aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  policy.allow_heuristic_evidence = true;
  policy.contradiction_penalty = 1500U;
  policy.minimum_publishable_confidence = 1200U;
  policy.max_evidence_considered = 8U;
  policy.default_freshness_window = 2048U;
  const aifc::HeuristicAdapterPolicy alpha = adapter("adapter-alpha", true, 1500U, 2U);
  const aifc::HeuristicAdapterPolicy beta = adapter("adapter-beta", false, 900U, 1U);
  const aifc::PortHint tcp_hint =
      hint(aifc::TransportProtocol::TCP, 2049U, aifc::SemanticClass::STORAGE_DATA, 800U, "adapter-beta");
  const aifc::PortHint udp_hint =
      hint(aifc::TransportProtocol::UDP, 4791U, aifc::SemanticClass::TELEMETRY, 300U, "adapter-alpha");
  if (reversed_order) {
    policy.heuristic_adapters = {beta, alpha};
    policy.port_hints = {udp_hint, tcp_hint};
  } else {
    policy.heuristic_adapters = {alpha, beta};
    policy.port_hints = {tcp_hint, udp_hint};
  }
  return policy;
}

}  // namespace

AIFC_TEST("policy/initial: documented defaults and the heuristic gate (REAL)") {
  const aifc::ClassifierPolicy policy = aifc::ClassifierPolicy::initial();
  AIFC_CHECK_EQ(policy.generation.value, 1U);
  AIFC_CHECK(policy.generation.valid());
  AIFC_CHECK_EQ(policy.allow_heuristic_evidence, false);
  AIFC_CHECK_EQ(policy.default_freshness_window, policy.limits.default_freshness_window);
  AIFC_CHECK_EQ(policy.default_freshness_window, 4096U);
  AIFC_CHECK_EQ(policy.contradiction_penalty, 2000U);
  AIFC_CHECK_EQ(policy.minimum_publishable_confidence, 1000U);
  AIFC_CHECK_EQ(policy.max_evidence_considered, 32U);
  AIFC_CHECK(policy.heuristic_adapters.empty());
  AIFC_CHECK(policy.port_hints.empty());

  // Heuristics are gated three times; the initial policy closes the first gate, so no adapter
  // name is enabled even if one were declared.
  AIFC_CHECK(!policy.heuristic_enabled("adapter-alpha"));
  AIFC_CHECK(!policy.heuristic_enabled(""));

  // The initial policy is already canonical, and canonicalising it does not change its digest.
  const auto canonical = aifc::ClassifierPolicy::canonicalize(policy);
  AIFC_CHECK_OK(canonical);
  if (canonical) {
    AIFC_CHECK_EQ(aifc::compute_policy_digest(canonical.value()).to_hex(),
                  aifc::compute_policy_digest(policy).to_hex());
    AIFC_CHECK_EQ(canonical.value().generation.value, 1U);
  }
}

AIFC_TEST("policy/canonicalize: a valid policy is accepted and normalised (REAL)") {
  aifc::ClassifierPolicy policy = valid_policy(false);
  const auto canonical = aifc::ClassifierPolicy::canonicalize(policy);
  AIFC_CHECK_OK(canonical);
  if (!canonical) return;

  const aifc::ClassifierPolicy& value = canonical.value();
  AIFC_CHECK_EQ(value.heuristic_adapters.size(), std::size_t{2});
  AIFC_CHECK_EQ(value.port_hints.size(), std::size_t{2});
  // Sorted by the canonical key, which is what makes the digest order independent.
  if (value.heuristic_adapters.size() == 2U) {
    AIFC_CHECK_EQ(value.heuristic_adapters[0].name, std::string("adapter-alpha"));
    AIFC_CHECK_EQ(value.heuristic_adapters[1].name, std::string("adapter-beta"));
  }
  if (value.port_hints.size() == 2U) {
    AIFC_CHECK(value.port_hints[0].transport == aifc::TransportProtocol::TCP);
    AIFC_CHECK_EQ(value.port_hints[0].port, static_cast<std::uint16_t>(2049U));
    AIFC_CHECK(value.port_hints[1].transport == aifc::TransportProtocol::UDP);
    AIFC_CHECK_EQ(value.port_hints[1].port, static_cast<std::uint16_t>(4791U));
  }
  // Content other than order is preserved exactly.
  AIFC_CHECK_EQ(value.contradiction_penalty, 1500U);
  AIFC_CHECK_EQ(value.minimum_publishable_confidence, 1200U);
  AIFC_CHECK_EQ(value.max_evidence_considered, 8U);
  AIFC_CHECK_EQ(value.default_freshness_window, 2048U);
  AIFC_CHECK_EQ(value.allow_heuristic_evidence, true);
  // Limits are replaced by their effective form.
  const aifc::ResourceLimits effective = valid_policy(false).limits.effective();
  AIFC_CHECK_EQ(value.limits.max_flows, effective.max_flows);
  AIFC_CHECK_EQ(value.limits.max_frame_payload, effective.max_frame_payload);

  // The three-way heuristic gate: global switch, adapter switch, and the name.
  AIFC_CHECK(value.heuristic_enabled("adapter-alpha"));
  AIFC_CHECK(!value.heuristic_enabled("adapter-beta"));
  AIFC_CHECK(!value.heuristic_enabled("adapter-gamma"));
  AIFC_CHECK(!value.heuristic_enabled("ADAPTER-ALPHA"));

  // A policy that enables heuristics with no adapters is legal and enables nothing.
  aifc::ClassifierPolicy no_adapters = aifc::ClassifierPolicy::initial();
  no_adapters.allow_heuristic_evidence = true;
  const auto canonical_no_adapters = aifc::ClassifierPolicy::canonicalize(no_adapters);
  AIFC_CHECK_OK(canonical_no_adapters);
  if (canonical_no_adapters) {
    AIFC_CHECK(!canonical_no_adapters.value().heuristic_enabled("adapter-alpha"));
  }

  // Boundary values are accepted: a confidence of exactly 1.0 and a penalty of exactly 0.
  aifc::ClassifierPolicy boundary = aifc::ClassifierPolicy::initial();
  boundary.minimum_publishable_confidence = aifc::Confidence::kScale;
  boundary.contradiction_penalty = 0U;
  boundary.max_evidence_considered = 1U;
  boundary.default_freshness_window = 1U;
  AIFC_CHECK_OK(aifc::ClassifierPolicy::canonicalize(boundary));

  // The caller's copy is not modified by canonicalize taking its argument by value.
  AIFC_CHECK_EQ(policy.heuristic_adapters[0].name, std::string("adapter-alpha"));
  AIFC_CHECK_EQ(policy.port_hints[0].port, static_cast<std::uint16_t>(2049U));
}

AIFC_TEST("policy/canonicalize: contradictory and malformed policies are refused (REAL)") {
  struct Case {
    const char* what;
    aifc::ClassifierPolicy policy;
    aifc::ErrorCode expected;
  };

  aifc::ClassifierPolicy zero_freshness = aifc::ClassifierPolicy::initial();
  zero_freshness.default_freshness_window = 0U;

  aifc::ClassifierPolicy high_confidence = aifc::ClassifierPolicy::initial();
  high_confidence.minimum_publishable_confidence = 10001U;

  aifc::ClassifierPolicy high_penalty = aifc::ClassifierPolicy::initial();
  high_penalty.contradiction_penalty = 10001U;

  aifc::ClassifierPolicy zero_considered = aifc::ClassifierPolicy::initial();
  zero_considered.max_evidence_considered = 0U;

  aifc::ClassifierPolicy enabled_but_off = aifc::ClassifierPolicy::initial();
  enabled_but_off.allow_heuristic_evidence = false;
  enabled_but_off.heuristic_adapters = {adapter("adapter-alpha", true, 1000U, 0U)};

  aifc::ClassifierPolicy hints_but_off = aifc::ClassifierPolicy::initial();
  hints_but_off.allow_heuristic_evidence = false;
  hints_but_off.heuristic_adapters = {adapter("adapter-alpha", false, 1000U, 0U)};
  hints_but_off.port_hints = {
      hint(aifc::TransportProtocol::TCP, 2049U, aifc::SemanticClass::STORAGE_DATA, 500U, "adapter-alpha")};

  aifc::ClassifierPolicy duplicate_adapter = aifc::ClassifierPolicy::initial();
  duplicate_adapter.allow_heuristic_evidence = true;
  duplicate_adapter.heuristic_adapters = {adapter("adapter-alpha", true, 1000U, 0U),
                                          adapter("adapter-alpha", false, 500U, 1U)};

  aifc::ClassifierPolicy duplicate_hint = aifc::ClassifierPolicy::initial();
  duplicate_hint.allow_heuristic_evidence = true;
  // The adapters are declared so that this case is about the duplicate hint and nothing else: a hint
  // whose adapter is undeclared is refused on that ground first.
  duplicate_hint.heuristic_adapters = {adapter("a", true, 1000U, 0U), adapter("b", true, 1000U, 0U)};
  duplicate_hint.port_hints = {
      hint(aifc::TransportProtocol::TCP, 2049U, aifc::SemanticClass::STORAGE_DATA, 500U, "a"),
      hint(aifc::TransportProtocol::TCP, 2049U, aifc::SemanticClass::STORAGE_DATA, 400U, "b")};

  aifc::ClassifierPolicy uppercase_adapter = aifc::ClassifierPolicy::initial();
  uppercase_adapter.allow_heuristic_evidence = true;
  uppercase_adapter.heuristic_adapters = {adapter("Adapter-Alpha", true, 1000U, 0U)};

  aifc::ClassifierPolicy spaced_adapter = aifc::ClassifierPolicy::initial();
  spaced_adapter.allow_heuristic_evidence = true;
  spaced_adapter.heuristic_adapters = {adapter("adapter alpha", true, 1000U, 0U)};

  aifc::ClassifierPolicy empty_adapter = aifc::ClassifierPolicy::initial();
  empty_adapter.allow_heuristic_evidence = true;
  empty_adapter.heuristic_adapters = {adapter("", true, 1000U, 0U)};

  aifc::ClassifierPolicy adapter_too_confident = aifc::ClassifierPolicy::initial();
  adapter_too_confident.allow_heuristic_evidence = true;
  adapter_too_confident.heuristic_adapters = {adapter("adapter-alpha", true, 10001U, 0U)};

  aifc::ClassifierPolicy hint_too_confident = aifc::ClassifierPolicy::initial();
  hint_too_confident.allow_heuristic_evidence = true;
  hint_too_confident.heuristic_adapters = {adapter("a", true, 1000U, 0U)};
  hint_too_confident.port_hints = {
      hint(aifc::TransportProtocol::TCP, 2049U, aifc::SemanticClass::STORAGE_DATA, 10001U, "a")};

  const Case cases[] = {
      {"default_freshness_window == 0", zero_freshness, aifc::ErrorCode::INVALID_ARGUMENT},
      {"minimum_publishable_confidence > 1.0", high_confidence, aifc::ErrorCode::INVALID_ARGUMENT},
      {"contradiction_penalty > 1.0", high_penalty, aifc::ErrorCode::INVALID_ARGUMENT},
      {"max_evidence_considered == 0", zero_considered, aifc::ErrorCode::INVALID_ARGUMENT},
      {"enabled adapter while allow_heuristic_evidence is false", enabled_but_off,
       aifc::ErrorCode::INVALID_ARGUMENT},
      {"port hints while allow_heuristic_evidence is false", hints_but_off,
       aifc::ErrorCode::INVALID_ARGUMENT},
      {"duplicate adapter name", duplicate_adapter, aifc::ErrorCode::DUPLICATE_IDENTITY},
      {"duplicate port hint", duplicate_hint, aifc::ErrorCode::DUPLICATE_IDENTITY},
      {"non-canonical adapter name (upper case)", uppercase_adapter,
       aifc::ErrorCode::MALFORMED_INPUT},
      {"non-canonical adapter name (space)", spaced_adapter, aifc::ErrorCode::MALFORMED_INPUT},
      {"empty adapter name", empty_adapter, aifc::ErrorCode::MALFORMED_INPUT},
      {"adapter confidence > 1.0", adapter_too_confident, aifc::ErrorCode::INVALID_ARGUMENT},
      {"port hint confidence > 1.0", hint_too_confident, aifc::ErrorCode::INVALID_ARGUMENT},
  };

  for (std::size_t index = 0; index < std::size(cases); ++index) {
    const Case& test_case = cases[index];
    const auto canonical = aifc::ClassifierPolicy::canonicalize(test_case.policy);
    AIFC_CHECK_MSG(!canonical.ok(),
                   "case " << index << " (" << test_case.what
                           << ") must be refused but canonicalize accepted it");
    if (!canonical.ok()) {
      AIFC_CHECK_MSG(canonical.code() == test_case.expected,
                     "case " << index << " (" << test_case.what << ") produced "
                             << std::string(aifc::to_string(canonical.code())) << " ("
                             << canonical.status().message << ") but "
                             << std::string(aifc::to_string(test_case.expected))
                             << " was expected");
    }
  }

  // A *disabled* adapter declared while the global switch is off is not contradictory: it
  // enables nothing, so the policy still describes exactly one behaviour.  The refusal above is
  // specifically about a policy that switches an adapter on while the global gate is closed.
  aifc::ClassifierPolicy disabled_adapter_but_off = aifc::ClassifierPolicy::initial();
  disabled_adapter_but_off.allow_heuristic_evidence = false;
  disabled_adapter_but_off.heuristic_adapters = {adapter("adapter-alpha", false, 1000U, 0U)};
  const auto accepted = aifc::ClassifierPolicy::canonicalize(disabled_adapter_but_off);
  AIFC_CHECK_MSG(accepted.ok(),
                 "a disabled adapter must not make the policy contradictory, but canonicalize "
                 "produced "
                     << status_text(accepted.status()));
  if (accepted) {
    AIFC_CHECK(!accepted.value().heuristic_enabled("adapter-alpha"));
  }
}

AIFC_TEST("policy: declaration order does not change the digest (REAL)") {
  const aifc::ClassifierPolicy forward = valid_policy(false);
  const aifc::ClassifierPolicy reversed = valid_policy(true);

  // Before canonicalisation the two policies are genuinely different declarations: the vectors
  // are in different orders.
  AIFC_CHECK_EQ(forward.heuristic_adapters.size(), std::size_t{2});
  AIFC_CHECK_EQ(reversed.heuristic_adapters.size(), std::size_t{2});
  if (forward.heuristic_adapters.size() == 2U && reversed.heuristic_adapters.size() == 2U) {
    AIFC_CHECK_EQ(forward.heuristic_adapters[0].name, std::string("adapter-alpha"));
    AIFC_CHECK_EQ(reversed.heuristic_adapters[0].name, std::string("adapter-beta"));
    AIFC_CHECK_NE(forward.heuristic_adapters[0].name, reversed.heuristic_adapters[0].name);
  }
  if (forward.port_hints.size() == 2U && reversed.port_hints.size() == 2U) {
    AIFC_CHECK(forward.port_hints[0].transport == aifc::TransportProtocol::TCP);
    AIFC_CHECK(reversed.port_hints[0].transport == aifc::TransportProtocol::UDP);
  }

  const auto canonical_forward = aifc::ClassifierPolicy::canonicalize(forward);
  const auto canonical_reversed = aifc::ClassifierPolicy::canonicalize(reversed);
  AIFC_CHECK_OK(canonical_forward);
  AIFC_CHECK_OK(canonical_reversed);
  if (!canonical_forward || !canonical_reversed) return;

  const aifc::Digest256 forward_digest = aifc::compute_policy_digest(canonical_forward.value());
  const aifc::Digest256 reversed_digest = aifc::compute_policy_digest(canonical_reversed.value());
  AIFC_CHECK_MSG(forward_digest == reversed_digest,
                 "two policies differing only in declaration order produced different digests: "
                     << forward_digest.to_hex() << " != " << reversed_digest.to_hex());
  AIFC_CHECK(!forward_digest.is_zero());

  // The canonical forms are equal field by field, not merely digest-equal.
  AIFC_CHECK_EQ(canonical_forward.value().heuristic_adapters.size(),
                canonical_reversed.value().heuristic_adapters.size());
  for (std::size_t index = 0; index < canonical_forward.value().heuristic_adapters.size(); ++index) {
    AIFC_CHECK_EQ(canonical_forward.value().heuristic_adapters[index].name,
                  canonical_reversed.value().heuristic_adapters[index].name);
    AIFC_CHECK_EQ(canonical_forward.value().heuristic_adapters[index].max_basis_points,
                  canonical_reversed.value().heuristic_adapters[index].max_basis_points);
    AIFC_CHECK_EQ(canonical_forward.value().heuristic_adapters[index].priority,
                  canonical_reversed.value().heuristic_adapters[index].priority);
  }
  for (std::size_t index = 0; index < canonical_forward.value().port_hints.size(); ++index) {
    AIFC_CHECK_EQ(canonical_forward.value().port_hints[index].port,
                  canonical_reversed.value().port_hints[index].port);
    AIFC_CHECK_EQ(canonical_forward.value().port_hints[index].adapter,
                  canonical_reversed.value().port_hints[index].adapter);
  }

  // Canonicalisation is idempotent: canonicalising a canonical policy reproduces the digest.
  const auto twice = aifc::ClassifierPolicy::canonicalize(canonical_forward.value());
  AIFC_CHECK_OK(twice);
  if (twice) {
    AIFC_CHECK_MSG(aifc::compute_policy_digest(twice.value()) == forward_digest,
                   "canonicalisation is not idempotent for " << forward_digest.to_hex());
  }

  // Order independence extends to three adapters declared in two different orders, so the
  // property is not an artefact of a two element special case.
  aifc::ClassifierPolicy three_a = aifc::ClassifierPolicy::initial();
  three_a.allow_heuristic_evidence = true;
  three_a.heuristic_adapters = {adapter("zulu", false, 100U, 0U), adapter("alpha", true, 200U, 1U),
                                adapter("mike", false, 300U, 2U)};
  aifc::ClassifierPolicy three_b = aifc::ClassifierPolicy::initial();
  three_b.allow_heuristic_evidence = true;
  three_b.heuristic_adapters = {adapter("mike", false, 300U, 2U), adapter("zulu", false, 100U, 0U),
                                adapter("alpha", true, 200U, 1U)};
  const auto canonical_three_a = aifc::ClassifierPolicy::canonicalize(three_a);
  const auto canonical_three_b = aifc::ClassifierPolicy::canonicalize(three_b);
  AIFC_CHECK_OK(canonical_three_a);
  AIFC_CHECK_OK(canonical_three_b);
  if (canonical_three_a && canonical_three_b) {
    AIFC_CHECK_MSG(aifc::compute_policy_digest(canonical_three_a.value()) ==
                       aifc::compute_policy_digest(canonical_three_b.value()),
                   "three adapters declared in two orders produced different digests");
    AIFC_CHECK_EQ(canonical_three_a.value().heuristic_adapters[0].name, std::string("alpha"));
    AIFC_CHECK_EQ(canonical_three_a.value().heuristic_adapters[1].name, std::string("mike"));
    AIFC_CHECK_EQ(canonical_three_a.value().heuristic_adapters[2].name, std::string("zulu"));
  }
}
