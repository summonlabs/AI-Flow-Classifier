// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Classifier policy.
//
// The policy is the complete, finite description of how a decision is reached.
// A decision records the policy generation *and* a digest of the policy content,
// so a decision can never be silently reinterpreted under a differently shaped
// policy that happens to reuse a generation number.
//
// A policy change is an explicit, versioned act.  It is never implied by a
// configuration tweak, by evidence arriving, or by the passage of time.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_POLICY_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_POLICY_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ai_flow_classifier/foundation/math.hpp"

#include "ai_flow_classifier/domain/flow_key.hpp"
#include "ai_flow_classifier/domain/semantic_class.hpp"
#include "ai_flow_classifier/foundation/config.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

// An optional heuristic adapter.  Adapters are the only route by which a guess can
// enter the runtime, and they are gated three times: the policy must enable
// heuristics globally, the adapter must be enabled by name, and the resulting
// evidence carries source HEURISTIC, which is the lowest rank and can never
// outrank a current authenticated declaration.
struct HeuristicAdapterPolicy {
  std::string name;
  bool enabled = false;
  // Highest confidence this adapter may claim, capped by
  // source_confidence(HEURISTIC) at evaluation time if it asks for more.
  std::uint32_t max_basis_points = 2000U;
  std::uint32_t priority = 0;
};

// A port-based heuristic.  Deliberately expressed as a lookup, not as code, so that the heuristic
// surface is finite and inspectable.
//
// A hint is the *declared* observation a heuristic submission may cite: the submitter identifies the
// hint through the record's binding field, and the coordinator refuses the submission when no such
// hint is declared and attached to an enabled adapter.  The runtime does not itself observe ports --
// it has no capture path -- so a hint is a permission and a label, not a measurement.  Ports and
// five-tuples alone are never authoritative; that is the point of this project.
struct PortHint {
  TransportProtocol transport = TransportProtocol::UNKNOWN;
  std::uint16_t port = 0;
  SemanticClass semantic = SemanticClass::UNKNOWN;
  std::uint32_t basis_points = 500U;
  std::string adapter;
};

struct ClassifierPolicy {
  ClassifierPolicyGeneration generation;

  ResourceLimits limits;

  // When false, a policy that would otherwise enable heuristics produces a denial
  // (HEURISTIC_DISABLED) for every heuristic submission, rather than silently ignoring it.
  //
  // This is the first of two gates.  The second is the adapter list below: a heuristic submission is
  // admitted only when at least one adapter is enabled *and* the submission names a port hint that is
  // declared and attached to an enabled adapter.  Both gates are consulted on the admission path --
  // see Classifier::admit_evidence -- so neither is a documentation-only claim.
  bool allow_heuristic_evidence = false;

  // Freshness window applied to evidence that does not carry its own deadline.
  std::uint64_t default_freshness_window = 4096ULL;

  // Explicit penalty applied to the confidence of a classification whose current
  // evidence set contains an unresolved contradiction.  The penalty is reported
  // in the explanation; it is never applied silently.
  std::uint32_t contradiction_penalty = 2000U;

  // A classification whose confidence falls below this value is reported with
  // evidence state INSUFFICIENT and class UNKNOWN, with the losing candidate kept
  // in the explanation as "below threshold".  This is the mechanism that keeps
  // UNKNOWN from being promoted by weak data.
  std::uint32_t minimum_publishable_confidence = 1000U;

  // Maximum number of evidence records considered per classification.  Ordered
  // canonically before the cap is applied, so the cap itself is deterministic.
  std::uint32_t max_evidence_considered = 32U;

  std::vector<HeuristicAdapterPolicy> heuristic_adapters;
  std::vector<PortHint> port_hints;

  // A policy with generation 0 and default content, used before a coordinator
  // installs anything.  It never enables heuristics.
  [[nodiscard]] static ClassifierPolicy initial();

  // Validates the policy and returns a canonical copy.  Adapters and hints are
  // sorted by their canonical keys so that two policies that differ only in
  // declaration order have the same digest, and therefore the same decisions.
  [[nodiscard]] static Result<ClassifierPolicy> canonicalize(ClassifierPolicy policy);

  [[nodiscard]] bool heuristic_enabled(std::string_view adapter_name) const noexcept;

  // How a heuristic submission identifies the hint it is citing.  The claim travels in the record's
  // existing opaque binding field, so no wire field was added for it: the low 16 bits are the port and
  // the next byte is the transport.  A submission that cites nothing decodes to port zero, and no hint
  // is registered for port zero.
  struct HeuristicClaim {
    TransportProtocol transport = TransportProtocol::UNKNOWN;
    std::uint16_t port = 0;
  };
  [[nodiscard]] static HeuristicClaim claim_of(std::uint64_t binding) noexcept;

  // The inverse of claim_of: the binding a submission must carry in order to cite (transport, port).
  // Exposed so that a caller does not have to know the layout.
  [[nodiscard]] static std::uint64_t hint_binding_of(TransportProtocol transport,
                                                     std::uint16_t port) noexcept;

  // True when this policy declares a usable hint for the transport and port: the hint exists, and it
  // names an adapter that the policy also declares and enables.  A hint that references an unknown or
  // disabled adapter is not usable, so the adapter gate cannot be bypassed by declaring a dangling
  // hint.
  [[nodiscard]] const PortHint* find_port_hint(TransportProtocol transport,
                                              std::uint16_t port) const noexcept;
};

// Canonical digest of the policy content.  The generation number is excluded,
// because the digest exists precisely to detect content that changed while the
// generation did not.
[[nodiscard]] Digest256 compute_policy_digest(const ClassifierPolicy& policy);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_POLICY_HPP
