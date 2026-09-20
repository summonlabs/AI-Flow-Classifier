// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Strongly typed public identities.
//
// Every identity in this runtime is a distinct type.  A PublisherId can never be
// passed where a WorkloadId is expected, and an identifier is never a substitute
// for a generation: see domain/generation.hpp for the fencing rules.
//
// String identifiers are canonical under ASCII lower-case folding and are
// validated on construction from untrusted input (see try_parse_string_id).  A
// string identity is a stable name chosen by a publisher, not a proof of
// anything; authority always comes from the authenticated session envelope.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_IDS_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_IDS_HPP

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <type_traits>

#include "ai_flow_classifier/foundation/config.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

// 16 byte opaque identity, used for flows and evidence.
struct Id128 {
  std::uint64_t hi = 0;
  std::uint64_t lo = 0;

  friend constexpr bool operator==(const Id128& a, const Id128& b) noexcept {
    return a.hi == b.hi && a.lo == b.lo;
  }
  friend constexpr bool operator!=(const Id128& a, const Id128& b) noexcept { return !(a == b); }
  friend constexpr bool operator<(const Id128& a, const Id128& b) noexcept {
    return a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo;
  }
  friend constexpr bool operator>(const Id128& a, const Id128& b) noexcept { return b < a; }
  friend constexpr bool operator<=(const Id128& a, const Id128& b) noexcept { return !(b < a); }
  friend constexpr bool operator>=(const Id128& a, const Id128& b) noexcept { return !(a < b); }

  [[nodiscard]] constexpr bool is_zero() const noexcept { return hi == 0 && lo == 0; }
  [[nodiscard]] static constexpr Id128 zero() noexcept { return Id128{}; }

  // Canonical lower-case hex, fixed 32 characters, no separators.
  [[nodiscard]] std::string to_hex() const;
};

// 32 byte digest, used for content hashes and for decision digests.
struct Digest256 {
  static constexpr std::size_t kBytes = 32;
  std::uint8_t bytes[kBytes] = {};

  friend constexpr bool operator==(const Digest256& a, const Digest256& b) noexcept {
    for (std::size_t i = 0; i < kBytes; ++i) {
      if (a.bytes[i] != b.bytes[i]) return false;
    }
    return true;
  }
  friend constexpr bool operator!=(const Digest256& a, const Digest256& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const Digest256& a, const Digest256& b) noexcept {
    for (std::size_t i = 0; i < kBytes; ++i) {
      if (a.bytes[i] != b.bytes[i]) return a.bytes[i] < b.bytes[i];
    }
    return false;
  }

  [[nodiscard]] constexpr bool is_zero() const noexcept {
    for (std::size_t i = 0; i < kBytes; ++i) {
      if (bytes[i] != 0) return false;
    }
    return true;
  }
  [[nodiscard]] static constexpr Digest256 zero() noexcept { return Digest256{}; }
  [[nodiscard]] std::string to_hex() const;
};

// Canonical text rendering for the two opaque identity types.  Declared here, after both types
// exist, so that a diagnostic can never print raw bytes where a hex identity was meant.
inline std::ostream& operator<<(std::ostream& stream, const Id128& id) {
  return stream << id.to_hex();
}

inline std::ostream& operator<<(std::ostream& stream, const Digest256& digest) {
  return stream << digest.to_hex();
}

// A monotonic, never reused counter.  Generation types below are aliases so that
// the same 64 bit value carries different meaning at each use site.
using Seq = std::uint64_t;
inline constexpr Seq kSeqNone = 0;

namespace detail {
template <typename Tag>
class StringId {
 public:
  StringId() = default;
  explicit StringId(std::string canonical) : value_(std::move(canonical)) {}

  [[nodiscard]] const std::string& value() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }
  [[nodiscard]] const char* c_str() const noexcept { return value_.c_str(); }

  friend bool operator==(const StringId& a, const StringId& b) noexcept {
    return a.value_ == b.value_;
  }
  friend bool operator!=(const StringId& a, const StringId& b) noexcept { return !(a == b); }
  friend bool operator<(const StringId& a, const StringId& b) noexcept {
    return a.value_ < b.value_;
  }

 private:
  std::string value_;
};
}  // namespace detail

struct PublisherIdTag {};
struct WorkloadIdTag {};
struct EvidenceIdTag {};
struct ContractIdTag {};
struct SessionIdTag {};
// A flow identity is opaque 128 bits derived from the canonical key, not a
// publisher-chosen name.  The alias exists so that a FlowId is a distinct name at every
// use site even though it shares its representation with the other 128 bit identities.
using FlowId = Id128;

using PublisherId = detail::StringId<PublisherIdTag>;
using WorkloadId = detail::StringId<WorkloadIdTag>;
using EvidenceId = detail::StringId<EvidenceIdTag>;
using ContractId = detail::StringId<ContractIdTag>;
using SessionId = detail::StringId<SessionIdTag>;

// A flow generation.  A flow key identifies an observed flow; a generation
// identifies one incarnation of it.  A classification is always bound to a
// generation, never to a key alone.
struct FlowGeneration {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const FlowGeneration& a, const FlowGeneration& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const FlowGeneration& a, const FlowGeneration& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const FlowGeneration& a, const FlowGeneration& b) noexcept {
    return a.value < b.value;
  }
  friend constexpr bool operator<=(const FlowGeneration& a, const FlowGeneration& b) noexcept {
    return a.value <= b.value;
  }
  friend constexpr bool operator>(const FlowGeneration& a, const FlowGeneration& b) noexcept {
    return a.value > b.value;
  }
  friend constexpr bool operator>=(const FlowGeneration& a, const FlowGeneration& b) noexcept {
    return a.value >= b.value;
  }
  [[nodiscard]] constexpr bool valid() const noexcept { return value != 0; }
  [[nodiscard]] std::string to_string() const;
};

struct WorkloadGeneration {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const WorkloadGeneration& a, const WorkloadGeneration& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const WorkloadGeneration& a, const WorkloadGeneration& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const WorkloadGeneration& a, const WorkloadGeneration& b) noexcept {
    return a.value < b.value;
  }
  friend constexpr bool operator>(const WorkloadGeneration& a, const WorkloadGeneration& b) noexcept {
    return a.value > b.value;
  }
  [[nodiscard]] constexpr bool valid() const noexcept { return value != 0; }
  [[nodiscard]] std::string to_string() const;
};

// Boot incarnation of a publisher process.  Restarting a publisher process
// produces a strictly larger boot id; state bound to an older boot id is stale
// even when the publisher identity itself is unchanged.
struct PublisherBootId {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const PublisherBootId& a, const PublisherBootId& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const PublisherBootId& a, const PublisherBootId& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const PublisherBootId& a, const PublisherBootId& b) noexcept {
    return a.value < b.value;
  }
  friend constexpr bool operator>(const PublisherBootId& a, const PublisherBootId& b) noexcept {
    return a.value > b.value;
  }
  [[nodiscard]] constexpr bool valid() const noexcept { return value != 0; }
  [[nodiscard]] std::string to_string() const;
};

// Incarnation of an evidence publication.  Republishing the same topic from the
// same publisher requires a strictly larger evidence generation.
struct EvidenceGeneration {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const EvidenceGeneration& a, const EvidenceGeneration& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const EvidenceGeneration& a, const EvidenceGeneration& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const EvidenceGeneration& a, const EvidenceGeneration& b) noexcept {
    return a.value < b.value;
  }
  friend constexpr bool operator>(const EvidenceGeneration& a, const EvidenceGeneration& b) noexcept {
    return a.value > b.value;
  }
  friend constexpr bool operator<=(const EvidenceGeneration& a, const EvidenceGeneration& b) noexcept {
    return a.value <= b.value;
  }
  friend constexpr bool operator>=(const EvidenceGeneration& a, const EvidenceGeneration& b) noexcept {
    return a.value >= b.value;
  }
  [[nodiscard]] constexpr bool valid() const noexcept { return value != 0; }
  [[nodiscard]] std::string to_string() const;
};

// Coordinator incarnation.  Advancing the epoch clears liveness and freshness:
// no authority survives a coordinator restart by itself.
struct CoordinatorEpoch {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const CoordinatorEpoch& a, const CoordinatorEpoch& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const CoordinatorEpoch& a, const CoordinatorEpoch& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const CoordinatorEpoch& a, const CoordinatorEpoch& b) noexcept {
    return a.value < b.value;
  }
  friend constexpr bool operator>(const CoordinatorEpoch& a, const CoordinatorEpoch& b) noexcept {
    return a.value > b.value;
  }
  [[nodiscard]] constexpr bool valid() const noexcept { return value != 0; }
  [[nodiscard]] std::string to_string() const;
};

// Incarnation of a coordinator process which is independent of the epoch it
// serves.  Two processes can serve the same epoch only if the first one is
// provably gone; a boot id mismatch is always STALE_BOOT_ID.
struct CoordinatorBootId {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const CoordinatorBootId& a, const CoordinatorBootId& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const CoordinatorBootId& a, const CoordinatorBootId& b) noexcept {
    return !(a == b);
  }
  [[nodiscard]] constexpr bool valid() const noexcept { return value != 0; }
  [[nodiscard]] std::string to_string() const;
};

// Generation of the classifier policy.  A classification records the policy
// generation that produced it, so a decision can never be silently reinterpreted
// under a newer policy.
struct ClassifierPolicyGeneration {
  std::uint64_t value = 0;
  friend constexpr bool operator==(const ClassifierPolicyGeneration& a,
                                   const ClassifierPolicyGeneration& b) noexcept {
    return a.value == b.value;
  }
  friend constexpr bool operator!=(const ClassifierPolicyGeneration& a,
                                   const ClassifierPolicyGeneration& b) noexcept {
    return !(a == b);
  }
  friend constexpr bool operator<(const ClassifierPolicyGeneration& a,
                                  const ClassifierPolicyGeneration& b) noexcept {
    return a.value < b.value;
  }
  friend constexpr bool operator>(const ClassifierPolicyGeneration& a,
                                  const ClassifierPolicyGeneration& b) noexcept {
    return a.value > b.value;
  }
  [[nodiscard]] constexpr bool valid() const noexcept { return value != 0; }
  [[nodiscard]] std::string to_string() const;
};

// Canonical string identity rules shared by every StringId user.
inline constexpr std::size_t kMaxIdentityBytes = 128U;

// Folds to lower case and validates the character set [a-z0-9._:-].  Returns
// MALFORMED_INPUT for an empty, oversized or non-conforming identity.
[[nodiscard]] Result<std::string> canonicalize_identity(std::string_view raw);
[[nodiscard]] bool is_canonical_identity(std::string_view value) noexcept;

[[nodiscard]] PublisherId make_publisher_id(std::string canonical);
[[nodiscard]] WorkloadId make_workload_id(std::string canonical);
[[nodiscard]] EvidenceId make_evidence_id(std::string canonical);
[[nodiscard]] ContractId make_contract_id(std::string canonical);

}  // namespace aifc

namespace std {
template <>
struct hash<aifc::Id128> {
  size_t operator()(const aifc::Id128& id) const noexcept {
    return static_cast<size_t>(id.hi ^ (id.lo * 0x9E3779B97F4A7C15ULL));
  }
};
template <>
struct hash<aifc::Digest256> {
  size_t operator()(const aifc::Digest256& d) const noexcept {
    std::uint64_t h = 1469598103934665603ULL;
    for (std::size_t i = 0; i < aifc::Digest256::kBytes; ++i) {
      h ^= d.bytes[i];
      h *= 1099511628211ULL;
    }
    return static_cast<size_t>(h);
  }
};
template <typename Tag>
struct hash<aifc::detail::StringId<Tag>> {
  size_t operator()(const aifc::detail::StringId<Tag>& id) const noexcept {
    return std::hash<std::string>{}(id.value());
  }
};
}  // namespace std

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_IDS_HPP
