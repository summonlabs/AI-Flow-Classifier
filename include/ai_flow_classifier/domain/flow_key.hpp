// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Flow keys and transport identity.
//
// A flow key is a canonicalised five-tuple plus transport.  It is deliberately a
// separate header from the flow *record* so that evidence, policy and contract types
// can name a key without depending on registration and generation bookkeeping.
//
// The runtime does not capture packets and does not inspect payloads.  A key arrives
// from a publisher or from the local endpoint observer; nothing here observes traffic.

#ifndef AI_FLOW_CLASSIFIER_DOMAIN_FLOW_KEY_HPP
#define AI_FLOW_CLASSIFIER_DOMAIN_FLOW_KEY_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>

#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

// Canonical 16 byte IPv6 form; IPv4 addresses are carried v4-mapped so that a host has
// exactly one representation and two spellings can never create two flows.
struct IpAddress {
  std::array<std::uint8_t, 16> bytes{};

  friend bool operator==(const IpAddress& a, const IpAddress& b) noexcept {
    return a.bytes == b.bytes;
  }
  friend bool operator!=(const IpAddress& a, const IpAddress& b) noexcept { return !(a == b); }
  friend bool operator<(const IpAddress& a, const IpAddress& b) noexcept {
    return a.bytes < b.bytes;
  }

  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] bool is_v4_mapped() const noexcept;
  [[nodiscard]] static IpAddress from_v4(std::uint32_t host_order) noexcept;
  [[nodiscard]] static IpAddress from_v6(const std::array<std::uint8_t, 16>& raw) noexcept;
  [[nodiscard]] static IpAddress from_bytes(const std::array<std::uint8_t, 16>& raw) noexcept {
    return from_v6(raw);
  }

  // Canonical text: dotted quad for a v4-mapped address, otherwise RFC 5952 style
  // zero-group compression rendered by this project rather than by a platform
  // inet_ntop, so the output is identical everywhere.
  [[nodiscard]] std::string to_string() const;
};

enum class TransportProtocol : std::uint8_t {
  UNKNOWN = 0,
  TCP = 1,
  UDP = 2,
  SCTP = 3,
  RDMA = 4,
};

[[nodiscard]] std::string_view to_string(TransportProtocol value) noexcept;
[[nodiscard]] Result<TransportProtocol> parse_transport_protocol(std::string_view text);
[[nodiscard]] Result<TransportProtocol> decode_transport_protocol(std::uint32_t code) noexcept;

inline std::ostream& operator<<(std::ostream& stream, TransportProtocol value) {
  return stream << to_string(value);
}

struct FlowKey {
  IpAddress local_address;
  IpAddress remote_address;
  std::uint16_t local_port = 0;
  std::uint16_t remote_port = 0;
  TransportProtocol transport = TransportProtocol::UNKNOWN;

  friend bool operator==(const FlowKey& a, const FlowKey& b) noexcept {
    return a.local_address == b.local_address && a.remote_address == b.remote_address &&
           a.local_port == b.local_port && a.remote_port == b.remote_port &&
           a.transport == b.transport;
  }
  friend bool operator!=(const FlowKey& a, const FlowKey& b) noexcept { return !(a == b); }
  friend bool operator<(const FlowKey& a, const FlowKey& b) noexcept;

  [[nodiscard]] std::string to_string() const;
};

// Derives the opaque flow identity from the key.  The mapping is injective over the
// canonical encoding and independent of process state, so two independent processes
// with the same canonical key agree on the same FlowId.
[[nodiscard]] Id128 derive_flow_id(const FlowKey& key) noexcept;

namespace detail {
struct FlowKeyHash {
  std::size_t operator()(const FlowKey& key) const noexcept;
};
}  // namespace detail

}  // namespace aifc

namespace std {
template <>
struct hash<aifc::FlowKey> {
  size_t operator()(const aifc::FlowKey& key) const noexcept;
};
}  // namespace std

#endif  // AI_FLOW_CLASSIFIER_DOMAIN_FLOW_KEY_HPP
