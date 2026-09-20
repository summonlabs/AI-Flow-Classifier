// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/domain/flow_key.hpp"

#include <array>
#include <string>

#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"

namespace aifc {
namespace {

struct TransportEntry {
  TransportProtocol value;
  std::string_view name;
};

constexpr std::array<TransportEntry, 5> kTransports = {{
    {TransportProtocol::UNKNOWN, "UNKNOWN"},
    {TransportProtocol::TCP, "TCP"},
    {TransportProtocol::UDP, "UDP"},
    {TransportProtocol::SCTP, "SCTP"},
    {TransportProtocol::RDMA, "RDMA"},
}};

// RFC 5952 renders a 16 bit group as one to four lower case hexadecimal digits with leading
// zeros suppressed.  The group has to be converted as a whole: rendering its two bytes
// independently suppresses a leading zero inside the low byte, so 0x2001 would render as
// "201" and 0x1001 and 0x0101 would both render as "101".
void append_hex_group(std::string& out, std::uint16_t value) {
  static constexpr char kDigits[] = "0123456789abcdef";
  char buffer[4] = {};
  int index = 0;
  do {
    buffer[index++] = kDigits[value & 0x0FU];
    value = static_cast<std::uint16_t>(value >> 4);
  } while (value != 0 && index < 4);
  while (index > 0) {
    out.push_back(buffer[--index]);
  }
}

}  // namespace

bool IpAddress::is_zero() const noexcept {
  for (std::uint8_t byte : bytes) {
    if (byte != 0) return false;
  }
  return true;
}

bool IpAddress::is_v4_mapped() const noexcept {
  for (std::size_t i = 0; i < 10; ++i) {
    if (bytes[i] != 0) return false;
  }
  return bytes[10] == 0xFFU && bytes[11] == 0xFFU;
}

IpAddress IpAddress::from_v4(std::uint32_t host_order) noexcept {
  IpAddress address;
  address.bytes[10] = 0xFFU;
  address.bytes[11] = 0xFFU;
  address.bytes[12] = static_cast<std::uint8_t>((host_order >> 24) & 0xFFU);
  address.bytes[13] = static_cast<std::uint8_t>((host_order >> 16) & 0xFFU);
  address.bytes[14] = static_cast<std::uint8_t>((host_order >> 8) & 0xFFU);
  address.bytes[15] = static_cast<std::uint8_t>(host_order & 0xFFU);
  return address;
}

IpAddress IpAddress::from_v6(const std::array<std::uint8_t, 16>& raw) noexcept {
  IpAddress address;
  address.bytes = raw;
  return address;
}

std::string IpAddress::to_string() const {
  std::string out;
  if (is_v4_mapped()) {
    for (std::size_t i = 12; i < 16; ++i) {
      if (i != 12) out.push_back('.');
      out += std::to_string(static_cast<unsigned>(bytes[i]));
    }
    return out;
  }
  // RFC 5952 style compression of the longest run of zero groups, implemented here
  // rather than with a platform inet_ntop so that the rendering is identical on every
  // platform and can therefore be compared in a test.
  std::uint16_t groups[8] = {};
  for (std::size_t i = 0; i < 8; ++i) {
    groups[i] = static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[i * 2]) << 8) |
                                           static_cast<std::uint16_t>(bytes[i * 2 + 1]));
  }
  std::size_t best_start = 8;
  std::size_t best_length = 0;
  std::size_t run_start = 0;
  std::size_t run_length = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    if (groups[i] == 0) {
      if (run_length == 0) run_start = i;
      ++run_length;
      if (run_length > best_length) {
        best_length = run_length;
        best_start = run_start;
      }
    } else {
      run_length = 0;
    }
  }
  if (best_length < 2) {
    best_start = 8;
    best_length = 0;
  }
  for (std::size_t i = 0; i < 8; ++i) {
    if (best_length != 0 && i == best_start) {
      out += "::";
      i += best_length - 1;
      continue;
    }
    if (!out.empty() && out.back() != ':') out.push_back(':');
    append_hex_group(out, groups[i]);
  }
  if (out.empty()) out = "::";
  return out;
}

std::string_view to_string(TransportProtocol value) noexcept {
  for (const TransportEntry& entry : kTransports) {
    if (entry.value == value) return entry.name;
  }
  return "UNRECOGNIZED_TRANSPORT";
}

Result<TransportProtocol> parse_transport_protocol(std::string_view text) {
  for (const TransportEntry& entry : kTransports) {
    if (entry.name == text) return entry.value;
  }
  return Status::failure(ErrorCode::MALFORMED_INPUT,
                         "unrecognised transport protocol: " + std::string(text));
}

Result<TransportProtocol> decode_transport_protocol(std::uint32_t code) noexcept {
  for (const TransportEntry& entry : kTransports) {
    if (static_cast<std::uint32_t>(entry.value) == code) return entry.value;
  }
  // An unknown transport is UNKNOWN, never a defaulted TCP.  Defaulting would let a
  // malformed code select the transport a heuristic hint is registered for.
  return TransportProtocol::UNKNOWN;
}

bool operator<(const FlowKey& a, const FlowKey& b) noexcept {
  if (a.transport != b.transport) return a.transport < b.transport;
  if (a.local_address != b.local_address) return a.local_address < b.local_address;
  if (a.local_port != b.local_port) return a.local_port < b.local_port;
  if (a.remote_address != b.remote_address) return a.remote_address < b.remote_address;
  return a.remote_port < b.remote_port;
}

std::string FlowKey::to_string() const {
  std::string out;
  out += aifc::to_string(transport);
  out += ' ';
  out += local_address.to_string();
  out += ':';
  out += std::to_string(static_cast<unsigned>(local_port));
  out += " -> ";
  out += remote_address.to_string();
  out += ':';
  out += std::to_string(static_cast<unsigned>(remote_port));
  return out;
}

Id128 derive_flow_id(const FlowKey& key) noexcept {
  BufferWriter writer(64);
  Status status = writer.put_u8(static_cast<std::uint8_t>(key.transport));
  if (status) {
    status = writer.put_blob(key.local_address.bytes.data(), key.local_address.bytes.size());
  }
  if (status) {
    status = writer.put_blob(key.remote_address.bytes.data(), key.remote_address.bytes.size());
  }
  if (status) status = writer.put_u16(key.local_port);
  if (status) status = writer.put_u16(key.remote_port);
  Id128 id;
  if (!status) return id;
  const auto digest = sha256(writer.bytes().data(), writer.bytes().size());
  for (std::size_t i = 0; i < 8; ++i) {
    id.hi = (id.hi << 8) | static_cast<std::uint64_t>(digest[i]);
    id.lo = (id.lo << 8) | static_cast<std::uint64_t>(digest[i + 8]);
  }
  if (id.is_zero()) id.lo = 1;
  return id;
}

namespace detail {

std::size_t FlowKeyHash::operator()(const FlowKey& key) const noexcept {
  std::uint64_t seed = static_cast<std::uint64_t>(key.transport);
  seed = stable_hash_combine(seed, stable_hash_bytes(key.local_address.bytes.data(),
                                                     key.local_address.bytes.size()));
  seed = stable_hash_combine(seed, static_cast<std::uint64_t>(key.local_port));
  seed = stable_hash_combine(seed, stable_hash_bytes(key.remote_address.bytes.data(),
                                                     key.remote_address.bytes.size()));
  seed = stable_hash_combine(seed, static_cast<std::uint64_t>(key.remote_port));
  return static_cast<std::size_t>(seed);
}

}  // namespace detail

}  // namespace aifc

namespace std {

size_t hash<aifc::FlowKey>::operator()(const aifc::FlowKey& key) const noexcept {
  return aifc::detail::FlowKeyHash{}(key);
}

}  // namespace std
