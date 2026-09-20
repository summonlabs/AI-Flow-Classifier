// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/ids.hpp"

#include <array>
#include <string>

namespace aifc {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] std::string to_hex_string(const std::uint8_t* data, std::size_t length) {
  std::string out;
  out.resize(length * 2);
  for (std::size_t i = 0; i < length; ++i) {
    out[i * 2] = kHexDigits[(data[i] >> 4) & 0x0FU];
    out[i * 2 + 1] = kHexDigits[data[i] & 0x0FU];
  }
  return out;
}

void store_u64_be(std::uint8_t* out, std::uint64_t value) noexcept {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((value >> (8 * (7 - i))) & 0xFFU);
  }
}

[[nodiscard]] std::string render_u64(std::uint64_t value) { return std::to_string(value); }

// True for [a-z0-9._:-].  Deliberately narrow: an identity is a token, not a
// display string, and a wide character set invites homoglyph confusion.
[[nodiscard]] bool is_identity_byte(unsigned char c) noexcept {
  if (c >= 'a' && c <= 'z') return true;
  if (c >= '0' && c <= '9') return true;
  return c == '.' || c == '_' || c == ':' || c == '-';
}

[[nodiscard]] unsigned char fold_ascii(unsigned char c) noexcept {
  if (c >= 'A' && c <= 'Z') return static_cast<unsigned char>(c - 'A' + 'a');
  return c;
}

}  // namespace

std::string Id128::to_hex() const {
  std::array<std::uint8_t, 16> raw{};
  store_u64_be(raw.data(), hi);
  store_u64_be(raw.data() + 8, lo);
  return to_hex_string(raw.data(), raw.size());
}

std::string Digest256::to_hex() const { return to_hex_string(bytes, kBytes); }

std::string FlowGeneration::to_string() const { return render_u64(value); }
std::string WorkloadGeneration::to_string() const { return render_u64(value); }
std::string PublisherBootId::to_string() const { return render_u64(value); }
std::string EvidenceGeneration::to_string() const { return render_u64(value); }
std::string CoordinatorEpoch::to_string() const { return render_u64(value); }
std::string CoordinatorBootId::to_string() const { return render_u64(value); }
std::string ClassifierPolicyGeneration::to_string() const { return render_u64(value); }

Result<std::string> canonicalize_identity(std::string_view raw) {
  if (raw.empty()) {
    return Status::failure(ErrorCode::MALFORMED_INPUT, "identity is empty");
  }
  if (raw.size() > kMaxIdentityBytes) {
    return Status::failure(ErrorCode::MALFORMED_INPUT,
                           "identity exceeds " + std::to_string(kMaxIdentityBytes) + " bytes");
  }
  std::string out;
  out.reserve(raw.size());
  for (char ch : raw) {
    const auto byte = static_cast<unsigned char>(ch);
    const unsigned char folded = fold_ascii(byte);
    if (!is_identity_byte(folded)) {
      return Status::failure(ErrorCode::MALFORMED_INPUT,
                             "identity contains a character outside [a-z0-9._:-]");
    }
    out.push_back(static_cast<char>(folded));
  }
  return out;
}

bool is_canonical_identity(std::string_view value) noexcept {
  if (value.empty() || value.size() > kMaxIdentityBytes) return false;
  for (char ch : value) {
    const auto byte = static_cast<unsigned char>(ch);
    if (fold_ascii(byte) != byte) return false;
    if (!is_identity_byte(byte)) return false;
  }
  return true;
}

PublisherId make_publisher_id(std::string canonical) {
  return is_canonical_identity(canonical) ? PublisherId(std::move(canonical)) : PublisherId{};
}
WorkloadId make_workload_id(std::string canonical) {
  return is_canonical_identity(canonical) ? WorkloadId(std::move(canonical)) : WorkloadId{};
}
EvidenceId make_evidence_id(std::string canonical) {
  return is_canonical_identity(canonical) ? EvidenceId(std::move(canonical)) : EvidenceId{};
}
ContractId make_contract_id(std::string canonical) {
  return is_canonical_identity(canonical) ? ContractId(std::move(canonical)) : ContractId{};
}

}  // namespace aifc
