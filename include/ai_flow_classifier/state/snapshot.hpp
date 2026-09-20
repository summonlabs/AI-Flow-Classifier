// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Durable coordinator state.
//
// Format
// ------
//
//   offset  size  field
//        0     4  magic "AIFS"
//        4     2  format version
//        6     2  persistence generation
//        8     8  body length
//       16     8  epoch
//       24     8  boot id
//       32     8  sequence high-water mark
//       40     8  written-at wall clock milliseconds (informational)
//       48    32  SHA-256 of the body
//       80     8  CRC-32 of bytes 0..79
//       88     N  body
//
// Rules
// -----
//
//   * a body longer than the configured bound is refused before allocation;
//   * a format version or persistence generation this build does not understand is
//     refused as UNSUPPORTED_FORMAT_VERSION, and nothing is applied;
//   * the body digest and the header checksum are both verified before decoding, so a
//     torn or corrupted file can never be partially applied;
//   * the body is decoded into a staging structure and only handed to the caller once
//     every record has decoded successfully;
//   * what is *not* restored is authority.  Sessions, liveness, freshness and the
//     decision memo are deliberately absent from the format, because none of them is
//     meaningful after a restart.

#ifndef AI_FLOW_CLASSIFIER_STATE_SNAPSHOT_HPP
#define AI_FLOW_CLASSIFIER_STATE_SNAPSHOT_HPP

#include <ostream>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ai_flow_classifier/codec/record_codec.hpp"
#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/publisher.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"
#include "ai_flow_classifier/foundation/ids.hpp"

namespace aifc {

inline constexpr std::size_t kSnapshotHeaderBytes = 88;
inline constexpr std::uint8_t kSnapshotMagic[4] = {'A', 'I', 'F', 'S'};
inline constexpr std::uint16_t kSnapshotFormatVersion = 1;
inline constexpr std::uint8_t kSnapshotBodySchema = 1;

// A durable coordinator state image.  Every collection is bounded by the policy that
// produced it, and reading enforces the same bounds.
struct StateSnapshot {
  std::uint16_t format_version = kSnapshotFormatVersion;
  std::uint16_t persistence_generation = kPersistenceGeneration;
  CoordinatorEpoch epoch;
  CoordinatorBootId boot;
  std::uint64_t sequence_high_water = 0;
  std::uint64_t written_at_wall_millis = 0;
  ClassifierPolicy policy;

  std::vector<PublisherRecord> publishers;
  std::vector<WorkloadRecord> workloads;
  std::vector<WorkloadContract> contracts;
  std::vector<FlowRecord> flows;
  std::vector<EvidenceRecord> evidence;
  std::vector<Classification> classifications;
  std::vector<RevocationRecord> revocations;
  std::vector<SupersessionRecord> supersessions;

  [[nodiscard]] std::size_t record_count() const noexcept {
    return publishers.size() + workloads.size() + contracts.size() + flows.size() +
           evidence.size() + classifications.size() + revocations.size() + supersessions.size();
  }
};

struct SnapshotLimits {
  std::uint64_t max_file_bytes = 256ULL * 1024ULL * 1024ULL;
  std::uint32_t max_records_per_collection = 1U << 20;
  CodecLimits codec{};
};

// Serialises a snapshot to its canonical byte image.
[[nodiscard]] Result<ByteBuffer> encode_snapshot(const StateSnapshot& snapshot,
                                                const SnapshotLimits& limits);

// Decodes a snapshot without applying anything.  Every failure leaves the caller's
// state untouched because the caller only ever sees a fully decoded value.
[[nodiscard]] Result<StateSnapshot> decode_snapshot(const std::uint8_t* data, std::size_t size,
                                                   const SnapshotLimits& limits);

// Writes a snapshot to path atomically and durably.
[[nodiscard]] Status write_snapshot_file(std::string_view path, const StateSnapshot& snapshot,
                                        const SnapshotLimits& limits);

// Reads a snapshot from path.  An absent file is NOT_FOUND; a present but invalid file
// is a specific integrity or version failure.
[[nodiscard]] Result<StateSnapshot> read_snapshot_file(std::string_view path,
                                                      const SnapshotLimits& limits);

// Removes sibling temporary files left behind by a process that died mid-write.
// Returns how many were removed.  A temporary file is never a valid snapshot, so
// removing them cannot lose committed state.
[[nodiscard]] Result<std::uint32_t> recover_orphan_temporaries(std::string_view directory,
                                                             std::string_view prefix);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_STATE_SNAPSHOT_HPP
