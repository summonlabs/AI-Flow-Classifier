// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/state/snapshot.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "ai_flow_classifier/codec/record_codec.hpp"
#include "ai_flow_classifier/foundation/clock.hpp"
#include "ai_flow_classifier/foundation/hash.hpp"
#include "ai_flow_classifier/io/files.hpp"

namespace aifc {
namespace {

constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kFormatOffset = 4;
constexpr std::size_t kGenerationOffset = 6;
constexpr std::size_t kBodyLengthOffset = 8;
constexpr std::size_t kEpochOffset = 16;
constexpr std::size_t kBootOffset = 24;
constexpr std::size_t kSequenceOffset = 32;
constexpr std::size_t kWrittenAtOffset = 40;
constexpr std::size_t kBodyDigestOffset = 48;
constexpr std::size_t kHeaderChecksumOffset = 80;

[[nodiscard]] Status decode_collection(BufferReader& reader, std::uint32_t max_records,
                                       std::string_view name, std::uint32_t& count) {
  Result<std::uint32_t> value = reader.get_count(max_records);
  if (!value) {
    return Status::failure(value.code(), std::string(name) + ": " + value.message());
  }
  count = value.value();
  return Status::success();
}

template <typename T, typename DecodeFn>
[[nodiscard]] Status decode_records(BufferReader& reader, std::uint32_t count, std::string_view name,
                                    std::vector<T>& out, DecodeFn decode) {
  // The declared count is checked against the bytes that actually remain before anything is
  // reserved.  Every record occupies at least one byte, so a count larger than the remaining body
  // cannot be honest.  Without this check a small, correctly sealed image with a forged count makes
  // the decoder reserve memory proportional to the forged count instead of to the file, which is a
  // memory-amplification primitive reachable from a file alone.
  if (static_cast<std::size_t>(count) > reader.remaining()) {
    return Status::failure(ErrorCode::MALFORMED_RECORD,
                           std::string(name) + " declares " + std::to_string(count) +
                               " records but only " + std::to_string(reader.remaining()) +
                               " bytes remain in the snapshot body");
  }
  out.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    Result<T> record = decode(reader);
    if (!record) {
      return Status::failure(record.code(), std::string(name) + "[" + std::to_string(i) +
                                                "]: " + record.message());
    }
    out.push_back(std::move(record).value());
  }
  return Status::success();
}

}  // namespace

Result<ByteBuffer> encode_snapshot(const StateSnapshot& snapshot, const SnapshotLimits& limits) {
  BufferWriter body(static_cast<std::uint32_t>(
      std::min<std::uint64_t>(limits.max_file_bytes, 0xFFFFFFFFULL)));
  Status status = body.put_u8(kSnapshotBodySchema);
  if (status) status = encode_policy(body, snapshot.policy);

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.publishers.size()));
  for (const PublisherRecord& record : snapshot.publishers) {
    if (!status) break;
    status = encode_publisher_record(body, record);
  }

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.workloads.size()));
  for (const WorkloadRecord& record : snapshot.workloads) {
    if (!status) break;
    status = encode_workload_record(body, record);
  }

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.contracts.size()));
  for (const WorkloadContract& contract : snapshot.contracts) {
    if (!status) break;
    status = encode_contract(body, contract);
  }

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.flows.size()));
  for (const FlowRecord& record : snapshot.flows) {
    if (!status) break;
    status = encode_flow_record(body, record);
  }

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.evidence.size()));
  for (const EvidenceRecord& record : snapshot.evidence) {
    if (!status) break;
    status = encode_evidence_record(body, record);
  }

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.classifications.size()));
  for (const Classification& classification : snapshot.classifications) {
    if (!status) break;
    status = encode_classification(body, classification);
  }

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.revocations.size()));
  for (const RevocationRecord& record : snapshot.revocations) {
    if (!status) break;
    status = encode_revocation(body, record);
  }

  if (status) status = body.put_u32(static_cast<std::uint32_t>(snapshot.supersessions.size()));
  for (const SupersessionRecord& record : snapshot.supersessions) {
    if (!status) break;
    status = encode_supersession(body, record);
  }

  if (!status) {
    return Status::failure(status.code, "snapshot body encoding failed: " + status.message);
  }

  const ByteBuffer body_bytes = body.take();
  if (body_bytes.size() + kSnapshotHeaderBytes > limits.max_file_bytes) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "snapshot body of " + std::to_string(body_bytes.size()) +
                               " bytes exceeds the configured bound");
  }

  ByteBuffer out(kSnapshotHeaderBytes + body_bytes.size());
  std::memcpy(out.data() + kMagicOffset, kSnapshotMagic, sizeof(kSnapshotMagic));
  store_u16_le(out.data() + kFormatOffset, snapshot.format_version);
  store_u16_le(out.data() + kGenerationOffset, snapshot.persistence_generation);
  store_u64_le(out.data() + kBodyLengthOffset, static_cast<std::uint64_t>(body_bytes.size()));
  store_u64_le(out.data() + kEpochOffset, snapshot.epoch.value);
  store_u64_le(out.data() + kBootOffset, snapshot.boot.value);
  store_u64_le(out.data() + kSequenceOffset, snapshot.sequence_high_water);
  store_u64_le(out.data() + kWrittenAtOffset, snapshot.written_at_wall_millis);
  const auto digest = sha256(body_bytes.data(), body_bytes.size());
  std::memcpy(out.data() + kBodyDigestOffset, digest.data(), digest.size());
  if (!body_bytes.empty()) {
    std::memcpy(out.data() + kSnapshotHeaderBytes, body_bytes.data(), body_bytes.size());
  }
  store_u32_le(out.data() + kHeaderChecksumOffset, 0U);
  const std::uint32_t checksum = crc32(out.data(), kSnapshotHeaderBytes);
  store_u32_le(out.data() + kHeaderChecksumOffset, checksum);
  return out;
}

Result<StateSnapshot> decode_snapshot(const std::uint8_t* data, std::size_t size,
                                      const SnapshotLimits& limits) {
  if (size < kSnapshotHeaderBytes) {
    return Status::failure(ErrorCode::TRUNCATED_STATE,
                           "snapshot is " + std::to_string(size) +
                               " bytes, shorter than the " +
                               std::to_string(kSnapshotHeaderBytes) + " byte header");
  }
  if (std::memcmp(data + kMagicOffset, kSnapshotMagic, sizeof(kSnapshotMagic)) != 0) {
    return Status::failure(ErrorCode::CORRUPT_STATE, "snapshot does not begin with the AIFS magic");
  }
  const std::uint16_t format = load_u16_le(data + kFormatOffset);
  if (format != kSnapshotFormatVersion) {
    return Status::failure(ErrorCode::UNSUPPORTED_FORMAT_VERSION,
                           "snapshot format version " + std::to_string(format) +
                               " is not supported; this build writes and reads version " +
                               std::to_string(kSnapshotFormatVersion));
  }
  const std::uint16_t generation = load_u16_le(data + kGenerationOffset);
  if (generation != kPersistenceGeneration) {
    return Status::failure(ErrorCode::UNSUPPORTED_FORMAT_VERSION,
                           "snapshot persistence generation " + std::to_string(generation) +
                               " is not supported; this build writes and reads generation " +
                               std::to_string(kPersistenceGeneration));
  }
  const std::uint64_t body_length = load_u64_le(data + kBodyLengthOffset);
  if (body_length > limits.max_file_bytes) {
    return Status::failure(ErrorCode::CAPACITY_EXCEEDED,
                           "snapshot declares a body of " + std::to_string(body_length) +
                               " bytes, exceeding the bound of " +
                               std::to_string(limits.max_file_bytes));
  }
  if (body_length > size - kSnapshotHeaderBytes) {
    return Status::failure(ErrorCode::TRUNCATED_STATE,
                           "snapshot declares " + std::to_string(body_length) +
                               " body bytes but only " +
                               std::to_string(size - kSnapshotHeaderBytes) + " are present");
  }

  // Verify the header checksum first so that a corrupted header cannot steer the
  // digest check or the length check.
  {
    ByteBuffer header(data, data + kSnapshotHeaderBytes);
    const std::uint32_t declared = load_u32_le(header.data() + kHeaderChecksumOffset);
    store_u32_le(header.data() + kHeaderChecksumOffset, 0U);
    const std::uint32_t computed = crc32(header.data(), header.size());
    if (declared != computed) {
      return Status::failure(ErrorCode::INTEGRITY_FAILURE,
                             "snapshot header checksum mismatch: declared " +
                                 std::to_string(declared) + ", computed " +
                                 std::to_string(computed));
    }
  }

  // Then the body digest, over exactly the declared body length.
  {
    const auto computed = sha256(data + kSnapshotHeaderBytes, static_cast<std::size_t>(body_length));
    if (!constant_time_equal(computed.data(), data + kBodyDigestOffset, Digest256::kBytes)) {
      return Status::failure(ErrorCode::INTEGRITY_FAILURE,
                             "snapshot body digest does not match the header");
    }
  }

  // A snapshot image is exactly one header and one body, and the header states the body
  // length.  Bytes beyond it mean the file was appended to, or produced by something other
  // than this writer; a decoder that ignored them would accept a different file as if it
  // were the canonical image, which is the same rule the canonical record codecs apply to a
  // record with trailing bytes.
  if (static_cast<std::size_t>(body_length) != size - kSnapshotHeaderBytes) {
    return Status::failure(ErrorCode::TRAILING_GARBAGE,
                           "snapshot declares " + std::to_string(body_length) +
                               " body bytes but " +
                               std::to_string(size - kSnapshotHeaderBytes) +
                               " bytes follow the header; a snapshot image is exactly one "
                               "header and one body");
  }

  StateSnapshot snapshot;
  snapshot.format_version = format;
  snapshot.persistence_generation = generation;
  snapshot.epoch = CoordinatorEpoch{load_u64_le(data + kEpochOffset)};
  snapshot.boot = CoordinatorBootId{load_u64_le(data + kBootOffset)};
  snapshot.sequence_high_water = load_u64_le(data + kSequenceOffset);
  snapshot.written_at_wall_millis = load_u64_le(data + kWrittenAtOffset);

  BufferReader reader(data + kSnapshotHeaderBytes, static_cast<std::size_t>(body_length),
                      limits.codec.max_string_bytes);
  Result<std::uint8_t> schema = reader.get_u8();
  if (!schema) return schema.status();
  if (schema.value() != kSnapshotBodySchema) {
    return Status::failure(ErrorCode::UNSUPPORTED_FORMAT_VERSION,
                           "snapshot body schema " + std::to_string(schema.value()) +
                               " is not supported");
  }
  Result<ClassifierPolicy> policy = decode_policy(reader, limits.codec);
  if (!policy) return Status::failure(policy.code(), "snapshot policy: " + policy.message());
  snapshot.policy = policy.value();

  std::uint32_t count = 0;
  Status status = decode_collection(reader, limits.max_records_per_collection, "publishers", count);
  if (!status) return status;
  status = decode_records<PublisherRecord>(reader, count, "publisher", snapshot.publishers,
                                           [&](BufferReader& in) {
                                             return decode_publisher_record(in, limits.codec);
                                           });
  if (!status) return status;

  status = decode_collection(reader, limits.max_records_per_collection, "workloads", count);
  if (!status) return status;
  status = decode_records<WorkloadRecord>(reader, count, "workload", snapshot.workloads,
                                          [&](BufferReader& in) {
                                            return decode_workload_record(in, limits.codec);
                                          });
  if (!status) return status;

  status = decode_collection(reader, limits.max_records_per_collection, "contracts", count);
  if (!status) return status;
  status = decode_records<WorkloadContract>(reader, count, "contract", snapshot.contracts,
                                            [&](BufferReader& in) {
                                              return decode_contract(in, limits.codec);
                                            });
  if (!status) return status;

  status = decode_collection(reader, limits.max_records_per_collection, "flows", count);
  if (!status) return status;
  status = decode_records<FlowRecord>(reader, count, "flow", snapshot.flows,
                                      [](BufferReader& in) { return decode_flow_record(in); });
  if (!status) return status;

  status = decode_collection(reader, limits.max_records_per_collection, "evidence", count);
  if (!status) return status;
  status = decode_records<EvidenceRecord>(reader, count, "evidence", snapshot.evidence,
                                          [&](BufferReader& in) {
                                            return decode_evidence_record(in, limits.codec);
                                          });
  if (!status) return status;

  status = decode_collection(reader, limits.max_records_per_collection, "classifications", count);
  if (!status) return status;
  status = decode_records<Classification>(reader, count, "classification", snapshot.classifications,
                                          [&](BufferReader& in) {
                                            return decode_classification(in, limits.codec);
                                          });
  if (!status) return status;

  status = decode_collection(reader, limits.max_records_per_collection, "revocations", count);
  if (!status) return status;
  status = decode_records<RevocationRecord>(reader, count, "revocation", snapshot.revocations,
                                            [&](BufferReader& in) {
                                              return decode_revocation(in, limits.codec);
                                            });
  if (!status) return status;

  status = decode_collection(reader, limits.max_records_per_collection, "supersessions", count);
  if (!status) return status;
  status = decode_records<SupersessionRecord>(reader, count, "supersession", snapshot.supersessions,
                                              [&](BufferReader& in) {
                                                return decode_supersession(in, limits.codec);
                                              });
  if (!status) return status;

  // Nothing may follow the last collection: a trailing byte means the image was
  // produced by something other than this writer.
  status = reader.finish();
  if (!status) return status;

  return snapshot;
}

Status write_snapshot_file(std::string_view path, const StateSnapshot& snapshot,
                          const SnapshotLimits& limits) {
  StateSnapshot image = snapshot;
  image.written_at_wall_millis = wall_clock_unix_millis();
  Result<ByteBuffer> encoded = encode_snapshot(image, limits);
  if (!encoded) return encoded.status();
  return atomic_replace(path, encoded.value().data(), encoded.value().size());
}

Result<StateSnapshot> read_snapshot_file(std::string_view path, const SnapshotLimits& limits) {
  Result<ByteBuffer> bytes = read_all(path, limits.max_file_bytes);
  if (!bytes) return bytes.status();
  return decode_snapshot(bytes.value().data(), bytes.value().size(), limits);
}

Result<std::uint32_t> recover_orphan_temporaries(std::string_view directory,
                                                std::string_view prefix) {
  Result<std::vector<std::string>> entries = list_directory(directory);
  if (!entries) return entries.status();
  std::uint32_t removed = 0;
  for (const std::string& name : entries.value()) {
    if (name.find(prefix) == std::string::npos) continue;
    if (name.find(".tmp-") == std::string::npos) continue;
    const std::string full = std::string(directory) + "/" + name;
    Status status = remove_file(full);
    if (status) ++removed;
  }
  return removed;
}

}  // namespace aifc
