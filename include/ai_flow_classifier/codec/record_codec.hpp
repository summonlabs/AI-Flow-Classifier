// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Canonical codecs for the domain records.
//
// Every decoder in this file treats its input as hostile:
//
//   * the declared length of a nested structure is checked against the bytes that
//     remain before anything is reserved;
//   * string and blob lengths are checked against the effective limit;
//   * a record that decodes but leaves bytes behind is TRAILING_GARBAGE, not a
//     success;
//   * an unknown numeric code decodes to the weakest, not the strongest, value;
//   * a malformed semantic class label fails rather than becoming UNKNOWN, because
//     UNKNOWN is a legitimate classification and must not be reachable by sending
//     nonsense.

#ifndef AI_FLOW_CLASSIFIER_CODEC_RECORD_CODEC_HPP
#define AI_FLOW_CLASSIFIER_CODEC_RECORD_CODEC_HPP

#include <ostream>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "ai_flow_classifier/domain/classification.hpp"
#include "ai_flow_classifier/domain/evidence.hpp"
#include "ai_flow_classifier/domain/flow.hpp"
#include "ai_flow_classifier/domain/policy.hpp"
#include "ai_flow_classifier/domain/publisher.hpp"
#include "ai_flow_classifier/domain/workload.hpp"
#include "ai_flow_classifier/foundation/bytes.hpp"
#include "ai_flow_classifier/foundation/config.hpp"
#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

struct CodecLimits {
  std::uint32_t max_string_bytes = kMaxStringBytes;
  std::uint32_t max_blob_bytes = kMaxBlobBytes;
  std::uint32_t max_collection_count = kMaxCollectionCount;

  [[nodiscard]] static CodecLimits from(const ResourceLimits& limits) noexcept;
};

// --- primitives ------------------------------------------------------------

Status encode_flow_key(BufferWriter& writer, const FlowKey& key);
Result<FlowKey> decode_flow_key(BufferReader& reader);

Status encode_id128(BufferWriter& writer, const Id128& id);
Result<Id128> decode_id128(BufferReader& reader);

Status encode_digest(BufferWriter& writer, const Digest256& digest);
Result<Digest256> decode_digest(BufferReader& reader);

Status encode_confidence(BufferWriter& writer, Confidence confidence);
Result<Confidence> decode_confidence(BufferReader& reader);

// --- domain records --------------------------------------------------------

Status encode_evidence_record(BufferWriter& writer, const EvidenceRecord& record);
Result<EvidenceRecord> decode_evidence_record(BufferReader& reader, const CodecLimits& limits);

Status encode_flow_record(BufferWriter& writer, const FlowRecord& record);
Result<FlowRecord> decode_flow_record(BufferReader& reader);

Status encode_publisher_record(BufferWriter& writer, const PublisherRecord& record);
Result<PublisherRecord> decode_publisher_record(BufferReader& reader, const CodecLimits& limits);

Status encode_workload_record(BufferWriter& writer, const WorkloadRecord& record);
Result<WorkloadRecord> decode_workload_record(BufferReader& reader, const CodecLimits& limits);

Status encode_contract(BufferWriter& writer, const WorkloadContract& contract);
Result<WorkloadContract> decode_contract(BufferReader& reader, const CodecLimits& limits);

Status encode_classification(BufferWriter& writer, const Classification& classification);
Result<Classification> decode_classification(BufferReader& reader, const CodecLimits& limits);

Status encode_revocation(BufferWriter& writer, const RevocationRecord& record);
Result<RevocationRecord> decode_revocation(BufferReader& reader, const CodecLimits& limits);

Status encode_supersession(BufferWriter& writer, const SupersessionRecord& record);
Result<SupersessionRecord> decode_supersession(BufferReader& reader, const CodecLimits& limits);

Status encode_policy(BufferWriter& writer, const ClassifierPolicy& policy);
Result<ClassifierPolicy> decode_policy(BufferReader& reader, const CodecLimits& limits);

Status encode_classification_query(BufferWriter& writer, const FlowKey& key,
                                   FlowGeneration generation, bool explain);
Result<std::tuple<FlowKey, FlowGeneration, bool>> decode_classification_query(
    BufferReader& reader);

// Canonical text rendering of a classification result, used by the CLI and by the
// wire response for a human-readable explanation.  The rendering is a pure function
// of the classification, so identical decisions render identically.
[[nodiscard]] std::string render_classification_json(const Classification& classification);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_CODEC_RECORD_CODEC_HPP
