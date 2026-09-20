// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc {

std::string_view to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::OK:
      return "OK";
    case ErrorCode::INVALID_ARGUMENT:
      return "INVALID_ARGUMENT";
    case ErrorCode::MALFORMED_INPUT:
      return "MALFORMED_INPUT";
    case ErrorCode::UNSUPPORTED_VERSION:
      return "UNSUPPORTED_VERSION";
    case ErrorCode::MALFORMED_FRAME:
      return "MALFORMED_FRAME";
    case ErrorCode::MALFORMED_RECORD:
      return "MALFORMED_RECORD";
    case ErrorCode::TRAILING_GARBAGE:
      return "TRAILING_GARBAGE";
    case ErrorCode::INTEGRITY_FAILURE:
      return "INTEGRITY_FAILURE";
    case ErrorCode::CAPACITY_EXCEEDED:
      return "CAPACITY_EXCEEDED";
    case ErrorCode::ARITHMETIC_OVERFLOW:
      return "ARITHMETIC_OVERFLOW";
    case ErrorCode::OUT_OF_RANGE:
      return "OUT_OF_RANGE";
    case ErrorCode::UNSUPPORTED_OPERATION:
      return "UNSUPPORTED_OPERATION";
    case ErrorCode::COUNTER_EXHAUSTED:
      return "COUNTER_EXHAUSTED";
    case ErrorCode::UNAUTHENTICATED:
      return "UNAUTHENTICATED";
    case ErrorCode::UNAUTHORIZED:
      return "UNAUTHORIZED";
    case ErrorCode::UNKNOWN_PUBLISHER:
      return "UNKNOWN_PUBLISHER";
    case ErrorCode::UNKNOWN_WORKLOAD:
      return "UNKNOWN_WORKLOAD";
    case ErrorCode::UNKNOWN_FLOW:
      return "UNKNOWN_FLOW";
    case ErrorCode::UNKNOWN_CONTRACT:
      return "UNKNOWN_CONTRACT";
    case ErrorCode::PUBLISHER_DEAD:
      return "PUBLISHER_DEAD";
    case ErrorCode::CONTRACT_MISMATCH:
      return "CONTRACT_MISMATCH";
    case ErrorCode::CONTRACT_RETIRED:
      return "CONTRACT_RETIRED";
    case ErrorCode::EVIDENCE_WITHDRAWN:
      return "EVIDENCE_WITHDRAWN";
    case ErrorCode::VIA_UNTRUSTED_CHANNEL:
      return "VIA_UNTRUSTED_CHANNEL";
    case ErrorCode::HEURISTIC_DISABLED:
      return "HEURISTIC_DISABLED";
    case ErrorCode::STALE_GENERATION:
      return "STALE_GENERATION";
    case ErrorCode::STALE_BOOT_ID:
      return "STALE_BOOT_ID";
    case ErrorCode::STALE_EPOCH:
      return "STALE_EPOCH";
    case ErrorCode::STALE_POLICY_GENERATION:
      return "STALE_POLICY_GENERATION";
    case ErrorCode::STALE_EVIDENCE:
      return "STALE_EVIDENCE";
    case ErrorCode::REPLAY_DETECTED:
      return "REPLAY_DETECTED";
    case ErrorCode::DUPLICATE_IDENTITY:
      return "DUPLICATE_IDENTITY";
    case ErrorCode::REVALIDATION_REQUIRED:
      return "REVALIDATION_REQUIRED";
    case ErrorCode::CONTRADICTORY_EVIDENCE:
      return "CONTRADICTORY_EVIDENCE";
    case ErrorCode::SUPERSEDED:
      return "SUPERSEDED";
    case ErrorCode::REVOKED:
      return "REVOKED";
    case ErrorCode::EVIDENCE_INSUFFICIENT:
      return "EVIDENCE_INSUFFICIENT";
    case ErrorCode::INSUFFICIENT_EVIDENCE:
      return "INSUFFICIENT_EVIDENCE";
    case ErrorCode::IO_ERROR:
      return "IO_ERROR";
    case ErrorCode::NOT_FOUND:
      return "NOT_FOUND";
    case ErrorCode::ALREADY_EXISTS:
      return "ALREADY_EXISTS";
    case ErrorCode::CORRUPT_STATE:
      return "CORRUPT_STATE";
    case ErrorCode::TRUNCATED_STATE:
      return "TRUNCATED_STATE";
    case ErrorCode::UNSUPPORTED_FORMAT_VERSION:
      return "UNSUPPORTED_FORMAT_VERSION";
    case ErrorCode::DURABILITY_FAILURE:
      return "DURABILITY_FAILURE";
    case ErrorCode::NOT_RUNNING:
      return "NOT_RUNNING";
    case ErrorCode::ALREADY_RUNNING:
      return "ALREADY_RUNNING";
    case ErrorCode::SHUTTING_DOWN:
      return "SHUTTING_DOWN";
    case ErrorCode::TIMEOUT:
      return "TIMEOUT";
    case ErrorCode::CANCELLED:
      return "CANCELLED";
    case ErrorCode::CONNECTION_CLOSED:
      return "CONNECTION_CLOSED";
    case ErrorCode::CONNECTION_RESET:
      return "CONNECTION_RESET";
    case ErrorCode::BIND_FAILED:
      return "BIND_FAILED";
    case ErrorCode::UNREACHABLE:
      return "UNREACHABLE";
    case ErrorCode::SESSION_LIMIT:
      return "SESSION_LIMIT";
    case ErrorCode::AMBIGUOUS_COMPLETION:
      return "AMBIGUOUS_COMPLETION";
    case ErrorCode::INTERNAL_ERROR:
      return "INTERNAL_ERROR";
  }
  return "UNRECOGNIZED_ERROR_CODE";
}

std::string_view to_string(ErrorClass error_class) noexcept {
  switch (error_class) {
    case ErrorClass::NONE:
      return "NONE";
    case ErrorClass::PERMANENT:
      return "PERMANENT";
    case ErrorClass::RETRYABLE:
      return "RETRYABLE";
    case ErrorClass::AUTHORITY:
      return "AUTHORITY";
    case ErrorClass::DENIAL:
      return "DENIAL";
    case ErrorClass::RESOURCE:
      return "RESOURCE";
    case ErrorClass::INTEGRITY:
      return "INTEGRITY";
    case ErrorClass::LIFECYCLE:
      return "LIFECYCLE";
    case ErrorClass::INTERNAL:
      return "INTERNAL";
  }
  return "UNRECOGNIZED_ERROR_CLASS";
}

ErrorClass classify(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::OK:
      return ErrorClass::NONE;

    case ErrorCode::MALFORMED_INPUT:
    case ErrorCode::MALFORMED_FRAME:
    case ErrorCode::MALFORMED_RECORD:
    case ErrorCode::TRAILING_GARBAGE:
    case ErrorCode::INTEGRITY_FAILURE:
    case ErrorCode::UNSUPPORTED_VERSION:
    case ErrorCode::CORRUPT_STATE:
    case ErrorCode::TRUNCATED_STATE:
    case ErrorCode::UNSUPPORTED_FORMAT_VERSION:
      return ErrorClass::INTEGRITY;

    case ErrorCode::UNAUTHENTICATED:
    case ErrorCode::UNAUTHORIZED:
    case ErrorCode::UNKNOWN_PUBLISHER:
    case ErrorCode::UNKNOWN_WORKLOAD:
    case ErrorCode::UNKNOWN_CONTRACT:
    case ErrorCode::PUBLISHER_DEAD:
    case ErrorCode::CONTRACT_MISMATCH:
    case ErrorCode::CONTRACT_RETIRED:
    case ErrorCode::EVIDENCE_WITHDRAWN:
    case ErrorCode::VIA_UNTRUSTED_CHANNEL:
    case ErrorCode::STALE_GENERATION:
    case ErrorCode::STALE_BOOT_ID:
    case ErrorCode::STALE_EPOCH:
    case ErrorCode::STALE_POLICY_GENERATION:
    case ErrorCode::STALE_EVIDENCE:
    case ErrorCode::REPLAY_DETECTED:
    case ErrorCode::DUPLICATE_IDENTITY:
    case ErrorCode::REVALIDATION_REQUIRED:
    case ErrorCode::SUPERSEDED:
      return ErrorClass::AUTHORITY;

    case ErrorCode::HEURISTIC_DISABLED:
    case ErrorCode::REVOKED:
    case ErrorCode::CONTRADICTORY_EVIDENCE:
      return ErrorClass::DENIAL;

    case ErrorCode::CAPACITY_EXCEEDED:
    case ErrorCode::ARITHMETIC_OVERFLOW:
    case ErrorCode::OUT_OF_RANGE:
    case ErrorCode::COUNTER_EXHAUSTED:
    case ErrorCode::SESSION_LIMIT:
      return ErrorClass::RESOURCE;

    case ErrorCode::TIMEOUT:
    case ErrorCode::CONNECTION_RESET:
    case ErrorCode::UNREACHABLE:
    case ErrorCode::AMBIGUOUS_COMPLETION:
      return ErrorClass::RETRYABLE;

    case ErrorCode::NOT_RUNNING:
    case ErrorCode::ALREADY_RUNNING:
    case ErrorCode::SHUTTING_DOWN:
    case ErrorCode::CANCELLED:
    case ErrorCode::CONNECTION_CLOSED:
      return ErrorClass::LIFECYCLE;

    case ErrorCode::INVALID_ARGUMENT:
    case ErrorCode::UNSUPPORTED_OPERATION:
    case ErrorCode::UNKNOWN_FLOW:
    case ErrorCode::EVIDENCE_INSUFFICIENT:
    case ErrorCode::INSUFFICIENT_EVIDENCE:
    case ErrorCode::NOT_FOUND:
    case ErrorCode::ALREADY_EXISTS:
    case ErrorCode::IO_ERROR:
    case ErrorCode::DURABILITY_FAILURE:
    case ErrorCode::BIND_FAILED:
      return ErrorClass::PERMANENT;

    case ErrorCode::INTERNAL_ERROR:
      return ErrorClass::INTERNAL;
  }
  return ErrorClass::INTERNAL;
}

bool is_authority_failure(ErrorCode code) noexcept { return classify(code) == ErrorClass::AUTHORITY; }

std::string render_status(const Status& status) {
  std::string out;
  out.reserve(64 + status.message.size());
  out += to_string(status.code);
  out += '(';
  out += to_string(classify(status.code));
  out += ')';
  if (!status.message.empty()) {
    out += ": ";
    out += status.message;
  }
  return out;
}

}  // namespace aifc
