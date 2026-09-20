// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic error codes.  Nothing in this runtime returns a bare bool for an
// operation that can fail for more than one reason: callers receive an
// ErrorCode they can branch on and an ErrorClass that states whether the
// condition is permanent, retryable, an authority failure or a denial.

#ifndef AI_FLOW_CLASSIFIER_FOUNDATION_ERRORS_HPP
#define AI_FLOW_CLASSIFIER_FOUNDATION_ERRORS_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace aifc {

enum class ErrorCode : std::uint32_t {
  OK = 0,

  // --- input shape ---------------------------------------------------------
  INVALID_ARGUMENT = 1,
  MALFORMED_INPUT = 2,
  UNSUPPORTED_VERSION = 3,
  MALFORMED_FRAME = 4,
  MALFORMED_RECORD = 5,
  TRAILING_GARBAGE = 6,
  INTEGRITY_FAILURE = 7,
  CAPACITY_EXCEEDED = 8,
  ARITHMETIC_OVERFLOW = 9,
  OUT_OF_RANGE = 10,
  UNSUPPORTED_OPERATION = 11,
  COUNTER_EXHAUSTED = 12,

  // --- authority / provenance ---------------------------------------------
  UNAUTHENTICATED = 20,
  UNAUTHORIZED = 21,
  UNKNOWN_PUBLISHER = 22,
  UNKNOWN_WORKLOAD = 23,
  UNKNOWN_FLOW = 24,
  UNKNOWN_CONTRACT = 25,
  PUBLISHER_DEAD = 26,
  CONTRACT_MISMATCH = 27,
  CONTRACT_RETIRED = 28,
  EVIDENCE_WITHDRAWN = 29,
  VIA_UNTRUSTED_CHANNEL = 30,
  HEURISTIC_DISABLED = 31,

  // --- generation / epoch fencing -----------------------------------------
  STALE_GENERATION = 40,
  STALE_BOOT_ID = 41,
  STALE_EPOCH = 42,
  STALE_POLICY_GENERATION = 43,
  STALE_EVIDENCE = 44,
  REPLAY_DETECTED = 45,
  DUPLICATE_IDENTITY = 46,
  REVALIDATION_REQUIRED = 47,

  // --- classification -----------------------------------------------------
  CONTRADICTORY_EVIDENCE = 60,
  SUPERSEDED = 61,
  REVOKED = 62,
  EVIDENCE_INSUFFICIENT = 63,
  INSUFFICIENT_EVIDENCE = 64,

  // --- persistence --------------------------------------------------------
  IO_ERROR = 80,
  NOT_FOUND = 81,
  ALREADY_EXISTS = 82,
  CORRUPT_STATE = 83,
  TRUNCATED_STATE = 84,
  UNSUPPORTED_FORMAT_VERSION = 85,
  DURABILITY_FAILURE = 86,

  // --- lifecycle / concurrency --------------------------------------------
  NOT_RUNNING = 100,
  ALREADY_RUNNING = 101,
  SHUTTING_DOWN = 102,
  TIMEOUT = 103,
  CANCELLED = 104,
  CONNECTION_CLOSED = 105,
  CONNECTION_RESET = 106,
  BIND_FAILED = 107,
  UNREACHABLE = 108,
  SESSION_LIMIT = 109,
  AMBIGUOUS_COMPLETION = 110,

  // --- internal -----------------------------------------------------------
  INTERNAL_ERROR = 200,
};

enum class ErrorClass : std::uint8_t {
  NONE = 0,
  PERMANENT,   // the same input will always fail; do not retry
  RETRYABLE,   // the condition is transient; the same request may succeed later
  AUTHORITY,   // the caller or the evidence lacks current authority
  DENIAL,      // the request is understood and refused by policy
  RESOURCE,    // a bound was reached
  INTEGRITY,   // data was malformed, corrupt or unverifiable
  LIFECYCLE,   // the runtime is not in a state where the request is meaningful
  INTERNAL,    // a defect or an unclassified internal condition
};

struct Status {
  ErrorCode code = ErrorCode::OK;
  std::string message;

  [[nodiscard]] bool ok() const noexcept { return code == ErrorCode::OK; }
  explicit operator bool() const noexcept { return ok(); }

  static Status success() { return Status{}; }
  static Status failure(ErrorCode code, std::string message) {
    Status status;
    status.code = code;
    status.message = std::move(message);
    return status;
  }
};

template <typename T>
class Result {
 public:
  Result(Status status) : status_(std::move(status)) {}  // NOLINT: implicit by design
  Result(T value) : status_(Status::success()), value_(std::move(value)) {}  // NOLINT

  [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return ok(); }

  [[nodiscard]] const Status& status() const noexcept { return status_; }
  [[nodiscard]] ErrorCode code() const noexcept { return status_.code; }
  [[nodiscard]] const std::string& message() const noexcept { return status_.message; }

  [[nodiscard]] const T& value() const & { return value_; }
  [[nodiscard]] T& value() & { return value_; }
  [[nodiscard]] T&& value() && { return std::move(value_); }
  [[nodiscard]] const T* operator->() const { return &value_; }
  [[nodiscard]] T* operator->() { return &value_; }
  [[nodiscard]] const T& operator*() const & { return value_; }
  [[nodiscard]] T& operator*() & { return value_; }

 private:
  Status status_;
  T value_{};
};

// Compile time guarantee that Result<void> is not needed; a void helper is
// provided instead of a partial specialisation so that call sites stay explicit.
[[nodiscard]] inline Status ok_status() { return Status::success(); }

[[nodiscard]] std::string_view to_string(ErrorCode code) noexcept;
[[nodiscard]] std::string_view to_string(ErrorClass error_class) noexcept;
[[nodiscard]] ErrorClass classify(ErrorCode code) noexcept;

// True when the code reports that the request was well formed but lacked current
// authority.  Used by the CLI to choose exit codes and by tests to assert that a
// denial is an authority failure and not a parse failure.
[[nodiscard]] bool is_authority_failure(ErrorCode code) noexcept;

// Canonical deterministic text for an error, used by the CLI and by the protocol
// when an error must cross the wire.
[[nodiscard]] std::string render_status(const Status& status);

}  // namespace aifc

#endif  // AI_FLOW_CLASSIFIER_FOUNDATION_ERRORS_HPP
