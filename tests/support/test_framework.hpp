// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// A small deterministic test framework.
//
// Requirements this satisfies, and why each one is here:
//
//   * a failing assertion prints the file, line, expression and both rendered operand
//     values, because "expected equal" without the values is not a diagnosis;
//   * property tests print their reproduction seed on failure, so a randomized failure
//     can be replayed exactly;
//   * there is no timeout mechanism anywhere.  A hanging test is a defect in the code
//     under test, and the framework does not hide it;
//   * the process exit code is non-zero when anything failed, so CTest cannot be fooled.

#ifndef AIFC_TEST_FRAMEWORK_HPP
#define AIFC_TEST_FRAMEWORK_HPP

#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ai_flow_classifier/ai_flow_classifier.hpp"

namespace aifc_test {

struct Failure {
  std::string message;
};

class Registry {
 public:
  using Body = std::function<void()>;

  struct Case {
    std::string name;
    Body body;
  };

  static Registry& instance();

  void add(std::string name, Body body) { cases_.push_back(Case{std::move(name), std::move(body)}); }
  [[nodiscard]] const std::vector<Case>& cases() const noexcept { return cases_; }

  void fail(std::string message) { failures_.push_back(std::move(message)); }
  [[nodiscard]] const std::vector<std::string>& failures() const noexcept { return failures_; }
  void clear_failures() { failures_.clear(); }

 private:
  std::vector<Case> cases_;
  std::vector<std::string> failures_;
};

class Registrar {
 public:
  Registrar(const char* name, Registry::Body body) {
    Registry::instance().add(name, std::move(body));
  }
};

// Renders a value for a failure message.
//
// The generic overload is constrained to types that actually have a stream insertion operator.
// That constraint is what lets the specific overloads below win for the project's own types
// instead of the generic one being selected and then failing to compile -- which is exactly the
// failure mode a test framework must not have, because the diagnostic message is the last thing
// that should break.
namespace detail {
template <typename T>
concept Streamable = requires(std::ostream& stream, const T& value) { stream << value; };
}  // namespace detail

template <typename T>
  requires detail::Streamable<T>
[[nodiscard]] std::string render(const T& value) {
  std::ostringstream stream;
  stream << value;
  return stream.str();
}

[[nodiscard]] inline std::string render(bool value) { return value ? "true" : "false"; }
[[nodiscard]] inline std::string render(std::string_view value) { return std::string(value); }
[[nodiscard]] inline std::string render(const std::string& value) { return value; }
[[nodiscard]] inline std::string render(const char* value) {
  return value == nullptr ? std::string("<null>") : std::string(value);
}

// Types with no stream insertion operator are rendered through their canonical text, so a
// CHECK_EQ on a Status, an identity or a flow key still shows both operands.
template <typename T>
[[nodiscard]] std::string render(const aifc::Result<T>& result) {
  return result ? std::string("ok") : aifc::render_status(result.status());
}
[[nodiscard]] inline std::string render(const aifc::Status& status) {
  return aifc::render_status(status);
}
[[nodiscard]] inline std::string render(const aifc::FlowKey& key) { return key.to_string(); }
[[nodiscard]] inline std::string render(const aifc::Id128& id) { return id.to_hex(); }
[[nodiscard]] inline std::string render(const aifc::Digest256& digest) { return digest.to_hex(); }
[[nodiscard]] inline std::string render(const aifc::Confidence& confidence) {
  return confidence.to_decimal();
}
template <typename Tag>
[[nodiscard]] std::string render(const aifc::detail::StringId<Tag>& id) {
  return id.value();
}

// Runs every registered case, honouring --list, --filter=<substring> and --verbose.  Returns the
// number of failing cases so the process exit status reflects the result.
int run_all(int argc, char** argv);

// Stream insertion for the vocabulary and identity types is provided by the library itself
// (see foundation/text.hpp and each vocabulary header), so a test can write
// "message << some_class" and get the canonical name.  Nothing is redefined here on purpose:
// one definition, in the library, means a diagnostic in a test and a diagnostic in an
// application render identically.

}  // namespace aifc_test

#define AIFC_TEST_CONCAT_INNER(a, b) a##b
#define AIFC_TEST_CONCAT(a, b) AIFC_TEST_CONCAT_INNER(a, b)

// Declares and registers a test case.
#define AIFC_TEST(name)                                                            \
  static void AIFC_TEST_CONCAT(aifc_test_body_, __LINE__)();                       \
  static const ::aifc_test::Registrar AIFC_TEST_CONCAT(aifc_test_registrar_,        \
                                                       __LINE__)(name,             \
                                                                 AIFC_TEST_CONCAT( \
                                                                     aifc_test_body_, \
                                                                     __LINE__));       \
  static void AIFC_TEST_CONCAT(aifc_test_body_, __LINE__)()

#define AIFC_FAIL(message)                                                      \
  do {                                                                          \
    std::ostringstream aifc_fail_stream;                                        \
    aifc_fail_stream << __FILE__ << ":" << __LINE__ << ": " << message;         \
    ::aifc_test::Registry::instance().fail(aifc_fail_stream.str());             \
  } while (false)

#define AIFC_CHECK(expression)                                                            \
  do {                                                                                    \
    if (!(expression)) {                                                                  \
      AIFC_FAIL("CHECK failed: " #expression);                                            \
    }                                                                                     \
  } while (false)

#define AIFC_CHECK_MSG(expression, message)                                               \
  do {                                                                                    \
    if (!(expression)) {                                                                  \
      std::ostringstream aifc_stream;                                                     \
      aifc_stream << "CHECK failed: " #expression << " -- " << message;                   \
      AIFC_FAIL(aifc_stream.str());                                                       \
    }                                                                                     \
  } while (false)

#define AIFC_CHECK_EQ(left, right)                                                        \
  do {                                                                                    \
    const auto& aifc_left = (left);                                                       \
    const auto& aifc_right = (right);                                                     \
    if (!(aifc_left == aifc_right)) {                                                     \
      std::ostringstream aifc_stream;                                                     \
      aifc_stream << "CHECK_EQ failed: " #left " == " #right "\n      left  = "          \
                  << ::aifc_test::render(aifc_left) << "\n      right = "                 \
                  << ::aifc_test::render(aifc_right);                                     \
      AIFC_FAIL(aifc_stream.str());                                                       \
    }                                                                                     \
  } while (false)

#define AIFC_CHECK_NE(left, right)                                                        \
  do {                                                                                    \
    const auto& aifc_left = (left);                                                       \
    const auto& aifc_right = (right);                                                     \
    if (aifc_left == aifc_right) {                                                        \
      std::ostringstream aifc_stream;                                                     \
      aifc_stream << "CHECK_NE failed: " #left " != " #right " (both "                    \
                  << ::aifc_test::render(aifc_left) << ")";                               \
      AIFC_FAIL(aifc_stream.str());                                                       \
    }                                                                                     \
  } while (false)

// Result helpers.  These are separate macros so that a failure names the operation that was
// expected to succeed.
//
// Both aifc::Result<T> and aifc::Status are accepted, because the API deliberately mixes the
// two: an operation that cannot produce a value returns Status, and one that can returns
// Result.  A test author should not have to remember which is which to assert that it worked.
namespace aifc_test {
namespace detail {

[[nodiscard]] inline bool succeeded(const aifc::Status& status) noexcept { return status.ok(); }
template <typename T>
[[nodiscard]] inline bool succeeded(const aifc::Result<T>& result) noexcept { return result.ok(); }

[[nodiscard]] inline aifc::ErrorCode code_of(const aifc::Status& status) noexcept {
  return status.code;
}
template <typename T>
[[nodiscard]] inline aifc::ErrorCode code_of(const aifc::Result<T>& result) noexcept {
  return result.code();
}

[[nodiscard]] inline std::string describe(const aifc::Status& status) {
  return aifc::render_status(status);
}
template <typename T>
[[nodiscard]] inline std::string describe(const aifc::Result<T>& result) {
  return aifc::render_status(result.status());
}

}  // namespace detail
}  // namespace aifc_test

#define AIFC_CHECK_OK(expression)                                                           \
  do {                                                                                      \
    const auto& aifc_result = (expression);                                                 \
    if (!::aifc_test::detail::succeeded(aifc_result)) {                                     \
      std::ostringstream aifc_stream;                                                       \
      aifc_stream << "expected success from " #expression " but got "                       \
                  << ::aifc_test::detail::describe(aifc_result);                            \
      AIFC_FAIL(aifc_stream.str());                                                         \
    }                                                                                       \
  } while (false)

#define AIFC_CHECK_ERR(expression, expected_code)                                            \
  do {                                                                                       \
    const auto& aifc_result = (expression);                                                  \
    if (::aifc_test::detail::succeeded(aifc_result)) {                                        \
      AIFC_FAIL("expected failure " #expected_code " from " #expression " but it succeeded"); \
    } else if (::aifc_test::detail::code_of(aifc_result) != (expected_code)) {                \
      std::ostringstream aifc_stream;                                                         \
      aifc_stream << "expected " #expected_code " from " #expression " but got "              \
                  << ::aifc_test::detail::describe(aifc_result);                              \
      AIFC_FAIL(aifc_stream.str());                                                           \
    }                                                                                         \
  } while (false)

#endif  // AIFC_TEST_FRAMEWORK_HPP
