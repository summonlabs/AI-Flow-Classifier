// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Real independent OS process control for the multiprocess proof surface.
//
// The claim being proved is that the runtime behaves correctly when authority lives in a
// process that can die without warning.  Making that claim requires processes that really
// are separate: a thread that stops cooperating is not a killed process, and an in-process
// "restart" is not a restart.
//
// The helpers here spawn a child, capture its output to a file (so a failing child can be
// diagnosed from its own words), and kill it hard.

#ifndef AIFC_TEST_PROCESS_HPP
#define AIFC_TEST_PROCESS_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "ai_flow_classifier/foundation/errors.hpp"

namespace aifc_test {

// A child process running this same test binary in its child role.
// Owns a child process.  Destruction terminates a child that is still running: a test that fails
// early would otherwise leave an unbounded loop behind, holding the test binary open and making the
// next build fail with a link error rather than the actual failure.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess();
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;

  // Spawns: executable child_mode_argument extra_arguments...
  // Standard output and standard error are redirected to output_path so that a child that
  // fails can be diagnosed from its own messages.
  static aifc::Result<ChildProcess> spawn(const std::string& executable,
                                         const std::string& child_mode_argument,
                                         const std::vector<std::string>& extra_arguments,
                                         const std::string& working_directory,
                                         const std::string& output_path);

  // Waits for the child to exit on its own.  Returns its exit code.
  [[nodiscard]] aifc::Result<int> wait();

  // Terminates the child immediately.  This is the equivalent of a process crash for the
  // purpose of the test: no destructor runs, no flush happens, and the peer sees a reset.
  aifc::Status kill();

  [[nodiscard]] bool running() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] std::uint64_t process_id() const noexcept { return process_id_; }

  // Reads the child's captured output.  Used by a failure message.
  [[nodiscard]] std::string output() const;

  void close() noexcept;

 private:
  void* handle_ = nullptr;
  std::uint64_t process_id_ = 0;
  std::string output_path_;
};

// Waits until a condition holds, polling at a fixed interval, and gives up after a bound.
// Returns false on timeout.  This is a test-side helper: it never changes what the code
// under test does, it only decides how long the test is willing to wait for an external
// process to reach a state.
template <typename Predicate>
[[nodiscard]] bool wait_until(Predicate predicate, std::uint32_t attempts = 200,
                              std::uint32_t interval_millis = 25);

}  // namespace aifc_test

#include <chrono>
#include <thread>

namespace aifc_test {

template <typename Predicate>
bool wait_until(Predicate predicate, std::uint32_t attempts, std::uint32_t interval_millis) {
  for (std::uint32_t attempt = 0; attempt < attempts; ++attempt) {
    if (predicate()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(interval_millis));
  }
  return predicate();
}

}  // namespace aifc_test

#endif  // AIFC_TEST_PROCESS_HPP
