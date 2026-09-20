// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Command line tooling.
//
// The tool is thin by design: it parses arguments, drives the public API, and renders
// what the library decided.  It contains no classification logic, no threshold and no
// precedence rule, so a discrepancy between the tool and the library is impossible by
// construction.

#ifndef AIFC_CLI_HPP
#define AIFC_CLI_HPP

#include <string>
#include <vector>

namespace aifc::cli {

// Exit codes.  They are part of the tool's contract and are stable.
enum class ExitCode : int {
  kOk = 0,
  kUsageError = 64,
  kRuntimeError = 70,
  kAuthorityError = 77,
  kIntegrityError = 65,
  kNotRunning = 69,
  // A classification was produced but the flow is UNKNOWN.  Distinct from a failure so
  // that a script can tell "the runtime says it does not know" from "the runtime failed".
  kUnknownClass = 3,
};

struct Options {
  std::string command;
  std::string state_path;
  std::string policy_path;
  std::string output_format = "text";
  bool explain = false;
  bool verbose = false;
  std::vector<std::string> positional;
};

[[nodiscard]] int run(const std::vector<std::string>& arguments);
[[nodiscard]] std::string usage();

}  // namespace aifc::cli

#endif  // AIFC_CLI_HPP
