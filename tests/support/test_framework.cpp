// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "test_framework.hpp"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

namespace aifc_test {

Registry& Registry::instance() {
  static Registry registry;
  return registry;
}

int run_all(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  bool verbose = false;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--list") {
      list_only = true;
    } else if (argument == "--verbose") {
      verbose = true;
    } else if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    } else {
      std::cout << "unknown argument: " << argument << "\n";
      return 64;
    }
  }

  const std::vector<Registry::Case>& cases = Registry::instance().cases();
  if (list_only) {
    for (const Registry::Case& test_case : cases) {
      std::cout << test_case.name << "\n";
    }
    return 0;
  }

  std::size_t executed = 0;
  std::size_t failed_cases = 0;
  for (const Registry::Case& test_case : cases) {
    if (!filter.empty() && test_case.name.find(filter) == std::string::npos) continue;
    Registry::instance().clear_failures();
    ++executed;
    // A line per case on stderr, unbuffered and flushed.
    //
    // There are no timeouts anywhere in this suite, so a hanging case would otherwise be invisible:
    // the failing binary would sit there with an empty output file and no way to tell which case it
    // was in.  This line is the difference between diagnosing a hang and guessing at one.
    std::fprintf(stderr, "[ CASE ] %s\n", test_case.name.c_str());
    std::fflush(stderr);
    try {
      test_case.body();
    } catch (const Failure& failure) {
      Registry::instance().fail(std::string("uncaught Failure: ") + failure.message);
    } catch (const std::exception& error) {
      Registry::instance().fail(std::string("uncaught exception: ") + error.what());
    } catch (...) {
      Registry::instance().fail("uncaught non-standard exception");
    }
    const std::vector<std::string>& failures = Registry::instance().failures();
    if (failures.empty()) {
      if (verbose) std::cout << "[  PASS  ] " << test_case.name << "\n";
      continue;
    }
    ++failed_cases;
    std::cout << "[  FAIL  ] " << test_case.name << "\n";
    for (const std::string& failure : failures) {
      std::cout << "           " << failure << "\n";
    }
  }

  std::cout << (failed_cases == 0 ? "PASS" : "FAIL") << ": " << (executed - failed_cases) << "/"
            << executed << " cases passed";
  if (!filter.empty()) std::cout << " (filter=" << filter << ")";
  std::cout << "\n";
  return failed_cases == 0 ? 0 : 1;
}

}  // namespace aifc_test
