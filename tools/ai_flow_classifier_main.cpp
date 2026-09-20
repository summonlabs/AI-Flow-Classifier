// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include <string>
#include <vector>

#include "cli.hpp"

int main(int argc, char** argv) {
  std::vector<std::string> arguments;
  arguments.reserve(argc > 0 ? static_cast<std::size_t>(argc - 1) : 0U);
  for (int i = 1; i < argc; ++i) {
    arguments.emplace_back(argv[i]);
  }
  return aifc::cli::run(arguments);
}
