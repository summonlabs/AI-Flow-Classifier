// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Entry point shared by every test binary.
//
// It lives in one place so that the multiprocess proof surface has exactly one way to put
// a binary into its child role, and so that a test binary which is spawned as a child never
// accidentally re-runs the whole suite.

#include <cstdio>
#include <cstring>

#include "test_framework.hpp"

// Provided by the multiprocess test translation unit when it is linked in.  A binary that
// does not implement the child role reports that clearly instead of silently running the
// whole suite and confusing its parent.
extern int aifc_run_child_role(int argc, char** argv);

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--aifc-child") == 0) {
      const int code = aifc_run_child_role(argc, argv);
      if (code < 0) {
        std::fprintf(stderr,
                     "this binary does not implement the child role; it was spawned "
                     "with --aifc-child by mistake\n");
        return 78;
      }
      return code;
    }
  }
  return aifc_test::run_all(argc, argv);
}
