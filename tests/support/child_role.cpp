// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Default child-role dispatcher.
//
// Every test binary links a definition of aifc_run_child_role so that the shared main() can
// reference it unconditionally.  The multiprocess test translation unit provides a stronger
// definition for its own binary only, so the other surfaces never acquire a child mode they
// do not implement.

#include <cstddef>

#if defined(_MSC_VER)
#define AIFC_WEAK
#else
#define AIFC_WEAK __attribute__((weak))
#endif

AIFC_WEAK int aifc_run_child_role(int argc, char** argv);

AIFC_WEAK int aifc_run_child_role(int argc, char** argv) {
  (void)argc;
  (void)argv;
  return -1;
}
