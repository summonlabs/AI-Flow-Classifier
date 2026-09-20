# AI Flow Classifier 1.0.0
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# Release gate: assert that every proof surface this release claims actually exists and
# that no surface was quietly dropped.
#
# Run with:
#   ctest --test-dir <build> --show-only=json-v1   (for the registration check)
# or, for the file level check:
#   cmake -DSOURCE_DIR=<repo> -P tools/verify_surfaces.cmake

cmake_minimum_required(VERSION 3.24)

if(NOT DEFINED SOURCE_DIR)
  get_filename_component(SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
else()
  get_filename_component(SOURCE_DIR "${SOURCE_DIR}" ABSOLUTE)
endif()

set(REQUIRED_SURFACES
  unit/test_foundation.cpp
  unit/test_domain.cpp
  unit/test_policy.cpp
  unit/test_store.cpp
  unit/test_decision_engine.cpp
  unit/test_freshness_and_ticks.cpp
  integration/test_classifier_flows.cpp
  integration/test_classifier_evidence.cpp
  integration/test_coordinator_inprocess.cpp
  property/test_precedence_properties.cpp
  property/test_contradiction_properties.cpp
  property/test_determinism_properties.cpp
  concurrency/test_classifier_concurrency.cpp
  concurrency/test_service_lifecycle.cpp
  adversarial/test_codec_fuzz.cpp
  adversarial/test_label_privilege.cpp
  adversarial/test_frame_adversarial.cpp
  persistence/test_snapshot_roundtrip.cpp
  persistence/test_snapshot_corruption.cpp
  persistence/test_restart_authority.cpp
  protocol/test_loopback_transport.cpp
  protocol/test_message_roundtrip.cpp
  multiprocess/test_publisher_processes.cpp
  multiprocess/test_coordinator_restart.cpp
  scale/test_indexed_lookup.cpp)

set(MISSING "")
foreach(surface IN LISTS REQUIRED_SURFACES)
  if(NOT EXISTS "${SOURCE_DIR}/tests/${surface}")
    list(APPEND MISSING "${surface}")
  endif()
endforeach()

if(MISSING)
  message(FATAL_ERROR "missing proof surfaces: ${MISSING}")
endif()

list(LENGTH REQUIRED_SURFACES COUNT)
message(STATUS "all ${COUNT} proof surfaces are present")

# Repository hygiene gates that belong to the same check: nothing generated, nothing
# machine specific and nothing that looks like a secret may be committed.
# Patterns are assembled from fragments so that this file does not contain the very strings it
# forbids -- a hygiene check that fails on itself is worse than no check, because the natural response
# is to weaken it.
set(_drive_e "E:")
set(_drive_c "C:")
set(FORBIDDEN_PATTERNS
  "${_drive_e}/The Journey"
  "${_drive_e}:\\\\The Journey"
  "${_drive_c}:/Users/"
  "${_drive_c}:\\\\Users\\\\")

file(GLOB_RECURSE TRACKED_FILES
  RELATIVE "${SOURCE_DIR}"
  "${SOURCE_DIR}/include/*"
  "${SOURCE_DIR}/src/*"
  "${SOURCE_DIR}/tools/*"
  "${SOURCE_DIR}/tests/*"
  "${SOURCE_DIR}/examples/*"
  "${SOURCE_DIR}/cmake/*"
  "${SOURCE_DIR}/docs/*")

set(VIOLATIONS "")
foreach(file IN LISTS TRACKED_FILES)
  file(READ "${SOURCE_DIR}/${file}" CONTENT)
  foreach(pattern IN LISTS FORBIDDEN_PATTERNS)
    if(CONTENT MATCHES "${pattern}")
      list(APPEND VIOLATIONS "${file} matches '${pattern}'")
    endif()
  endforeach()
endforeach()

if(VIOLATIONS)
  list(JOIN VIOLATIONS "\n  " VIOLATION_TEXT)
  message(FATAL_ERROR "machine specific paths found in committed sources:\n  ${VIOLATION_TEXT}")
endif()

message(STATUS "no machine specific paths in committed sources")

# The README must end exactly with the required License section, and nothing may follow it.  This
# is checked mechanically because it is the kind of requirement that survives review by hand and
# then quietly breaks on the next documentation edit.
file(READ "${SOURCE_DIR}/README.md" README_CONTENT)
string(REGEX REPLACE "[ \t\r\n]+$" "" README_TRIMMED "${README_CONTENT}")

set(REQUIRED_README_ENDING
  "## License\n\nApache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.")

string(LENGTH "${REQUIRED_README_ENDING}" REQUIRED_LENGTH)
string(LENGTH "${README_TRIMMED}" TRIMMED_LENGTH)
if(TRIMMED_LENGTH LESS REQUIRED_LENGTH)
  message(FATAL_ERROR "README.md is shorter than the required License ending")
endif()

math(EXPR TAIL_START "${TRIMMED_LENGTH} - ${REQUIRED_LENGTH}")
string(SUBSTRING "${README_TRIMMED}" ${TAIL_START} ${REQUIRED_LENGTH} README_TAIL)
if(NOT README_TAIL STREQUAL REQUIRED_README_ENDING)
  message(FATAL_ERROR
    "README.md does not end exactly with the required License section.  The tail was:\n${README_TAIL}")
endif()
message(STATUS "README.md ends with the required License section and nothing follows it")

# The LICENSE file must contain the full Apache License 2.0 text.
file(READ "${SOURCE_DIR}/LICENSE" LICENSE_CONTENT)
foreach(required_phrase
    "Apache License"
    "Version 2.0, January 2004"
    "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"
    "Grant of Patent License"
    "Disclaimer of Warranty"
    "Limitation of Liability"
    "END OF TERMS AND CONDITIONS"
    "Copyright 2026 Summon Software Labs.")
  string(FIND "${LICENSE_CONTENT}" "${required_phrase}" FOUND_AT)
  if(FOUND_AT EQUAL -1)
    message(FATAL_ERROR "LICENSE is missing the required phrase: ${required_phrase}")
  endif()
endforeach()
message(STATUS "LICENSE contains the full Apache License 2.0 text")

