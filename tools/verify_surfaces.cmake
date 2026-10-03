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

# Repository hygiene gate that belongs to the same check: no committed source may
# name an absolute path on the machine that produced it.
#
# The detector is deliberately generic rather than a list of remembered bad strings:
# it matches any Windows drive-absolute path and then accepts only the
# machine-independent roots a portable source tree is allowed to name. A user
# profile directory is never in that list, so no account name has to be written
# down here -- the check cannot leak the very thing it forbids, and it keeps
# working on a machine whose paths this file has never seen.
set(ALLOWED_ABSOLUTE_ROOTS
  Windows
  "Program Files"
  "Program Files (x86)"
  ProgramData
  Temp
  CMake
  cmake)

# A drive-absolute path, preceded by a non-alphanumeric boundary so that the "s" of
# an https URL is not mistaken for a drive letter. The first path component is the
# only part a portable tree may name.
set(ABSOLUTE_PATH_PATTERN [=[[^A-Za-z0-9][A-Za-z]:[\\/]+[A-Za-z0-9_.][A-Za-z0-9_. -]*]=])

# A POSIX user home directory: the two conventional account roots.
set(USER_HOME_PATH_PATTERN [=[/(home|Users)/[A-Za-z0-9_.-]+]=])

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

  string(REGEX MATCHALL "${ABSOLUTE_PATH_PATTERN}" ABSOLUTE_MATCHES "${CONTENT}")
  foreach(match IN LISTS ABSOLUTE_MATCHES)
    # Strip the boundary character and the drive prefix, then keep everything up to
    # the next separator: that first component decides whether the path is allowed.
    string(REGEX REPLACE [=[^[^A-Za-z0-9][A-Za-z]:[\\/]+]=] "" ROOT_COMPONENT "${match}")
    string(REGEX REPLACE [=[[\\/].*$]=] "" ROOT_COMPONENT "${ROOT_COMPONENT}")
    list(FIND ALLOWED_ABSOLUTE_ROOTS "${ROOT_COMPONENT}" ROOT_INDEX)
    if(ROOT_INDEX EQUAL -1)
      list(APPEND VIOLATIONS "${file}: absolute local path '${match}'")
    endif()
  endforeach()

  if(CONTENT MATCHES "${USER_HOME_PATH_PATTERN}")
    list(APPEND VIOLATIONS "${file}: user home path '${CMAKE_MATCH_0}'")
  endif()
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
