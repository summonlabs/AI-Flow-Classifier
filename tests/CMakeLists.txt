# Test suite.
#
# Every executable here is a proof surface.  They are independent binaries rather than one
# binary with a filter so that a crash, a hang or a sanitizer abort in one surface cannot mask
# another.  CTest registers them by name.
#
# No test carries a timeout.  A hanging test is a defect in the code under test, and a timeout
# parameter would hide it behind a passing build.
#
# AIFC_REQUIRE_ALL_SURFACES turns the "every surface must exist" rule into a configure error.
# It is ON by default so that a release cannot be built with a proof surface missing; a
# developer who is part-way through authoring one can set it OFF explicitly, and the release
# procedure in docs/release.md always leaves it ON.

option(AIFC_REQUIRE_ALL_SURFACES "Fail configuration when a proof surface is missing" ON)

add_library(aifc_test_support STATIC
  support/child_role.cpp
  support/process.cpp
  support/synthetic.cpp
  support/test_framework.cpp)
target_include_directories(aifc_test_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(aifc_test_support PUBLIC AIFlowClassifier::ai_flow_classifier)
aifc_configure_target(aifc_test_support)

set(AIFC_EXPECTED_TEST_SOURCES
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

set(AIFC_PRESENT_TEST_SOURCES "")
set(AIFC_MISSING_TEST_SOURCES "")
foreach(test_source IN LISTS AIFC_EXPECTED_TEST_SOURCES)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_source}")
    list(APPEND AIFC_PRESENT_TEST_SOURCES "${test_source}")
  else()
    list(APPEND AIFC_MISSING_TEST_SOURCES "${test_source}")
  endif()
endforeach()

if(AIFC_MISSING_TEST_SOURCES)
  if(AIFC_REQUIRE_ALL_SURFACES)
    message(FATAL_ERROR
      "missing proof surfaces: ${AIFC_MISSING_TEST_SOURCES}.  The release standard requires "
      "every listed surface to exist; configure with -DAIFC_REQUIRE_ALL_SURFACES=OFF only "
      "while a surface is being authored.")
  endif()
  message(STATUS "proof surfaces not yet present: ${AIFC_MISSING_TEST_SOURCES}")
endif()

foreach(test_source IN LISTS AIFC_PRESENT_TEST_SOURCES)
  get_filename_component(test_name "${test_source}" NAME_WE)
  # main.cpp is compiled into each binary rather than living in the support library, so that a
  # test which defines a strong child-role dispatcher always wins over the weak default: a weak
  # symbol is not reliably selected out of a static library.
  add_executable(${test_name} ${test_source} support/main.cpp)
  target_link_libraries(${test_name} PRIVATE aifc_test_support)
  # The support headers are found through the support directory rather than through the support
  # library's usage requirements, because the library is only linked after the target is
  # created and the include path must be visible to the target's own sources.
  target_include_directories(${test_name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/support")
  aifc_configure_target(${test_name})
  set_target_properties(${test_name} PROPERTIES OUTPUT_NAME "${test_name}")
  add_test(NAME ${test_name} COMMAND ${test_name})
  # Each test runs in its own directory so that a test which writes state cannot collide with
  # another one running in parallel.
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/run/${test_name}")
  set_tests_properties(${test_name} PROPERTIES
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/run/${test_name}")
endforeach()
