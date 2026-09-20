cmake_minimum_required(VERSION 3.24)

# ---------------------------------------------------------------------------
# AI Flow Classifier
#
# The project version is also the product version and the release tag:
#   AI Flow Classifier 1.0.0  <->  annotated tag v1.0.0
#
# Wire compatibility is tracked separately by AIFC_PROTOCOL_VERSION, and the
# persistence generation by AIFC_PERSISTENCE_GENERATION.  Neither is implied by
# the product version.
# ---------------------------------------------------------------------------
project(AI_Flow_Classifier
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral C++20 runtime for classifying network flows by AI workload semantics, provenance and generation-bound evidence"
  HOMEPAGE_URL "https://github.com/summonlabs/AI-Flow-Classifier"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT DEFINED CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()
if(NOT DEFINED CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
endif()
if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
endif()

include(AIFCCompilerOptions)

option(AIFC_BUILD_TOOLS "Build the ai-flow-classifier command line tooling" ON)
option(AIFC_BUILD_EXAMPLES "Build example programs" ON)
option(AIFC_BUILD_TESTS "Build the test suite" ON)
option(AIFC_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(AIFC_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer when the toolchain supports them" OFF)
option(AIFC_ENABLE_TSAN "Build with ThreadSanitizer when the toolchain supports it" OFF)
option(AIFC_INSTALL_TOOLS "Install the command line tooling" ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(AIFC_IS_TOP_LEVEL ON)
else()
  set(AIFC_IS_TOP_LEVEL OFF)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(src)

if(AIFC_BUILD_TOOLS)
  add_subdirectory(tools)
endif()

if(AIFC_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(AIFC_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(AIFC_IS_TOP_LEVEL)
  include(CTest)
endif()

# ---------------------------------------------------------------------------
# Packaging: a downstream project must be able to locate, link and run against
# an installed copy of this library with a plain find_package(AI_Flow_Classifier).
# ---------------------------------------------------------------------------
set(AIFC_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/AI_Flow_Classifier"
    CACHE STRING "Directory for the installed CMake package files")

install(EXPORT AIFlowClassifierTargets
  FILE AIFlowClassifierTargets.cmake
  NAMESPACE AIFlowClassifier::
  DESTINATION "${AIFC_INSTALL_CMAKEDIR}")

# The file names are derived from the package name, because that is what find_package() looks for:
# <PackageName>Config.cmake, or the lower-case form with "-config".  An earlier version installed
# "AIFlowClassifierConfig.cmake", which configures and installs perfectly and is then impossible to
# find -- the failure only appears when a downstream project tries to use the installed copy, which is
# exactly the case this repository validates.
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/AIFlowClassifierConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION "${AIFC_INSTALL_CMAKEDIR}")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion
  ARCH_INDEPENDENT)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  DESTINATION "${AIFC_INSTALL_CMAKEDIR}")

# The lower-case spelling is installed as well, so that find_package(ai_flow_classifier) -- which CMake
# also permits -- resolves to the same package rather than to nothing.
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  DESTINATION "${AIFC_INSTALL_CMAKEDIR}"
  RENAME "ai_flow_classifier-config.cmake")
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  DESTINATION "${AIFC_INSTALL_CMAKEDIR}"
  RENAME "ai_flow_classifier-config-version.cmake")

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/AI_Flow_Classifier"
  RENAME LICENSE)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/AI_Flow_Classifier"
  RENAME README.md)

message(STATUS "AI Flow Classifier ${PROJECT_VERSION}")
message(STATUS "  build type          : ${CMAKE_BUILD_TYPE}")
message(STATUS "  compiler            : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  warnings as errors  : ${AIFC_WARNINGS_AS_ERRORS}")
message(STATUS "  tools/examples/tests: ${AIFC_BUILD_TOOLS}/${AIFC_BUILD_EXAMPLES}/${AIFC_BUILD_TESTS}")
