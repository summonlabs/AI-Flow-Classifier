# AI Flow Classifier core library.
#
# The source list is explicit rather than globbed so that a file which stops being
# compiled is a visible change to this list, not a silent omission.

set(AIFC_CORE_SOURCES
  foundation/bytes.cpp
  foundation/clock.cpp
  foundation/config.cpp
  foundation/errors.cpp
  foundation/hash.cpp
  foundation/ids.cpp
  foundation/log.cpp
  foundation/math.cpp
  foundation/rng.cpp
  io/files.cpp
  domain/classification.cpp
  domain/evidence.cpp
  domain/flow.cpp
  domain/policy.cpp
  domain/publisher.cpp
  domain/semantic_class.cpp
  domain/workload.cpp
  store/classification_index.cpp
  store/evidence_store.cpp
  store/flow_registry.cpp
  store/publisher_registry.cpp
  store/workload_registry.cpp
  classify/classifier.cpp
  classify/decision_engine.cpp
  codec/record_codec.cpp
  protocol/frame.cpp
  protocol/messages.cpp
  state/snapshot.cpp
  net/channel.cpp
  net/tcp.cpp
  runtime/coordinator.cpp
  runtime/coordinator_service.cpp
)

set(AIFC_CORE_PUBLIC_HEADERS
  include/ai_flow_classifier/ai_flow_classifier.hpp
  include/ai_flow_classifier/foundation/bytes.hpp
  include/ai_flow_classifier/foundation/clock.hpp
  include/ai_flow_classifier/foundation/config.hpp
  include/ai_flow_classifier/foundation/errors.hpp
  include/ai_flow_classifier/foundation/hash.hpp
  include/ai_flow_classifier/foundation/ids.hpp
  include/ai_flow_classifier/foundation/log.hpp
  include/ai_flow_classifier/foundation/math.hpp
  include/ai_flow_classifier/foundation/rng.hpp
  include/ai_flow_classifier/foundation/text.hpp
  include/ai_flow_classifier/io/files.hpp
  include/ai_flow_classifier/domain/classification.hpp
  include/ai_flow_classifier/domain/evidence.hpp
  include/ai_flow_classifier/domain/flow.hpp
  include/ai_flow_classifier/domain/policy.hpp
  include/ai_flow_classifier/domain/publisher.hpp
  include/ai_flow_classifier/domain/semantic_class.hpp
  include/ai_flow_classifier/domain/workload.hpp
  include/ai_flow_classifier/store/classification_index.hpp
  include/ai_flow_classifier/store/evidence_store.hpp
  include/ai_flow_classifier/store/flow_registry.hpp
  include/ai_flow_classifier/store/publisher_registry.hpp
  include/ai_flow_classifier/store/workload_registry.hpp
  include/ai_flow_classifier/classify/classifier.hpp
  include/ai_flow_classifier/classify/decision_engine.hpp
  include/ai_flow_classifier/codec/record_codec.hpp
  include/ai_flow_classifier/protocol/frame.hpp
  include/ai_flow_classifier/protocol/messages.hpp
  include/ai_flow_classifier/state/snapshot.hpp
  include/ai_flow_classifier/net/channel.hpp
  include/ai_flow_classifier/net/tcp.hpp
  include/ai_flow_classifier/runtime/coordinator.hpp
  include/ai_flow_classifier/runtime/coordinator_service.hpp
)

add_library(ai_flow_classifier ${AIFC_CORE_SOURCES})
add_library(AIFlowClassifier::ai_flow_classifier ALIAS ai_flow_classifier)

# The public headers live at the repository root, beside the sources, so that an
# installed copy and the build tree present the same include path to consumers.
target_include_directories(ai_flow_classifier
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

set_target_properties(ai_flow_classifier PROPERTIES
  VERSION "${PROJECT_VERSION}"
  SOVERSION "${PROJECT_VERSION_MAJOR}"
  OUTPUT_NAME "ai_flow_classifier"
  POSITION_INDEPENDENT_CODE ON)

aifc_configure_target(ai_flow_classifier)

find_package(Threads REQUIRED)
target_link_libraries(ai_flow_classifier PUBLIC Threads::Threads)

# The loopback transport (net/tcp.cpp) is part of the core library, so the platform socket
# library is part of its link interface: without it every consumer of the transport -- the
# coordinator service, the protocol tests, the multiprocess tests -- fails to link with
# unresolved WSA* / socket / recv / send symbols.  It has to be PUBLIC (not PRIVATE) because
# this is a static library and the dependency is not recorded inside the archive.
if(WIN32)
  target_link_libraries(ai_flow_classifier PUBLIC ws2_32)
endif()

if(NOT MSVC)
  target_link_libraries(ai_flow_classifier PUBLIC ${CMAKE_DL_LIBS})
endif()

include(CheckCXXSourceCompiles)
include(CMakePushCheckState)
cmake_push_check_state()
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
check_cxx_source_compiles("int main(){return 0;}" AIFC_HAS_WORKING_COMPILER)
cmake_pop_check_state()
if(NOT AIFC_HAS_WORKING_COMPILER)
  message(FATAL_ERROR "the configured compiler cannot build a trivial C++ program")
endif()

# Sanitizer support is probed, never assumed.  When the probe fails the build
# reports UNSUPPORTED and does not add flags that would fail the link.
if(AIFC_ENABLE_SANITIZERS OR AIFC_ENABLE_TSAN)
  include(CheckCXXSourceCompiles)
  if(MSVC)
    set(AIFC_SANITIZER_FLAGS /fsanitize=address)
  else()
    set(AIFC_SANITIZER_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
  endif()
  aifc_probe_sanitizer(AIFC_SANITIZER_SUPPORTED "${AIFC_SANITIZER_FLAGS}")
  if(AIFC_SANITIZER_SUPPORTED)
    message(STATUS "sanitizers            : SUPPORTED (${AIFC_SANITIZER_FLAGS})")
    target_compile_options(ai_flow_classifier PUBLIC ${AIFC_SANITIZER_FLAGS})
    target_link_options(ai_flow_classifier PUBLIC ${AIFC_SANITIZER_FLAGS})
  else()
    message(STATUS "sanitizers            : UNSUPPORTED on this toolchain (probe failed); no sanitizer flags added")
  endif()
endif()

# --- installation ----------------------------------------------------------

install(TARGETS ai_flow_classifier
  EXPORT AIFlowClassifierTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# The public headers live at the repository root, not under src/.  Installing "include/..." here
# silently installed nothing, and the exported target then pointed at an include directory that did not
# exist in the prefix -- which configures happily and fails in the consumer, exactly where it is most
# expensive to find.
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../include/ai_flow_classifier"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")
