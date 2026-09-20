# Examples.  Each one executes a real supported path against the real library; none
# of them is a stub, and none of them is required by the test suite.

set(AIFC_EXAMPLE_TARGETS
  example_declared_classification
  example_contradiction
  example_heuristic_adapter
  example_end_to_end)

foreach(example IN LISTS AIFC_EXAMPLE_TARGETS)
  add_executable(${example} ${example}.cpp)
  target_link_libraries(${example} PRIVATE AIFlowClassifier::ai_flow_classifier)
  aifc_configure_target(${example})
  set_target_properties(${example} PROPERTIES OUTPUT_NAME "${example}")
endforeach()

install(TARGETS ${AIFC_EXAMPLE_TARGETS}
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
