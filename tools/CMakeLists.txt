# Command line tooling.  These are thin wrappers: every decision they report comes
# from the installed library, and none of them contain classification logic.

add_executable(ai-flow-classifier
  ai_flow_classifier_main.cpp
  cli.cpp)

target_link_libraries(ai-flow-classifier PRIVATE AIFlowClassifier::ai_flow_classifier)
aifc_configure_target(ai-flow-classifier)
set_target_properties(ai-flow-classifier PROPERTIES OUTPUT_NAME "ai-flow-classifier")

if(AIFC_INSTALL_TOOLS)
  install(TARGETS ai-flow-classifier
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()
