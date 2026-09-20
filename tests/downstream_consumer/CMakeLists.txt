cmake_minimum_required(VERSION 3.24)
project(AIFlowClassifierConsumer LANGUAGES CXX)

# An independent downstream consumer.  It is not part of any parent build: the point of
# this project is to prove that the installed package can be found and used by a project
# that has never seen this source tree.
find_package(AI_Flow_Classifier 1.0 REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE AIFlowClassifier::ai_flow_classifier)
set_target_properties(consumer PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
