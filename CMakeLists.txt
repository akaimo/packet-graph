cmake_minimum_required(VERSION 3.12)
project(packet-graph)

set(CMAKE_CXX_STANDARD 14)

include_directories(/usr/local/include/graphviz)

add_executable(packet-graph main.cpp)

target_link_libraries(packet-graph cgraph)
