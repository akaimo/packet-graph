cmake_minimum_required(VERSION 3.12)
project(packet-graph C)

set(CMAKE_C_STANDARD 99)

include_directories(/usr/local/include/graphviz)

add_executable(packet-graph main.c)

target_link_libraries(packet-graph cgraph)
