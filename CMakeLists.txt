cmake_minimum_required(VERSION 3.10.2)
project(tls_demo VERSION 0.0.1)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_subdirectory(src/demo)
add_subdirectory(src/na_demo)
add_subdirectory(src/utah_demo)
