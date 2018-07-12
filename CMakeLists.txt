cmake_minimum_required(VERSION 3.5.1)
project(tls_demo VERSION 0.0.1)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

include(FindOpenSSL)

set(openssl_version_required "1.0.2h")
if(NOT ${OPENSSL_VERSION} STREQUAL ${openssl_version_required})     # VERSION_EQUAL misses the trailing letter
    message(FATAL_ERROR "Expected OpenSSL version ${openssl_version_required} but found ${OPENSSL_VERSION}")
endif()

add_subdirectory(src/demo)
add_subdirectory(src/na_demo)
add_subdirectory(src/utah_demo)
