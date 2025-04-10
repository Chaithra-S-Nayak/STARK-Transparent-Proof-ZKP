cmake_minimum_required(VERSION 3.10)

project(libSTARK)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/src)

# Source files
set(RANDOMNESS_SOURCES
    src/randomness/public_randomness.cpp
)

set(CONSTRAINTS_SOURCES
    src/constraints/polynomial_constraints.cpp
)

# Randomness library
add_library(randomness STATIC ${RANDOMNESS_SOURCES})
target_link_libraries(randomness ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})

# Constraints library
add_library(constraints STATIC ${CONSTRAINTS_SOURCES})
target_link_libraries(constraints ${OPENSSL_LIBRARIES})

# Test executable
add_executable(test_constraints src/constraints/test_polynomial_constraints.cpp)
target_link_libraries(test_constraints randomness constraints ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})