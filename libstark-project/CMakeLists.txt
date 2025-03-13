cmake_minimum_required(VERSION 3.10)

project(LibSTARKProject)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)

file(GLOB SOURCES
    src/*.cpp
    src/randomness/*.cpp
    src/constraints/*.cpp
    src/proofs/*.cpp
    src/utils/*.cpp
)

add_executable(libstark ${SOURCES})