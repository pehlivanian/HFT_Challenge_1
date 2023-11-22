cmake_minimum_required(VERSION 3.27)

project(proto)

if (CMAKE_CXX_COMPILER_LOADED)
  message(STATUS "The C++ compiler ID is ${CMAKE_CXX_COMPILER_ID}")
  message(STATUS "The C++ compiler version is ${CMAKE_CXX_COMPILER_VERSION}")
endif()

set(CMAKE_CXX_FLAGS "-mavx2 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-03")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(client client.cpp)
