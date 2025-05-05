cmake_minimum_required(VERSION 3.13)
project(Http)

# Deps
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Boost)
include(fmtlib)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Lib
add_library(http 
  src/http_base64.cpp
  src/http_error.cpp
  src/http_message.cpp)

target_link_libraries(http
  PUBLIC Boost::asio
  PUBLIC OpenSSL::SSL OpenSSL::Crypto)

target_compile_features(http PUBLIC cxx_std_17)
target_include_directories(http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Example
add_executable(example test/example.cpp)
target_compile_features(example PUBLIC cxx_std_20)
target_compile_options(example PRIVATE)
target_link_options(example PUBLIC $<$<CONFIG:Release>:-s>)
target_link_libraries(example 
  PUBLIC Threads::Threads
  PUBLIC http
  PUBLIC fmt::fmt)