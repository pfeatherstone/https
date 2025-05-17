cmake_minimum_required(VERSION 3.13)
project(Http)

# Deps
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Boost)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Lib
add_library(http src/http.cpp)
target_compile_features(http PUBLIC cxx_std_17)
target_include_directories(http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(http
  PUBLIC Boost::asio
  PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Examples
add_executable(example test/example.cpp)
target_compile_features(example PUBLIC cxx_std_20)
target_link_options(example PUBLIC $<$<CONFIG:Release>:-s>)
target_link_libraries(example 
  PUBLIC Threads::Threads
  PUBLIC http)

add_executable(example_ssl test/example_ssl.cpp)
target_compile_features(example_ssl PUBLIC cxx_std_20)
target_link_options(example_ssl PUBLIC $<$<CONFIG:Release>:-s>)
target_link_libraries(example_ssl 
  PUBLIC Threads::Threads
  PUBLIC http)