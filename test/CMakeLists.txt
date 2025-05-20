cmake_minimum_required(VERSION 3.13)
project(Http)

# Deps
include(FetchContent)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

if(POLICY CMP0135)
   cmake_policy(SET CMP0135 OLD)
endif()
set(BOOST_INCLUDE_LIBRARIES asio)
set(BOOST_ENABLE_CMAKE ON)
set(BOOST_ASIO_DISABLE_BOOST_COROUTINE ON)
FetchContent_Declare(
  Boost
  URL "https://github.com/boostorg/boost/releases/download/boost-1.88.0/boost-1.88.0-cmake.tar.xz"
  URL_HASH MD5=3edffaacd2cfe63c240ef1b99497c74f)
FetchContent_MakeAvailable(Boost)

# Lib
add_library(http ${CMAKE_CURRENT_SOURCE_DIR}/../src/http.cpp)
target_compile_features(http PUBLIC cxx_std_17)
target_include_directories(http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(http
  PUBLIC Boost::asio
  PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Examples
add_executable(example ${CMAKE_CURRENT_SOURCE_DIR}/example.cpp)
target_compile_features(example PUBLIC cxx_std_20)
target_link_options(example PUBLIC $<$<CONFIG:Release>:-s>)
target_link_libraries(example 
  PUBLIC Threads::Threads
  PUBLIC http)