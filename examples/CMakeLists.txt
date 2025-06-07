cmake_minimum_required(VERSION 3.13)
project(Http)

# Deps
include(FetchContent)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

if(POLICY CMP0135)
   cmake_policy(SET CMP0135 OLD)
endif()
set(BOOST_INCLUDE_LIBRARIES compat asio)
set(BOOST_ENABLE_CMAKE ON)
FetchContent_Declare(
  Boost
  URL "https://github.com/boostorg/boost/releases/download/boost-1.88.0/boost-1.88.0-cmake.tar.xz"
  URL_HASH MD5=3edffaacd2cfe63c240ef1b99497c74f)
FetchContent_MakeAvailable(Boost)

# Lib
add_library(http ${CMAKE_CURRENT_SOURCE_DIR}/../src/http.cpp)
target_compile_features(http PUBLIC cxx_std_17)
target_include_directories(http PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(http PUBLIC OpenSSL::SSL OpenSSL::Crypto Boost::asio)

# Examples
function(add_executable_20 target_name)
  add_executable(${target_name} ${ARGN})
  target_compile_features(${target_name} PUBLIC cxx_std_20)
  target_link_options(${target_name} PUBLIC $<$<CONFIG:Release>:-s>)
  target_link_libraries(${target_name} PUBLIC Threads::Threads http)
endfunction()

function(add_executable_coro target_name)
  add_executable(${target_name} ${ARGN})
  target_link_options(${target_name} PRIVATE $<$<CONFIG:Release>:-s>)
  target_link_libraries(${target_name} PRIVATE Threads::Threads Boost::compat http)
endfunction()

add_executable_20(server              ${CMAKE_CURRENT_SOURCE_DIR}/server.cpp)
add_executable_20(client_http         ${CMAKE_CURRENT_SOURCE_DIR}/client_http.cpp ${CMAKE_CURRENT_SOURCE_DIR}/extra/yyjson.c)
add_executable_20(client_ws_awaitable ${CMAKE_CURRENT_SOURCE_DIR}/client_ws_awaitable.cpp)
add_executable_coro(client_ws_coro    ${CMAKE_CURRENT_SOURCE_DIR}/client_ws_coro.cpp)

# Unit tests
add_executable(tests
  unit_tests/main.cpp
  unit_tests/base64.cpp
  unit_tests/sha1.cpp
  unit_tests/message.cpp
  unit_tests/async.cpp)
target_link_options(tests PRIVATE $<$<CONFIG:Release>:-s>)
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/extra)
target_link_libraries(tests PRIVATE http)