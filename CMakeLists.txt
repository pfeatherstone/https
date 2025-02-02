cmake_minimum_required(VERSION 3.13)
project(Http)

# Deps
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Boost)
find_package(OpenSSL REQUIRED)

# Lib
add_library(http 
  src/http_field.cpp
  src/http_message.cpp
  src/http_mime.cpp
  src/http_status.cpp)

target_link_libraries(http
  PUBLIC Boost::asio
  PUBLIC OpenSSL::SSL OpenSSL::Crypto)

target_compile_features(http PUBLIC cxx_std_17)