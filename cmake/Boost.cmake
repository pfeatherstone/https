if(POLICY CMP0135)
   cmake_policy(SET CMP0135 OLD)
endif()
include(FetchContent)
set(BOOST_INCLUDE_LIBRARIES asio)
set(BOOST_ENABLE_CMAKE ON)
set(BOOST_ASIO_DISABLE_BOOST_COROUTINE ON)
FetchContent_Declare(
  Boost
  URL "https://github.com/boostorg/boost/releases/download/boost-1.87.0/boost-1.87.0-cmake.tar.xz"
  URL_HASH MD5=d55d43218e81ca3d0fc14436b7665bf1)
FetchContent_MakeAvailable(Boost)