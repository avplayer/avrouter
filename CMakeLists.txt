cmake_minimum_required(VERSION 2.8.9)

project(avrouter)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
set(CMAKE_COMPILER_IS_CLANGXX 1)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
if(UNIX)
set(CMAKE_COMPILER_IS_UNIX_ICC 1)
else()
# CMAKE_COMPILER_IS_WIN_ICC 的 c++11 模式命令行参数不一样
set(CMAKE_COMPILER_IS_WIN_ICC 1)
endif()
endif()

if(MSVC)
	set (Boost_USE_MULTITHREADED TRUE)
	set (Boost_USE_STATIC_LIBS TRUE)
endif()

option(BUILD_PRODUCTION "build for production" OFF)
if( BUILD_PRODUCTION )
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNO_TEST")
endif()

find_package(Threads REQUIRED)
find_package(Boost 1.54 COMPONENTS thread system coroutine context regex date_time chrono filesystem program_options REQUIRED)
find_package(Protobuf REQUIRED)
find_package(OpenSSL REQUIRED)

#pkg_check_modules(PKCS11 REQUIRED libpkcs11-helper-1 )

include_directories(${PROTOBUF_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
#include_directories(${PKCS11_INCLUDE_DIRS})
include_directories(include)
include_directories(proto_doc)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/proto_doc)

check_library_exists(rt clock_gettime "" HAVE_CLOCK_GETTIME)
if(HAVE_CLOCK_GETTIME)
        link_libraries(-lrt)
endif(HAVE_CLOCK_GETTIME)

link_directories(${Boost_LIB_DIRS})

link_libraries(${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} ${PKCS11_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
set(PostgreSQL_FIND_QUIETLY TRUE)
find_package(PostgreSQL REQUIRED)

find_library(SOCI_LIBRARY NAMES soci_core HINTS /usr/local/lib /usr/local/lib64 /usr/lib64 /usr/lib /usr/local/lib /usr/lib/soci/lib)
find_library(SOCI_PG_LIBRARY NAMES soci_postgresql HINTS /usr/local/lib /usr/local/lib64 /usr/lib64 /usr/lib /usr/lib/soci/lib)

find_path( SOCI_INCLUDE_DIRS connection-pool.h PATHS /usr/include/soci /usr/local/include/soci /opt/soci/include/soci)

if(NOT SOCI_LIBRARY)
message(FATAL_ERROR "SOCI library NOT FOUND!" )
endif()

if(NOT SOCI_PG_LIBRARY)
message(FATAL_ERROR "SOCI do not have postgresql backend!" )
endif()

include_directories( ${PostgreSQL_INCLUDE_DIRS} )
include_directories( ${SOCI_INCLUDE_DIRS} )

link_libraries(${SOCI_LIBRARY} ${SOCI_PG_LIBRARY} ${PostgreSQL_LIBRARIES})

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_CLANGXX OR CMAKE_COMPILER_IS_UNIX_ICC)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -DENABLE_LOGGER")
endif()

add_subdirectory(proto_doc)
add_subdirectory(src)

