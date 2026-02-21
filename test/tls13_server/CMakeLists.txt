cmake_minimum_required(VERSION 3.21)
project(tls13_only_server LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(NTS_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

set(NATIVE_TLS_SHIM_BACKEND "MBEDTLS" CACHE STRING "" FORCE)
set(NATIVE_TLS_SHIM_FETCH_MBEDTLS ON CACHE BOOL "" FORCE)
set(NATIVE_TLS_SHIM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(NATIVE_TLS_SHIM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(NATIVE_TLS_SHIM_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

add_subdirectory("${NTS_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/native_tls_shim" EXCLUDE_FROM_ALL)

add_executable(tls13_only_server main.cpp)
target_compile_definitions(tls13_only_server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_include_directories(tls13_only_server PRIVATE "${NTS_SOURCE_DIR}/test/cpp-httplib")
target_link_libraries(tls13_only_server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
