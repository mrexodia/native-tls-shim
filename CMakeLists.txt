cmake_minimum_required(VERSION 3.21)
project(native_tls_shim VERSION 0.1.0 LANGUAGES C CXX)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
# When embedded via FetchContent/add_subdirectory, propagate the module path so
# sibling dependencies can transparently resolve find_package(OpenSSL).
if(NOT PROJECT_IS_TOP_LEVEL)
  set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" PARENT_SCOPE)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(NATIVE_TLS_SHIM_BACKEND "AUTO" CACHE STRING "TLS backend: AUTO|MBEDTLS|SCHANNEL|APPLE")
set_property(CACHE NATIVE_TLS_SHIM_BACKEND PROPERTY STRINGS AUTO MBEDTLS SCHANNEL APPLE)

option(NATIVE_TLS_SHIM_FETCH_MBEDTLS "Fetch MbedTLS with FetchContent" ON)
option(NATIVE_TLS_SHIM_BUILD_TESTS "Build integration tests" ${PROJECT_IS_TOP_LEVEL})
option(NATIVE_TLS_SHIM_BUILD_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(NATIVE_TLS_SHIM_ENABLE_INSTALL "Enable install/export rules" ${PROJECT_IS_TOP_LEVEL})

string(TOUPPER "${NATIVE_TLS_SHIM_BACKEND}" _backend)
if(_backend STREQUAL "AUTO")
  if(WIN32)
    set(_backend "SCHANNEL")
  elseif(APPLE)
    set(_backend "APPLE")
  else()
    set(_backend "MBEDTLS")
  endif()
endif()

set(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND "${_backend}")

if(_backend STREQUAL "SCHANNEL")
  message(WARNING "Schannel backend is not implemented yet; building mbedTLS backend with Schannel placeholders.")
  set(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND "MBEDTLS")
elseif(_backend STREQUAL "APPLE")
  message(WARNING "Apple Security backend is not implemented yet; building mbedTLS backend with Apple placeholders.")
  set(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND "MBEDTLS")
endif()

set(_mbedtls_targets)
if(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND STREQUAL "MBEDTLS")
  if(NATIVE_TLS_SHIM_FETCH_MBEDTLS)
    include(FetchContent)
    FetchContent_Declare(
      mbedtls
      GIT_REPOSITORY https://github.com/mrexodia/mbedtls.git
      GIT_TAG cmake-fixes-3.6
      GIT_SHALLOW TRUE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
    # mrexodia/mbedtls cmake-fixes-3.6 uses generated sources on Windows.
    set(GEN_FILES ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(mbedtls)
  else()
    find_package(MbedTLS REQUIRED)
  endif()

  if(TARGET mbedtls AND TARGET mbedx509 AND TARGET mbedcrypto)
    set(_mbedtls_targets mbedtls mbedx509 mbedcrypto)
  elseif(TARGET MbedTLS::mbedtls AND TARGET MbedTLS::mbedx509 AND TARGET MbedTLS::mbedcrypto)
    set(_mbedtls_targets MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
  else()
    message(FATAL_ERROR "Unable to resolve MbedTLS targets")
  endif()
endif()

add_library(native_tls_shim STATIC
  src/tls_backend.cpp
  src/tls_mbedtls.cpp
  src/tls_schannel.cpp
  src/tls_apple.cpp
)

add_library(native_tls_shim::native_tls_shim ALIAS native_tls_shim)

target_include_directories(native_tls_shim
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(NATIVE_TLS_SHIM_EFFECTIVE_BACKEND STREQUAL "MBEDTLS")
  target_link_libraries(native_tls_shim PRIVATE
    $<BUILD_INTERFACE:${_mbedtls_targets}>
    $<INSTALL_INTERFACE:MbedTLS::mbedtls;MbedTLS::mbedx509;MbedTLS::mbedcrypto>)
endif()

if(WIN32)
  target_link_libraries(native_tls_shim PRIVATE ws2_32)
endif()

target_compile_definitions(native_tls_shim
  PUBLIC
    OPENSSL_VERSION_NUMBER=0x30000000L
)

if(_backend STREQUAL "SCHANNEL")
  target_compile_definitions(native_tls_shim PUBLIC NATIVE_TLS_SHIM_BACKEND_SCHANNEL)
elseif(_backend STREQUAL "APPLE")
  target_compile_definitions(native_tls_shim PUBLIC NATIVE_TLS_SHIM_BACKEND_APPLE)
else()
  target_compile_definitions(native_tls_shim PUBLIC NATIVE_TLS_SHIM_BACKEND_MBEDTLS)
endif()

add_library(openssl_ssl INTERFACE)
add_library(openssl_crypto INTERFACE)

target_link_libraries(openssl_ssl INTERFACE native_tls_shim)
target_link_libraries(openssl_crypto INTERFACE native_tls_shim)

set_target_properties(openssl_ssl PROPERTIES EXPORT_NAME SSL)
set_target_properties(openssl_crypto PROPERTIES EXPORT_NAME Crypto)

if(NOT TARGET OpenSSL::SSL)
  add_library(OpenSSL::SSL ALIAS openssl_ssl)
endif()
if(NOT TARGET OpenSSL::Crypto)
  add_library(OpenSSL::Crypto ALIAS openssl_crypto)
endif()

if(NATIVE_TLS_SHIM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

if(NATIVE_TLS_SHIM_BUILD_EXAMPLES)
  add_subdirectory(example)
endif()

if(NATIVE_TLS_SHIM_ENABLE_INSTALL)
  install(TARGETS native_tls_shim openssl_ssl openssl_crypto
    EXPORT NativeTLSShimTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

  install(DIRECTORY openssl DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(EXPORT NativeTLSShimTargets
    FILE NativeTLSShimTargets.cmake
    NAMESPACE OpenSSL::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenSSL)

  configure_package_config_file(
    cmake/OpenSSLConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenSSL)

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)

  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSLConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/OpenSSL)
endif()
