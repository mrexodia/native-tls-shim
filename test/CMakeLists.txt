include(FetchContent)

set(_cpp_httplib_dir "${CMAKE_SOURCE_DIR}/test/cpp-httplib")
set(_ixws_dir "${CMAKE_SOURCE_DIR}/test/IXWebSocket")

# ---- cpp-httplib ----
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE ON CACHE BOOL "" FORCE)
set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_TEST OFF CACHE BOOL "" FORCE)
set(HTTPLIB_INSTALL OFF CACHE BOOL "" FORCE)

if(EXISTS "${_cpp_httplib_dir}/CMakeLists.txt")
  add_subdirectory("${_cpp_httplib_dir}" "${CMAKE_CURRENT_BINARY_DIR}/cpp-httplib" SYSTEM)
else()
  FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(cpp_httplib)
endif()

# ---- IXWebSocket ----
set(USE_TLS ON CACHE BOOL "" FORCE)
set(USE_OPEN_SSL ON CACHE BOOL "" FORCE)
set(USE_MBED_TLS OFF CACHE BOOL "" FORCE)
set(USE_SECURE_TRANSPORT OFF CACHE BOOL "" FORCE)
set(USE_ZLIB OFF CACHE BOOL "" FORCE)
set(BUILD_DEMO OFF CACHE BOOL "" FORCE)
set(OPENSSL_FOUND TRUE CACHE BOOL "" FORCE)
set(OPENSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}" CACHE PATH "" FORCE)
set(OPENSSL_LIBRARIES "OpenSSL::SSL;OpenSSL::Crypto" CACHE STRING "" FORCE)

if(EXISTS "${_ixws_dir}/CMakeLists.txt")
  add_subdirectory("${_ixws_dir}" "${CMAKE_CURRENT_BINARY_DIR}/IXWebSocket" SYSTEM)
else()
  FetchContent_Declare(
    ixwebsocket
    GIT_REPOSITORY https://github.com/machinezone/IXWebSocket.git
    GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(ixwebsocket)
endif()

enable_testing()

add_executable(test_httplib_client test_httplib_client.cpp)
target_compile_definitions(test_httplib_client PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(test_httplib_client PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_server test_httplib_server.cpp)
target_compile_definitions(test_httplib_server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_server PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_verify_disabled test_httplib_verify_disabled.cpp)
target_compile_definitions(test_httplib_verify_disabled PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_verify_disabled PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_peer_cert test_httplib_peer_cert.cpp)
target_compile_definitions(test_httplib_peer_cert PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_peer_cert PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_hostname_mismatch test_httplib_hostname_mismatch.cpp)
target_compile_definitions(test_httplib_hostname_mismatch PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_hostname_mismatch PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_in_memory_ca test_httplib_in_memory_ca.cpp)
target_compile_definitions(test_httplib_in_memory_ca PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_in_memory_ca PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_httplib_mtls test_httplib_mtls.cpp)
target_compile_definitions(test_httplib_mtls PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_httplib_mtls PRIVATE httplib::httplib OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_evp_hash test_evp_hash.cpp)
target_link_libraries(test_evp_hash PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_client test_ixwebsocket_client.cpp)
target_link_libraries(test_ixwebsocket_client PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_server test_ixwebsocket_server.cpp)
target_compile_definitions(test_ixwebsocket_server PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixwebsocket_server PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_verify_disabled test_ixwebsocket_verify_disabled.cpp)
target_compile_definitions(test_ixwebsocket_verify_disabled PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixwebsocket_verify_disabled PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixhttp_tls_matrix test_ixhttp_tls_matrix.cpp)
target_compile_definitions(test_ixhttp_tls_matrix PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixhttp_tls_matrix PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ixwebsocket_mtls test_ixwebsocket_mtls.cpp)
target_compile_definitions(test_ixwebsocket_mtls PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(test_ixwebsocket_mtls PRIVATE ixwebsocket OpenSSL::SSL OpenSSL::Crypto)

add_test(NAME test_httplib_client COMMAND test_httplib_client)
add_test(NAME test_httplib_server COMMAND test_httplib_server)
add_test(NAME test_httplib_verify_disabled COMMAND test_httplib_verify_disabled)
add_test(NAME test_httplib_peer_cert COMMAND test_httplib_peer_cert)
add_test(NAME test_httplib_hostname_mismatch COMMAND test_httplib_hostname_mismatch)
add_test(NAME test_httplib_in_memory_ca COMMAND test_httplib_in_memory_ca)
add_test(NAME test_httplib_mtls COMMAND test_httplib_mtls)
add_test(NAME test_evp_hash COMMAND test_evp_hash)
add_test(NAME test_ixwebsocket_client COMMAND test_ixwebsocket_client)
add_test(NAME test_ixwebsocket_server COMMAND test_ixwebsocket_server)
add_test(NAME test_ixwebsocket_verify_disabled COMMAND test_ixwebsocket_verify_disabled)
add_test(NAME test_ixhttp_tls_matrix COMMAND test_ixhttp_tls_matrix)
add_test(NAME test_ixwebsocket_mtls COMMAND test_ixwebsocket_mtls)

add_executable(debug_schannel_init debug_schannel_init.cpp)
target_compile_definitions(debug_schannel_init PRIVATE NTS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(debug_schannel_init PRIVATE OpenSSL::SSL OpenSSL::Crypto)
