# native-tls-shim OpenSSL override module

if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
  set(OPENSSL_FOUND TRUE)
  set(OPENSSL_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/..")
  set(OPENSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
  set(OPENSSL_VERSION "3.0.0-native-tls-shim")
  return()
endif()

# Fallback to config mode for installed package usage.
find_package(OpenSSL CONFIG QUIET)
if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
  set(OPENSSL_FOUND TRUE)
  set(OPENSSL_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
  set(OPENSSL_VERSION "3.0.0-native-tls-shim")
endif()
