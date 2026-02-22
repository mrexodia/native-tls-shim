#pragma once

/*
 * Minimal RSA compatibility header.
 *
 * native-tls-shim targets TLS APIs and OpenSSL 3.x code paths first.
 * Low-level RSA primitives are not implemented yet; this header exists so
 * projects that include <openssl/rsa.h> (e.g. Asio type glue) still compile.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rsa_st RSA;

void RSA_free(RSA* rsa);

#ifdef __cplusplus
}
#endif
