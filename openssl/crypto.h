#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void* OPENSSL_malloc(size_t size);
void  OPENSSL_free(void* ptr);
void  OPENSSL_cleanse(void* ptr, size_t len);
void  OPENSSL_thread_stop(void);

/* Legacy OpenSSL 1.0 thread API stubs */
#define CRYPTO_LOCK 1

int   CRYPTO_num_locks(void);
void* CRYPTO_get_locking_callback(void);
void  CRYPTO_set_locking_callback(void (*func)(int, int, const char*, int));

#ifdef __cplusplus
}
#endif
