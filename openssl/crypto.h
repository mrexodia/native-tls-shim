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
void* CRYPTO_get_id_callback(void);
void  CRYPTO_set_id_callback(unsigned long (*func)(void));
void  CRYPTO_cleanup_all_ex_data(void);

#ifdef __cplusplus
}
#endif
