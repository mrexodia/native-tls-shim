#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_LIB_X509 11

#define ERR_GET_LIB(l)    ((int)(((l) >> 24) & 0xFF))
#define ERR_GET_REASON(l) ((int)((l) & 0xFFFFFF))

unsigned long ERR_get_error(void);
unsigned long ERR_peek_last_error(void);
void          ERR_error_string_n(unsigned long e, char* buf, size_t len);
char*         ERR_error_string(unsigned long e, char* buf);
void          ERR_clear_error(void);

#ifdef __cplusplus
}
#endif
