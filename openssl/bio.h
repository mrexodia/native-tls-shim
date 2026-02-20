#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;

#define BIO_NOCLOSE 0

BIO* BIO_new_socket(int sock, int close_flag);
void BIO_set_nbio(BIO* bio, long on);

BIO* BIO_new_mem_buf(const void* buf, int len);
BIO* BIO_new(const BIO_METHOD* method);
const BIO_METHOD* BIO_s_mem(void);

long BIO_get_mem_data(BIO* bio, char** pp);

int  BIO_free(BIO* a);
void BIO_free_all(BIO* a);

#ifdef __cplusplus
}
#endif
