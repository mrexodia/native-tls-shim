#pragma once

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bio_st BIO;
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct rsa_st RSA;
typedef struct dh_st DH;
typedef struct x509_info_st X509_INFO;
typedef struct stack_x509_info_st STACK_OF_X509_INFO;

typedef int pem_password_cb(char* buf, int size, int rwflag, void* userdata);

#define PEM_R_NO_START_LINE 108

X509*     PEM_read_bio_X509(BIO* bp, X509** x, void* cb, void* u);
X509*     PEM_read_bio_X509_AUX(BIO* bp, X509** x, void* cb, void* u);
EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x, void* cb, void* u);
RSA*      PEM_read_bio_RSAPrivateKey(BIO* bp, RSA** x, pem_password_cb* cb, void* u);
EVP_PKEY* PEM_read_bio_Parameters(BIO* bp, EVP_PKEY** x);
DH*       PEM_read_bio_DHparams(BIO* bp, DH** x, pem_password_cb* cb, void* u);

int PEM_write_bio_X509(BIO* bp, X509* x);
int PEM_write_bio_PrivateKey(BIO* bp, EVP_PKEY* x, const void* enc,
                             unsigned char* kstr, int klen, void* cb, void* u);

STACK_OF_X509_INFO* PEM_X509_INFO_read_bio(BIO* bp, STACK_OF_X509_INFO* sk,
                                            void* cb, void* u);

#ifdef __cplusplus
}
#endif
