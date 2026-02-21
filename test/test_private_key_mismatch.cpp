#include <openssl/ssl.h>

#include "tls_paths.h"

#include <iostream>

int main() {
  std::string cert = ix_cert("trusted-server-crt.pem");
  std::string good_key = ix_cert("trusted-server-key.pem");
  std::string bad_key = ix_cert("untrusted-client-key.pem");

  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) return 1;

  if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) != 1) {
    SSL_CTX_free(ctx);
    return 1;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, bad_key.c_str(), SSL_FILETYPE_PEM) != 1) {
    SSL_CTX_free(ctx);
    return 1;
  }

  int mismatch_ok = SSL_CTX_check_private_key(ctx);

  if (SSL_CTX_use_PrivateKey_file(ctx, good_key.c_str(), SSL_FILETYPE_PEM) != 1) {
    SSL_CTX_free(ctx);
    return 1;
  }

  int match_ok = SSL_CTX_check_private_key(ctx);

  SSL_CTX_free(ctx);

  bool ok = (mismatch_ok == 0) && (match_ok == 1);
  if (!ok) {
    std::cerr << "private key mismatch check failed" << "\n";
  }
  return ok ? 0 : 1;
}
