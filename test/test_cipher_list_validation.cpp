#include <openssl/ssl.h>

#include <iostream>

int main() {
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) return 1;

  int ok_default = SSL_CTX_set_cipher_list(ctx, "DEFAULT");
  int ok_invalid = SSL_CTX_set_cipher_list(ctx, "INVALID-CIPHER-STRING");
  int ok_invalid_suites = SSL_CTX_set_ciphersuites(ctx, "TLS_INVALID_CIPHER");

  SSL_CTX_free(ctx);

  bool ok = (ok_default == 1) && (ok_invalid == 0) && (ok_invalid_suites == 0);
  if (!ok) {
    std::cerr << "cipher list validation failed" << "\n";
  }
  return ok ? 0 : 1;
}
