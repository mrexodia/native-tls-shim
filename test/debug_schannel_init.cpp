#include "tls_paths.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

static void print_err(const char* label) {
  unsigned long e = ERR_get_error();
  char buf[256] = {0};
  ERR_error_string_n(e, buf, sizeof(buf));
  std::cout << label << " err=" << e << " msg=" << buf << "\n";
}

static void check_pair(const char* cert_name, const char* key_name) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  std::cout << "== " << cert_name << " / " << key_name << " ==\n";
  if (!ctx) {
    print_err("SSL_CTX_new");
    return;
  }

  auto cert = ix_cert(cert_name);
  auto key = ix_cert(key_name);

  int r1 = SSL_CTX_use_certificate_chain_file(ctx, cert.c_str());
  std::cout << "use_cert=" << r1 << "\n";
  if (r1 != 1) print_err("use_cert");

  int r2 = SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM);
  std::cout << "use_key=" << r2 << "\n";
  if (r2 != 1) print_err("use_key");

  int r3 = SSL_CTX_check_private_key(ctx);
  std::cout << "check_key=" << r3 << "\n";
  if (r3 != 1) print_err("check_key");

#ifdef _WIN32
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  SSL* ssl = SSL_new(ctx);
  SSL_set_fd(ssl, (int)s);
  int ar = SSL_accept(ssl);
  int ae = SSL_get_error(ssl, ar);
  std::cout << "accept_ret=" << ar << " accept_err=" << ae << "\n";
  if (ar != 1 && ae != SSL_ERROR_WANT_READ && ae != SSL_ERROR_WANT_WRITE) {
    print_err("accept");
  }
  SSL_free(ssl);
  closesocket(s);
#endif

  SSL_CTX_free(ctx);
}

int main() {
#ifdef _WIN32
  WSADATA wsa{};
  WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
  check_pair("trusted-server-crt.pem", "trusted-server-key.pem");
  check_pair("wrong-name-server-crt.pem", "wrong-name-server-key.pem");
#ifdef _WIN32
  WSACleanup();
#endif
  return 0;
}
