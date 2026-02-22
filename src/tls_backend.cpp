#include "tls_internal.hpp"

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#endif

namespace {
thread_local unsigned long g_last_error_code = 0;
thread_local std::string g_last_error_message;
thread_local unsigned long g_last_popped_error_code = 0;
thread_local std::string g_last_popped_error_message;

std::mutex g_app_data_mutex;
std::unordered_map<const SSL*, void*> g_ssl_app_data;
std::unordered_map<const SSL_CTX*, void*> g_ssl_ctx_app_data;
} // namespace

namespace native_tls {

void set_last_error(unsigned long code, const std::string& message) {
  g_last_error_code = code;
  g_last_error_message = message;
  if (code == 0) {
    g_last_popped_error_code = 0;
    g_last_popped_error_message.clear();
  }
}

unsigned long peek_last_error_code() { return g_last_error_code; }

unsigned long pop_last_error_code() {
  auto e = g_last_error_code;
  g_last_popped_error_code = g_last_error_code;
  g_last_popped_error_message = g_last_error_message;
  g_last_error_code = 0;
  g_last_error_message.clear();
  return e;
}

std::string get_last_error_string(unsigned long code) {
  if (code == 0) return std::string();
  if (!g_last_error_message.empty() && code == g_last_error_code) {
    return g_last_error_message;
  }
  if (!g_last_popped_error_message.empty() && code == g_last_popped_error_code) {
    return g_last_popped_error_message;
  }
  return "native-tls-shim error: " + std::to_string(code);
}

unsigned long make_error_code(int lib, int reason) {
  return (static_cast<unsigned long>(lib & 0xFF) << 24) |
         static_cast<unsigned long>(reason & 0xFFFFFF);
}

void set_error_message(const std::string& msg, int reason, int lib) {
  set_last_error(make_error_code(lib, reason), msg);
}

void clear_error_message() { set_last_error(0, {}); }

std::string trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
    s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
    s.pop_back();
  return s;
}

std::string extract_dn_component(const std::string& dn, const std::string& key) {
  auto pattern = key + "=";
  auto pos = dn.find(pattern);
  if (pos == std::string::npos) return {};
  pos += pattern.size();
  auto end = dn.find(',', pos);
  if (end == std::string::npos) end = dn.size();
  return trim(dn.substr(pos, end - pos));
}

bool wildcard_match(const std::string& pattern, const std::string& host) {
  if (pattern == host) return true;

  if (pattern.size() < 3 || pattern[0] != '*' || pattern[1] != '.') return false;
  if (pattern.find('*', 1) != std::string::npos) return false;

  std::string suffix = pattern.substr(1); // ".example.com"
  if (host.size() <= suffix.size()) return false;
  if (host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0) return false;

  std::string left = host.substr(0, host.size() - suffix.size());
  if (left.empty() || left.find('.') != std::string::npos) return false;

  return true;
}

bool set_fd_nonblocking(int fd, bool on) {
#ifdef _WIN32
  u_long mode = on ? 1 : 0;
  return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  if (on)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags) == 0;
#endif
}

bool is_ip_literal(const std::string& s) {
  std::array<unsigned char, 16> buf{};
  return inet_pton(AF_INET, s.c_str(), buf.data()) == 1 ||
         inet_pton(AF_INET6, s.c_str(), buf.data()) == 1;
}

} // namespace native_tls

extern "C" {

void* OPENSSL_malloc(size_t size) { return ::operator new(size, std::nothrow); }

void OPENSSL_free(void* ptr) { ::operator delete(ptr); }

void OPENSSL_cleanse(void* ptr, size_t len) {
  if (!ptr || len == 0) return;
  volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
  while (len--) *p++ = 0;
}

void OPENSSL_thread_stop(void) {}

unsigned long ERR_get_error(void) { return native_tls::pop_last_error_code(); }

unsigned long ERR_peek_error(void) { return native_tls::peek_last_error_code(); }

unsigned long ERR_peek_last_error(void) {
  return native_tls::peek_last_error_code();
}

void ERR_error_string_n(unsigned long e, char* buf, size_t len) {
  if (!buf || len == 0) return;
  auto msg = native_tls::get_last_error_string(e);
  if (msg.empty()) msg = "ok";
  auto n = std::min(msg.size(), len - 1);
  std::memcpy(buf, msg.data(), n);
  buf[n] = '\0';
}

char* ERR_error_string(unsigned long e, char* buf) {
  static thread_local std::array<char, 256> local{};
  if (!buf) {
    ERR_error_string_n(e, local.data(), local.size());
    return local.data();
  }
  ERR_error_string_n(e, buf, 256);
  return buf;
}

const char* ERR_lib_error_string(unsigned long e) {
  switch (ERR_GET_LIB(e)) {
    case ERR_LIB_SSL: return "SSL routines";
    case ERR_LIB_PEM: return "PEM routines";
    case ERR_LIB_EVP: return "digital envelope routines";
    case ERR_LIB_X509: return "X509 routines";
    default: return nullptr;
  }
}

const char* ERR_reason_error_string(unsigned long e) {
  static thread_local std::array<char, 256> buf{};
  ERR_error_string_n(e, buf.data(), buf.size());
  return buf.data();
}

void ERR_clear_error(void) { native_tls::set_last_error(0, {}); }

int OPENSSL_init_ssl(uint64_t /*opts*/, const void* /*settings*/) { return 1; }

int OpenSSL_add_ssl_algorithms(void) { return 1; }

int SSL_load_error_strings(void) { return 1; }

const unsigned char* ASN1_STRING_get0_data(const ASN1_STRING* x) {
  if (!x || x->bytes.empty()) return nullptr;
  return x->bytes.data();
}

unsigned char* ASN1_STRING_data(ASN1_STRING* x) {
  return const_cast<unsigned char*>(ASN1_STRING_get0_data(x));
}

int ASN1_STRING_length(const ASN1_STRING* x) {
  if (!x) return 0;
  return static_cast<int>(x->bytes.size());
}

ASN1_TIME* ASN1_TIME_new(void) { return new ASN1_TIME(); }

void ASN1_TIME_free(ASN1_TIME* t) { delete t; }

ASN1_TIME* ASN1_TIME_set(ASN1_TIME* s, time_t t) {
  if (!s) s = ASN1_TIME_new();
  if (s) s->epoch = t;
  return s;
}

int ASN1_TIME_diff(int* pday, int* psec, const ASN1_TIME* from, const ASN1_TIME* to) {
  if (!pday || !psec || !from || !to) return 0;
  auto diff = static_cast<long long>(to->epoch) - static_cast<long long>(from->epoch);
  *pday = static_cast<int>(diff / 86400);
  *psec = static_cast<int>(diff % 86400);
  return 1;
}

BIGNUM* ASN1_INTEGER_to_BN(const ASN1_INTEGER* ai, BIGNUM* bn) {
  if (!ai) return nullptr;
  if (!bn) bn = new BIGNUM();
  if (!bn) return nullptr;
  bn->bytes = ai->bytes;
  return bn;
}

char* BN_bn2hex(const BIGNUM* a) {
  if (!a) return nullptr;
  static const char* hex = "0123456789ABCDEF";
  if (a->bytes.empty()) {
    char* z = static_cast<char*>(OPENSSL_malloc(2));
    if (!z) return nullptr;
    z[0] = '0';
    z[1] = '\0';
    return z;
  }
  size_t out_len = a->bytes.size() * 2;
  char* out = static_cast<char*>(OPENSSL_malloc(out_len + 1));
  if (!out) return nullptr;
  for (size_t i = 0; i < a->bytes.size(); ++i) {
    out[2 * i] = hex[(a->bytes[i] >> 4) & 0x0F];
    out[2 * i + 1] = hex[a->bytes[i] & 0x0F];
  }
  out[out_len] = '\0';
  return out;
}

void BN_free(BIGNUM* a) { delete a; }

void SSL_set_app_data(SSL* ssl, void* arg) {
  if (!ssl) return;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  if (arg) {
    g_ssl_app_data[ssl] = arg;
  } else {
    g_ssl_app_data.erase(ssl);
  }
}

void* SSL_get_app_data(const SSL* ssl) {
  if (!ssl) return nullptr;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto it = g_ssl_app_data.find(ssl);
  return it == g_ssl_app_data.end() ? nullptr : it->second;
}

void SSL_CTX_set_app_data(SSL_CTX* ctx, void* arg) {
  if (!ctx) return;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  if (arg) {
    g_ssl_ctx_app_data[ctx] = arg;
  } else {
    g_ssl_ctx_app_data.erase(ctx);
  }
}

void* SSL_CTX_get_app_data(const SSL_CTX* ctx) {
  if (!ctx) return nullptr;
  std::lock_guard<std::mutex> lock(g_app_data_mutex);
  auto it = g_ssl_ctx_app_data.find(ctx);
  return it == g_ssl_ctx_app_data.end() ? nullptr : it->second;
}


} // extern "C"
