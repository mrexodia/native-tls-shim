#include "tls_internal.hpp"

#include "openssl/conf.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <string>

namespace {
thread_local unsigned long g_last_error_code = 0;
thread_local std::string g_last_error_message;
thread_local unsigned long g_last_popped_error_code = 0;
thread_local std::string g_last_popped_error_message;

void (*g_locking_callback)(int, int, const char*, int) = nullptr;
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

int CRYPTO_num_locks(void) { return 0; }

void* CRYPTO_get_locking_callback(void) {
  return reinterpret_cast<void*>(g_locking_callback);
}

void CRYPTO_set_locking_callback(void (*func)(int, int, const char*, int)) {
  g_locking_callback = func;
}

unsigned long ERR_get_error(void) { return native_tls::pop_last_error_code(); }

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

void ERR_clear_error(void) { native_tls::set_last_error(0, {}); }

int OPENSSL_config(const char* /*config_name*/) { return 1; }

int OPENSSL_init_ssl(uint64_t /*opts*/, const void* /*settings*/) { return 1; }

int OpenSSL_add_ssl_algorithms(void) { return 1; }

int SSL_load_error_strings(void) { return 1; }

} // extern "C"
