#include "tls_internal.hpp"

#include "openssl/conf.h"
#include "openssl/crypto.h"
#include "openssl/engine.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ssl.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {
thread_local unsigned long g_last_error_code = 0;
thread_local std::string g_last_error_message;
thread_local unsigned long g_last_popped_error_code = 0;
thread_local std::string g_last_popped_error_message;

void (*g_locking_callback)(int, int, const char*, int) = nullptr;
unsigned long (*g_id_callback)(void) = nullptr;

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

void* CRYPTO_get_id_callback(void) {
  return reinterpret_cast<void*>(g_id_callback);
}

void CRYPTO_set_id_callback(unsigned long (*func)(void)) { g_id_callback = func; }

void CRYPTO_cleanup_all_ex_data(void) {}

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

const char* ERR_func_error_string(unsigned long /*e*/) { return nullptr; }

void ERR_clear_error(void) { native_tls::set_last_error(0, {}); }

void ERR_free_strings(void) {}

int OPENSSL_config(const char* /*config_name*/) { return 1; }

void CONF_modules_unload(int /*all*/) {}

int OPENSSL_init_ssl(uint64_t /*opts*/, const void* /*settings*/) { return 1; }

int OpenSSL_add_ssl_algorithms(void) { return 1; }

int OpenSSL_add_all_algorithms(void) { return 1; }

int SSL_library_init(void) { return 1; }

int SSL_load_error_strings(void) { return 1; }

void EVP_cleanup(void) {}

void ENGINE_cleanup(void) {}

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

void RSA_free(RSA* /*rsa*/) {
  // Legacy low-level RSA API is intentionally unsupported in this shim.
  // We currently do not create RSA* objects anywhere, so this is a no-op.
}

void DH_free(DH* /*dh*/) {
  // Legacy low-level DH API is intentionally unsupported in this shim.
  // We currently do not create DH* objects anywhere, so this is a no-op.
}

} // extern "C"
