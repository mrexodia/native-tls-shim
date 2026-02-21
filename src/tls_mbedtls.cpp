#include "tls_internal.hpp"

#include "openssl/bio.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#if MBEDTLS_VERSION_MAJOR >= 3
#include <psa/crypto.h>
#endif

#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

constexpr unsigned long make_error_code(int lib, int reason) {
  return (static_cast<unsigned long>(lib & 0xFF) << 24) |
         static_cast<unsigned long>(reason & 0xFFFFFF);
}

inline void set_error_message(const std::string& msg, int reason = 1,
                              int lib = ERR_LIB_X509) {
  native_tls::set_last_error(make_error_code(lib, reason), msg);
}

inline void clear_error_message() { native_tls::set_last_error(0, {}); }

#ifdef _WIN32
using socket_len_t = int;
#else
using socket_len_t = socklen_t;
#endif

int close_socket_fd(int fd) {
#ifdef _WIN32
  return closesocket(fd);
#else
  return close(fd);
#endif
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

time_t timegm_utc(std::tm* tmv) {
#ifdef _WIN32
  return _mkgmtime(tmv);
#else
  return timegm(tmv);
#endif
}

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

int map_mbedtls_to_ssl_error(int ret) {
  if (ret > 0) return SSL_ERROR_NONE;
  if (ret == 0) return SSL_ERROR_ZERO_RETURN;
  if (ret == MBEDTLS_ERR_SSL_WANT_READ) return SSL_ERROR_WANT_READ;
  if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) return SSL_ERROR_WANT_WRITE;
  if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return SSL_ERROR_ZERO_RETURN;
  return SSL_ERROR_SSL;
}

struct ssl_method_st {
  int endpoint;
};

struct asn1_string_st {
  std::vector<unsigned char> bytes;
};

struct asn1_time_st {
  time_t epoch = 0;
};

struct bignum_st {
  std::vector<unsigned char> bytes;
};

struct x509_name_st {
  std::string text;
  std::string common_name;
};

struct x509_st {
  mbedtls_x509_crt crt;
  int refs = 1;
  x509_name_st subject_name;
  x509_name_st issuer_name;
  asn1_string_st serial;
  asn1_time_st not_before;
  asn1_time_st not_after;

  x509_st() { mbedtls_x509_crt_init(&crt); }
  ~x509_st() { mbedtls_x509_crt_free(&crt); }
};

struct x509_crl_st {};

struct x509_object_st {
  int type = X509_LU_X509;
  X509* cert = nullptr;
};

struct stack_st_X509_OBJECT {
  std::vector<x509_object_st> items;
};

struct stack_st_X509_NAME {
  std::vector<X509_NAME*> names;
};

struct stack_x509_info_st {
  std::vector<X509_INFO*> items;
};

struct x509_store_st {
  mbedtls_x509_crt ca_chain;
  std::vector<X509*> certs;
  unsigned long flags = 0;
  stack_st_X509_OBJECT object_cache;

  x509_store_st() { mbedtls_x509_crt_init(&ca_chain); }
  ~x509_store_st() {
    for (auto* cert : certs) {
      if (cert) X509_free(cert);
    }
    mbedtls_x509_crt_free(&ca_chain);
  }
};

struct x509_verify_param_st {
  std::string host;
  unsigned int hostflags = 0;
};

struct x509_store_ctx_st {
  SSL* ssl = nullptr;
  X509* current_cert = nullptr;
  int error = X509_V_OK;
  int depth = 0;
};

struct bio_method_st {
  int kind;
};

enum class BioKind { Socket, Memory };

struct bio_st {
  BioKind kind = BioKind::Memory;
  int fd = -1;
  bool close_on_free = false;
  std::vector<unsigned char> data;
  size_t offset = 0;
};

struct evp_pkey_st {
  mbedtls_pk_context pk;
  bool has_key = false;
  std::string pem;

  evp_pkey_st() { mbedtls_pk_init(&pk); }
  ~evp_pkey_st() { mbedtls_pk_free(&pk); }
};

struct evp_md_st {
  mbedtls_md_type_t type;
};

struct evp_md_ctx_st {
  mbedtls_md_context_t md;
  const EVP_MD* current = nullptr;
  bool setup = false;

  evp_md_ctx_st() { mbedtls_md_init(&md); }
  ~evp_md_ctx_st() { mbedtls_md_free(&md); }
};

struct ssl_ctx_st {
  bool is_client = true;
  int verify_mode = SSL_VERIFY_NONE;
  int verify_depth = 0;
  int (*verify_callback)(int, X509_STORE_CTX*) = nullptr;

  long mode = 0;
  long options = 0;
  int session_cache_mode = SSL_SESS_CACHE_OFF;
  int min_proto_version = TLS1_2_VERSION;

  void* passwd_userdata = nullptr;

  X509_STORE* cert_store = nullptr;
  stack_st_X509_NAME* client_ca_list = nullptr;

  mbedtls_ssl_config conf;
  mbedtls_x509_crt own_cert_chain;
  mbedtls_pk_context own_key;
  bool own_cert_loaded = false;
  bool own_key_loaded = false;

  std::vector<std::string> alpn_protocols;
  std::vector<const char*> alpn_protocol_ptrs;

  std::vector<int> ciphersuites;
  bool ciphersuites_set = false;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  ssl_ctx_st() {
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&own_cert_chain);
    mbedtls_pk_init(&own_key);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
  }

  ~ssl_ctx_st() {
    if (client_ca_list) sk_X509_NAME_pop_free(client_ca_list, X509_NAME_free);
    if (cert_store) X509_STORE_free(cert_store);
    mbedtls_pk_free(&own_key);
    mbedtls_x509_crt_free(&own_cert_chain);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
  }
};

struct ssl_st {
  SSL_CTX* ctx = nullptr;
  mbedtls_ssl_context ssl;
  bool ssl_setup = false;

  int fd = -1;
  BIO* rbio = nullptr;
  BIO* wbio = nullptr;

  int verify_mode = SSL_VERIFY_NONE;
  int (*verify_callback)(int, X509_STORE_CTX*) = nullptr;

  int last_error = SSL_ERROR_NONE;
  int last_ret = 1;

  std::string hostname;
  std::string selected_alpn;
  x509_verify_param_st param;
  bool ignore_verify_result = false;

  std::vector<unsigned char> peeked_plaintext;

  ssl_st() { mbedtls_ssl_init(&ssl); }
  ~ssl_st() {
    if (rbio) {
      if (wbio == rbio) {
        BIO_free(rbio);
      } else {
        BIO_free(rbio);
        if (wbio) BIO_free(wbio);
      }
      rbio = nullptr;
      wbio = nullptr;
    }
    mbedtls_ssl_free(&ssl);
  }
};

const ssl_method_st g_client_method{MBEDTLS_SSL_IS_CLIENT};
const ssl_method_st g_server_method{MBEDTLS_SSL_IS_SERVER};
const bio_method_st g_mem_method{1};

const EVP_MD g_md5{MBEDTLS_MD_MD5};
const EVP_MD g_sha256{MBEDTLS_MD_SHA256};
const EVP_MD g_sha512{MBEDTLS_MD_SHA512};

#if MBEDTLS_VERSION_MAJOR >= 3
std::once_flag g_psa_init_once;
#endif

int ssl_send_cb(void* ctx, const unsigned char* buf, size_t len) {
  int fd = *static_cast<int*>(ctx);
#ifdef _WIN32
  int rc = send(fd, reinterpret_cast<const char*>(buf), static_cast<int>(len), 0);
#else
#ifdef MSG_NOSIGNAL
  int flags = MSG_NOSIGNAL;
#else
  int flags = 0;
#endif
  int rc = static_cast<int>(::send(fd, buf, len, flags));
#endif
  if (rc < 0) {
#ifdef _WIN32
    int wsa = WSAGetLastError();
    if (wsa == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
#endif
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  return rc;
}

int ssl_recv_cb(void* ctx, unsigned char* buf, size_t len) {
  int fd = *static_cast<int*>(ctx);
#ifdef _WIN32
  int rc = recv(fd, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
#else
  int rc = static_cast<int>(::recv(fd, buf, len, 0));
#endif
  if (rc == 0) return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
  if (rc < 0) {
#ifdef _WIN32
    int wsa = WSAGetLastError();
    if (wsa == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
#endif
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }
  return rc;
}

void refresh_x509_fields(X509* x) {
  if (!x) return;

  char buf[1024];
  buf[0] = '\0';
  if (mbedtls_x509_dn_gets(buf, sizeof(buf), &x->crt.subject) > 0) {
    x->subject_name.text = buf;
    x->subject_name.common_name = extract_dn_component(x->subject_name.text, "CN");
  } else {
    x->subject_name.text.clear();
    x->subject_name.common_name.clear();
  }

  buf[0] = '\0';
  if (mbedtls_x509_dn_gets(buf, sizeof(buf), &x->crt.issuer) > 0) {
    x->issuer_name.text = buf;
    x->issuer_name.common_name = extract_dn_component(x->issuer_name.text, "CN");
  } else {
    x->issuer_name.text.clear();
    x->issuer_name.common_name.clear();
  }

  x->serial.bytes.assign(x->crt.serial.p, x->crt.serial.p + x->crt.serial.len);

  std::tm tmnb{};
  tmnb.tm_year = x->crt.valid_from.year - 1900;
  tmnb.tm_mon = x->crt.valid_from.mon - 1;
  tmnb.tm_mday = x->crt.valid_from.day;
  tmnb.tm_hour = x->crt.valid_from.hour;
  tmnb.tm_min = x->crt.valid_from.min;
  tmnb.tm_sec = x->crt.valid_from.sec;
  x->not_before.epoch = timegm_utc(&tmnb);

  std::tm tmna{};
  tmna.tm_year = x->crt.valid_to.year - 1900;
  tmna.tm_mon = x->crt.valid_to.mon - 1;
  tmna.tm_mday = x->crt.valid_to.day;
  tmna.tm_hour = x->crt.valid_to.hour;
  tmna.tm_min = x->crt.valid_to.min;
  tmna.tm_sec = x->crt.valid_to.sec;
  x->not_after.epoch = timegm_utc(&tmna);
}

X509* x509_from_der(const unsigned char* der, size_t len) {
  auto* x = new X509();
  int rc = mbedtls_x509_crt_parse_der(&x->crt, der, len);
  if (rc != 0) {
    delete x;
    return nullptr;
  }
  refresh_x509_fields(x);
  return x;
}

X509* x509_clone(const X509* in) {
  if (!in || !in->crt.raw.p || in->crt.raw.len == 0) return nullptr;
  return x509_from_der(in->crt.raw.p, in->crt.raw.len);
}

int verify_mode_to_authmode(int mode, bool is_server) {
  if (!(mode & SSL_VERIFY_PEER)) return MBEDTLS_SSL_VERIFY_NONE;
  if (is_server && !(mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
    return MBEDTLS_SSL_VERIFY_OPTIONAL;
  }
  return MBEDTLS_SSL_VERIFY_REQUIRED;
}

bool ctx_has_ca_store(const SSL_CTX* ctx) {
  return ctx && ctx->cert_store && !ctx->cert_store->certs.empty();
}

bool ctx_should_verify_peer(const SSL_CTX* ctx) {
  if (!ctx) return false;
  if (ctx->verify_mode & SSL_VERIFY_PEER) return true;
  return ctx->is_client && ctx_has_ca_store(ctx);
}

bool ssl_should_verify_peer(const SSL* ssl) {
  if (!ssl || !ssl->ctx) return false;
  if (ssl->verify_mode & SSL_VERIFY_PEER) return true;
  return ctx_should_verify_peer(ssl->ctx);
}

void apply_ctx_verify_mode(SSL_CTX* ctx) {
  if (!ctx) return;
  int auth = MBEDTLS_SSL_VERIFY_NONE;
  if (ctx->verify_mode & SSL_VERIFY_PEER) {
    auth = verify_mode_to_authmode(ctx->verify_mode, !ctx->is_client);
  } else if (ctx->is_client && ctx_has_ca_store(ctx)) {
    auth = MBEDTLS_SSL_VERIFY_REQUIRED;
  }
  mbedtls_ssl_conf_authmode(&ctx->conf, auth);
}

void apply_ctx_ca_store(SSL_CTX* ctx) {
  if (!ctx) return;

  bool should_set = ctx_should_verify_peer(ctx);
  if (!should_set) {
    mbedtls_ssl_conf_ca_chain(&ctx->conf, nullptr, nullptr);
    return;
  }

  if (ctx->cert_store && ctx->cert_store->ca_chain.raw.p) {
    mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cert_store->ca_chain, nullptr);
  } else {
    mbedtls_ssl_conf_ca_chain(&ctx->conf, nullptr, nullptr);
  }
}

bool apply_ctx_own_cert(SSL_CTX* ctx) {
  if (!ctx) return false;
  if (!ctx->own_cert_loaded || !ctx->own_key_loaded) return true;
  int rc = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->own_cert_chain, &ctx->own_key);
  if (rc != 0) {
    char err[256] = {0};
    mbedtls_strerror(rc, err, sizeof(err));
    set_error_message(std::string("mbedtls_ssl_conf_own_cert failed: ") + err);
    return false;
  }
  return true;
}

void parse_alpn_blob(SSL_CTX* ctx, const unsigned char* protos, unsigned int len) {
  ctx->alpn_protocols.clear();
  ctx->alpn_protocol_ptrs.clear();

  size_t i = 0;
  while (i < len) {
    unsigned int l = protos[i++];
    if (l == 0 || i + l > len) break;
    ctx->alpn_protocols.emplace_back(reinterpret_cast<const char*>(protos + i), l);
    i += l;
  }

  for (auto& s : ctx->alpn_protocols) {
    ctx->alpn_protocol_ptrs.push_back(s.c_str());
  }
  ctx->alpn_protocol_ptrs.push_back(nullptr);

  if (!ctx->alpn_protocols.empty()) {
    mbedtls_ssl_conf_alpn_protocols(&ctx->conf, ctx->alpn_protocol_ptrs.data());
  }
}

bool setup_ssl_context(SSL_CTX* ctx) {
  if (!ctx) return false;

#if MBEDTLS_VERSION_MAJOR >= 3
  std::call_once(g_psa_init_once, []() { psa_crypto_init(); });
#endif

  const char* pers = "native_tls_shim";
  int rc = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                                 reinterpret_cast<const unsigned char*>(pers),
                                 std::strlen(pers));
  if (rc != 0) {
    set_error_message("mbedtls_ctr_drbg_seed failed");
    return false;
  }

  rc = mbedtls_ssl_config_defaults(&ctx->conf,
                                   ctx->is_client ? MBEDTLS_SSL_IS_CLIENT
                                                  : MBEDTLS_SSL_IS_SERVER,
                                   MBEDTLS_SSL_TRANSPORT_STREAM,
                                   MBEDTLS_SSL_PRESET_DEFAULT);
  if (rc != 0) {
    set_error_message("mbedtls_ssl_config_defaults failed");
    return false;
  }

  mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
#ifdef MBEDTLS_SSL_VERSION_TLS1_3
  mbedtls_ssl_conf_max_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#else
  mbedtls_ssl_conf_max_tls_version(&ctx->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif
  apply_ctx_verify_mode(ctx);
  apply_ctx_ca_store(ctx);

  return true;
}

bool setup_ssl_instance(SSL* ssl) {
  if (!ssl || !ssl->ctx) return false;
  int rc = mbedtls_ssl_setup(&ssl->ssl, &ssl->ctx->conf);
  if (rc != 0) {
    char err[256] = {0};
    mbedtls_strerror(rc, err, sizeof(err));
    set_error_message(std::string("mbedtls_ssl_setup failed: ") + err);
    return false;
  }
  int auth = MBEDTLS_SSL_VERIFY_NONE;
  if (ssl->verify_mode & SSL_VERIFY_PEER) {
    auth = verify_mode_to_authmode(ssl->verify_mode, !ssl->ctx->is_client);
  } else if (ssl->ctx && ssl->ctx->is_client && ctx_has_ca_store(ssl->ctx)) {
    auth = MBEDTLS_SSL_VERIFY_REQUIRED;
  } else if (!(ssl->verify_mode & SSL_VERIFY_PEER) && ssl->ctx &&
             (ssl->ctx->verify_mode & SSL_VERIFY_PEER)) {
    auth = verify_mode_to_authmode(ssl->ctx->verify_mode, !ssl->ctx->is_client);
  }
  mbedtls_ssl_set_hs_authmode(&ssl->ssl, auth);

  ssl->ssl_setup = true;

  if (ssl->fd >= 0) {
    mbedtls_ssl_set_bio(&ssl->ssl, &ssl->fd, ssl_send_cb, ssl_recv_cb, nullptr);
  }
  return true;
}

bool add_cert_to_store(X509_STORE* store, X509* cert, bool allow_duplicate_error) {
  if (!store || !cert) return false;

  for (auto* existing : store->certs) {
    if (!existing) continue;
    if (existing->crt.raw.len == cert->crt.raw.len &&
        existing->crt.raw.p && cert->crt.raw.p &&
        std::memcmp(existing->crt.raw.p, cert->crt.raw.p, cert->crt.raw.len) == 0) {
      if (!allow_duplicate_error) return true;
      set_error_message("certificate already in store", X509_R_CERT_ALREADY_IN_HASH_TABLE);
      return false;
    }
  }

  int rc = mbedtls_x509_crt_parse_der(&store->ca_chain, cert->crt.raw.p, cert->crt.raw.len);
  if (rc != 0) {
    set_error_message("mbedtls_x509_crt_parse_der failed while adding cert");
    return false;
  }

  X509_up_ref(cert);
  store->certs.push_back(cert);
  return true;
}

bool load_ca_file_into_store(X509_STORE* store, const char* file) {
  if (!store || !file || !*file) return false;

  mbedtls_x509_crt chain;
  mbedtls_x509_crt_init(&chain);
  int rc = mbedtls_x509_crt_parse_file(&chain, file);
  if (rc < 0) {
    mbedtls_x509_crt_free(&chain);
    return false;
  }

  bool any = false;
  for (mbedtls_x509_crt* p = &chain; p && p->raw.p; p = p->next) {
    auto* x = x509_from_der(p->raw.p, p->raw.len);
    if (!x) continue;
    if (add_cert_to_store(store, x, false)) any = true;
    X509_free(x);
  }

  mbedtls_x509_crt_free(&chain);
  return any;
}

bool load_default_ca_paths(X509_STORE* store) {
  static const char* paths[] = {
      "/etc/ssl/certs/ca-certificates.crt",
      "/etc/pki/tls/certs/ca-bundle.crt",
      "/etc/ssl/ca-bundle.pem",
      "/etc/ssl/cert.pem",
  };
  bool loaded = false;
  for (auto* p : paths) {
    if (load_ca_file_into_store(store, p)) loaded = true;
  }
  return loaded;
}

bool cert_matches_hostname(const X509* cert, const std::string& host, bool check_ip) {
  if (!cert) return false;

  auto names = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(const_cast<X509*>(cert), NID_subject_alt_name, nullptr, nullptr));
  if (names) {
    int n = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < n; ++i) {
      auto* gn = sk_GENERAL_NAME_value(names, i);
      if (!gn) continue;
      if (check_ip && gn->type == GEN_IPADD && gn->d.iPAddress) {
        auto* data = ASN1_STRING_get0_data(gn->d.iPAddress);
        int len = ASN1_STRING_length(gn->d.iPAddress);
        char buf[INET6_ADDRSTRLEN] = {0};
        if (len == 4) inet_ntop(AF_INET, data, buf, sizeof(buf));
        else if (len == 16) inet_ntop(AF_INET6, data, buf, sizeof(buf));
        if (host == buf) {
          GENERAL_NAMES_free(names);
          return true;
        }
      } else if (!check_ip && gn->type == GEN_DNS && gn->d.dNSName) {
        auto* data = reinterpret_cast<const char*>(ASN1_STRING_get0_data(gn->d.dNSName));
        int len = ASN1_STRING_length(gn->d.dNSName);
        std::string pattern(data, static_cast<size_t>(len));
        if (wildcard_match(pattern, host) || pattern == host) {
          GENERAL_NAMES_free(names);
          return true;
        }
      }
    }
    GENERAL_NAMES_free(names);
  }

  if (!check_ip) {
    auto cn = cert->subject_name.common_name;
    if (!cn.empty() && (cn == host || wildcard_match(cn, host))) return true;
  }

  return false;
}

bool is_ip_literal(const std::string& s) {
  std::array<unsigned char, 16> buf{};
  return inet_pton(AF_INET, s.c_str(), buf.data()) == 1 ||
         inet_pton(AF_INET6, s.c_str(), buf.data()) == 1;
}

int run_verify_callback_if_any(SSL* ssl) {
  if (!ssl) return 1;
  auto* cb = ssl->verify_callback ? ssl->verify_callback : ssl->ctx->verify_callback;
  if (!cb) return 1;

  auto* cert = SSL_get_peer_certificate(ssl);
  x509_store_ctx_st verify_ctx;
  verify_ctx.ssl = ssl;
  verify_ctx.current_cert = cert;
  verify_ctx.depth = 0;

  long verify_result = ssl->ignore_verify_result ? X509_V_OK : SSL_get_verify_result(ssl);
  verify_ctx.error = (verify_result == X509_V_OK) ? X509_V_OK : X509_V_ERR_UNSPECIFIED;

  int preverify = (verify_result == X509_V_OK) ? 1 : 0;
  int rc = cb(preverify, &verify_ctx);

  if (cert) X509_free(cert);
  return rc;
}

bool next_pem_block(BIO* bio, const char* begin_tag, const char* end_tag,
                    std::string& out_block) {
  if (!bio || bio->kind != BioKind::Memory) return false;
  if (bio->offset >= bio->data.size()) return false;

  std::string text(reinterpret_cast<const char*>(bio->data.data()), bio->data.size());
  auto begin = text.find(begin_tag, bio->offset);
  if (begin == std::string::npos) return false;
  auto end = text.find(end_tag, begin);
  if (end == std::string::npos) return false;
  end += std::strlen(end_tag);
  // include trailing newline if present
  if (end < text.size() && text[end] == '\r') ++end;
  if (end < text.size() && text[end] == '\n') ++end;

  out_block = text.substr(begin, end - begin);
  bio->offset = end;
  return true;
}


extern "C" {

/* ===== BIO ===== */
BIO* BIO_new_socket(int sock, int close_flag) {
  auto* bio = new BIO();
  bio->kind = BioKind::Socket;
  bio->fd = sock;
  bio->close_on_free = close_flag != BIO_NOCLOSE;
  return bio;
}

void BIO_set_nbio(BIO* bio, long on) {
  if (!bio || bio->kind != BioKind::Socket || bio->fd < 0) return;
  set_fd_nonblocking(bio->fd, on != 0);
}

BIO* BIO_new_mem_buf(const void* buf, int len) {
  auto* bio = new BIO();
  bio->kind = BioKind::Memory;
  if (buf) {
    if (len < 0) {
      auto* c = static_cast<const char*>(buf);
      len = static_cast<int>(std::strlen(c));
    }
    bio->data.assign(static_cast<const unsigned char*>(buf),
                     static_cast<const unsigned char*>(buf) + len);
  }
  return bio;
}

BIO* BIO_new(const BIO_METHOD* method) {
  if (!method || method != &g_mem_method) return nullptr;
  return BIO_new_mem_buf(nullptr, 0);
}

const BIO_METHOD* BIO_s_mem(void) { return &g_mem_method; }

long BIO_get_mem_data(BIO* bio, char** pp) {
  if (!bio || bio->kind != BioKind::Memory) {
    if (pp) *pp = nullptr;
    return 0;
  }
  if (pp) {
    *pp = reinterpret_cast<char*>(bio->data.data() + bio->offset);
  }
  return static_cast<long>(bio->data.size() - bio->offset);
}

int BIO_free(BIO* a) {
  if (!a) return 0;
  if (a->kind == BioKind::Socket && a->close_on_free && a->fd >= 0) {
    close_socket_fd(a->fd);
  }
  delete a;
  return 1;
}

void BIO_free_all(BIO* a) { (void)BIO_free(a); }

/* ===== EVP (digest + pkey lifecycle) ===== */
EVP_MD_CTX* EVP_MD_CTX_new(void) { return new EVP_MD_CTX(); }

void EVP_MD_CTX_free(EVP_MD_CTX* ctx) { delete ctx; }

int EVP_DigestInit_ex(EVP_MD_CTX* ctx, const EVP_MD* type, void* /*engine*/) {
  if (!ctx || !type) return 0;
  mbedtls_md_free(&ctx->md);
  mbedtls_md_init(&ctx->md);

  auto* info = mbedtls_md_info_from_type(type->type);
  if (!info) return 0;
  if (mbedtls_md_setup(&ctx->md, info, 0) != 0) return 0;
  if (mbedtls_md_starts(&ctx->md) != 0) return 0;
  ctx->current = type;
  ctx->setup = true;
  return 1;
}

int EVP_DigestUpdate(EVP_MD_CTX* ctx, const void* d, size_t cnt) {
  if (!ctx || !ctx->setup) return 0;
  return mbedtls_md_update(&ctx->md, static_cast<const unsigned char*>(d), cnt) == 0 ? 1 : 0;
}

int EVP_DigestFinal_ex(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* s) {
  if (!ctx || !ctx->setup || !md) return 0;
  if (mbedtls_md_finish(&ctx->md, md) != 0) return 0;
  if (s) {
    auto* info = mbedtls_md_info_from_type(ctx->current->type);
    *s = info ? static_cast<unsigned int>(mbedtls_md_get_size(info)) : 0;
  }
  return 1;
}

const EVP_MD* EVP_md5(void) { return &g_md5; }
const EVP_MD* EVP_sha256(void) { return &g_sha256; }
const EVP_MD* EVP_sha512(void) { return &g_sha512; }

void EVP_PKEY_free(EVP_PKEY* pkey) { delete pkey; }

/* ===== ASN1 / BN ===== */
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

/* ===== X509 ===== */
X509* d2i_X509(X509** px, const unsigned char** in, int len) {
  if (!in || !*in || len <= 0) return nullptr;
  auto* out = x509_from_der(*in, static_cast<size_t>(len));
  if (!out) return nullptr;
  *in += len;
  if (px) *px = out;
  return out;
}

int i2d_X509(const X509* x, unsigned char** out) {
  if (!x || !x->crt.raw.p) return -1;
  int len = static_cast<int>(x->crt.raw.len);
  if (!out) return len;
  std::memcpy(*out, x->crt.raw.p, x->crt.raw.len);
  *out += x->crt.raw.len;
  return len;
}

void X509_free(X509* cert) {
  if (!cert) return;
  cert->refs--;
  if (cert->refs <= 0) {
    delete cert;
  }
}

int X509_up_ref(X509* cert) {
  if (!cert) return 0;
  cert->refs++;
  return 1;
}

X509_NAME* X509_get_subject_name(const X509* x) {
  if (!x) return nullptr;
  return const_cast<X509_NAME*>(&x->subject_name);
}

X509_NAME* X509_get_issuer_name(const X509* x) {
  if (!x) return nullptr;
  return const_cast<X509_NAME*>(&x->issuer_name);
}

ASN1_INTEGER* X509_get_serialNumber(X509* x) {
  if (!x) return nullptr;
  return &x->serial;
}

const ASN1_TIME* X509_get0_notBefore(const X509* x) {
  if (!x) return nullptr;
  return &x->not_before;
}

const ASN1_TIME* X509_get0_notAfter(const X509* x) {
  if (!x) return nullptr;
  return &x->not_after;
}

char* X509_NAME_oneline(const X509_NAME* a, char* buf, int size) {
  if (!a || !buf || size <= 0) return nullptr;
  auto n = (std::min)(static_cast<int>(a->text.size()), size - 1);
  std::memcpy(buf, a->text.data(), n);
  buf[n] = '\0';
  return buf;
}

int X509_NAME_get_text_by_NID(X509_NAME* name, int nid, char* buf, int len) {
  if (!name || !buf || len <= 0) return -1;
  std::string val;
  if (nid == NID_commonName) val = name->common_name;
  else return -1;
  auto n = (std::min)(static_cast<int>(val.size()), len - 1);
  std::memcpy(buf, val.data(), n);
  buf[n] = '\0';
  return n;
}

X509_NAME* X509_NAME_dup(const X509_NAME* name) {
  if (!name) return nullptr;
  auto* n = new X509_NAME();
  n->text = name->text;
  n->common_name = name->common_name;
  return n;
}

void X509_NAME_free(X509_NAME* name) { delete name; }

int X509_check_host(X509* x, const char* chk, size_t chklen,
                    unsigned int /*flags*/, char** peername) {
  if (!x || !chk) return 0;
  std::string host = chklen ? std::string(chk, chklen) : std::string(chk);
  bool ok = cert_matches_hostname(x, host, false);
  if (ok && peername) {
    auto* out = static_cast<char*>(OPENSSL_malloc(host.size() + 1));
    if (out) {
      std::memcpy(out, host.data(), host.size());
      out[host.size()] = '\0';
      *peername = out;
    }
  }
  return ok ? 1 : 0;
}

int X509_check_ip_asc(X509* x, const char* ipasc, unsigned int /*flags*/) {
  if (!x || !ipasc) return 0;
  return cert_matches_hostname(x, ipasc, true) ? 1 : 0;
}

const char* X509_verify_cert_error_string(long n) {
  switch (n) {
    case X509_V_OK: return "ok";
    case X509_V_ERR_CERT_HAS_EXPIRED: return "certificate has expired";
    case X509_V_ERR_CERT_NOT_YET_VALID: return "certificate is not yet valid";
    case X509_V_ERR_CERT_REVOKED: return "certificate revoked";
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: return "self signed certificate";
    case X509_V_ERR_HOSTNAME_MISMATCH: return "hostname mismatch";
    default: return "certificate verify error";
  }
}

/* ===== X509 store ===== */
X509_STORE* X509_STORE_new(void) { return new X509_STORE(); }

void X509_STORE_free(X509_STORE* store) { delete store; }

int X509_STORE_add_cert(X509_STORE* store, X509* cert) {
  return add_cert_to_store(store, cert, true) ? 1 : 0;
}

int X509_STORE_add_crl(X509_STORE* /*store*/, X509_CRL* /*crl*/) { return 1; }

void X509_STORE_set_flags(X509_STORE* store, unsigned long flags) {
  if (store) store->flags |= flags;
}

STACK_OF_X509_OBJECT* X509_STORE_get0_objects(const X509_STORE* store) {
  if (!store) return nullptr;
  auto* s = const_cast<X509_STORE*>(store);
  s->object_cache.items.clear();
  s->object_cache.items.reserve(s->certs.size());
  for (auto* cert : s->certs) {
    s->object_cache.items.push_back({X509_LU_X509, cert});
  }
  return &s->object_cache;
}

int X509_OBJECT_get_type(const X509_OBJECT* obj) { return obj ? obj->type : 0; }

X509* X509_OBJECT_get0_X509(const X509_OBJECT* obj) { return obj ? obj->cert : nullptr; }

int sk_X509_OBJECT_num(const STACK_OF_X509_OBJECT* st) {
  return st ? static_cast<int>(st->items.size()) : 0;
}

X509_OBJECT* sk_X509_OBJECT_value(const STACK_OF_X509_OBJECT* st, int i) {
  if (!st || i < 0 || static_cast<size_t>(i) >= st->items.size()) return nullptr;
  return const_cast<X509_OBJECT*>(&st->items[static_cast<size_t>(i)]);
}

/* ===== verify param/store ctx ===== */
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM* param, const char* name, size_t namelen) {
  if (!param || !name) return 0;
  param->host = namelen ? std::string(name, namelen) : std::string(name);
  return 1;
}

void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM* param, unsigned int flags) {
  if (param) param->hostflags = flags;
}

X509* X509_STORE_CTX_get_current_cert(X509_STORE_CTX* ctx) {
  return ctx ? ctx->current_cert : nullptr;
}

int X509_STORE_CTX_get_error(X509_STORE_CTX* ctx) {
  return ctx ? ctx->error : X509_V_ERR_UNSPECIFIED;
}

int X509_STORE_CTX_get_error_depth(X509_STORE_CTX* ctx) { return ctx ? ctx->depth : 0; }

void* X509_STORE_CTX_get_ex_data(X509_STORE_CTX* ctx, int idx) {
  if (!ctx || idx != 0) return nullptr;
  return ctx->ssl;
}

/* ===== GENERAL_NAME stack ===== */
struct stack_st_GENERAL_NAME {
  std::vector<GENERAL_NAME*> names;
};

int native_sk_GENERAL_NAME_num(const STACK_OF_GENERAL_NAME* st) {
  return st ? static_cast<int>(st->names.size()) : 0;
}

GENERAL_NAME* native_sk_GENERAL_NAME_value(const STACK_OF_GENERAL_NAME* st, int i) {
  if (!st || i < 0 || static_cast<size_t>(i) >= st->names.size()) return nullptr;
  return st->names[static_cast<size_t>(i)];
}

void GENERAL_NAME_free(GENERAL_NAME* a) {
  if (!a) return;
  delete a->d.ptr;
  delete a;
}

void sk_GENERAL_NAME_pop_free(STACK_OF_GENERAL_NAME* st, void (*freefn)(GENERAL_NAME*)) {
  if (!st) return;
  for (auto* n : st->names) {
    if (freefn) freefn(n);
  }
  delete st;
}

void GENERAL_NAMES_free(STACK_OF_GENERAL_NAME* st) {
  sk_GENERAL_NAME_pop_free(st, GENERAL_NAME_free);
}

void* X509_get_ext_d2i(X509* x, int nid, int* /*crit*/, int* /*idx*/) {
  if (!x || nid != NID_subject_alt_name) return nullptr;

  auto* out = new STACK_OF_GENERAL_NAME();

  for (const mbedtls_x509_sequence* cur = &x->crt.subject_alt_names; cur && cur->buf.p; cur = cur->next) {
    mbedtls_x509_subject_alternative_name san;
    int rc = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
    if (rc != 0) continue;

    auto* gn = new GENERAL_NAME();
    gn->type = GEN_OTHERNAME;
    gn->d.ptr = new ASN1_STRING();

    if (san.type == MBEDTLS_X509_SAN_DNS_NAME) {
      gn->type = GEN_DNS;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.dNSName = gn->d.ptr;
      out->names.push_back(gn);
    } else if (san.type == MBEDTLS_X509_SAN_IP_ADDRESS) {
      gn->type = GEN_IPADD;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.iPAddress = gn->d.ptr;
      out->names.push_back(gn);
    } else if (san.type == MBEDTLS_X509_SAN_RFC822_NAME) {
      gn->type = GEN_EMAIL;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.rfc822Name = gn->d.ptr;
      out->names.push_back(gn);
    } else if (san.type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) {
      gn->type = GEN_URI;
      gn->d.ptr->bytes.assign(san.san.unstructured_name.p,
                              san.san.unstructured_name.p + san.san.unstructured_name.len);
      gn->d.uniformResourceIdentifier = gn->d.ptr;
      out->names.push_back(gn);
    } else {
      GENERAL_NAME_free(gn);
    }

    mbedtls_x509_free_subject_alt_name(&san);
  }

  if (out->names.empty()) {
    delete out;
    return nullptr;
  }

  return out;
}

/* ===== X509_NAME stack ===== */
STACK_OF_X509_NAME* sk_X509_NAME_new_null(void) { return new STACK_OF_X509_NAME(); }

int sk_X509_NAME_push(STACK_OF_X509_NAME* sk, X509_NAME* name) {
  if (!sk || !name) return 0;
  sk->names.push_back(name);
  return 1;
}

int sk_X509_NAME_num(const STACK_OF_X509_NAME* sk) {
  return sk ? static_cast<int>(sk->names.size()) : 0;
}

void sk_X509_NAME_free(STACK_OF_X509_NAME* sk) { delete sk; }

void sk_X509_NAME_pop_free(STACK_OF_X509_NAME* sk, void (*free_fn)(X509_NAME*)) {
  if (!sk) return;
  for (auto* n : sk->names) {
    if (free_fn) free_fn(n);
  }
  delete sk;
}

/* ===== X509_INFO stack ===== */
int sk_X509_INFO_num(const STACK_OF_X509_INFO* st) {
  return st ? static_cast<int>(st->items.size()) : 0;
}

X509_INFO* sk_X509_INFO_value(const STACK_OF_X509_INFO* st, int i) {
  if (!st || i < 0 || static_cast<size_t>(i) >= st->items.size()) return nullptr;
  return st->items[static_cast<size_t>(i)];
}

void X509_INFO_free(X509_INFO* info) {
  if (!info) return;
  if (info->x509) X509_free(info->x509);
  delete info;
}

void sk_X509_INFO_pop_free(STACK_OF_X509_INFO* st, void (*freefn)(X509_INFO*)) {
  if (!st) return;
  for (auto* i : st->items) {
    if (freefn) freefn(i);
  }
  delete st;
}

/* ===== PEM ===== */
X509* PEM_read_bio_X509(BIO* bp, X509** x, void* /*cb*/, void* /*u*/) {
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", pem)) {
    return nullptr;
  }

  auto* cert = new X509();
  int rc = mbedtls_x509_crt_parse(&cert->crt,
                                  reinterpret_cast<const unsigned char*>(pem.c_str()),
                                  pem.size() + 1);
  if (rc != 0) {
    delete cert;
    return nullptr;
  }
  refresh_x509_fields(cert);
  if (x) *x = cert;
  return cert;
}

X509* PEM_read_bio_X509_AUX(BIO* bp, X509** x, void* cb, void* u) {
  return PEM_read_bio_X509(bp, x, cb, u);
}

EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x, void* /*cb*/, void* u) {
  if (!bp) return nullptr;

  std::string pem;
  if (!next_pem_block(bp, "-----BEGIN", "-----END", pem)) return nullptr;

  auto* pkey = new EVP_PKEY();
  const unsigned char* pwd = u ? reinterpret_cast<const unsigned char*>(u) : nullptr;
  size_t pwd_len = u ? std::strlen(reinterpret_cast<const char*>(u)) : 0;

#if MBEDTLS_VERSION_MAJOR >= 3
  int rc = mbedtls_pk_parse_key(&pkey->pk,
                                reinterpret_cast<const unsigned char*>(pem.c_str()),
                                pem.size() + 1,
                                pwd,
                                pwd_len,
                                mbedtls_ctr_drbg_random,
                                nullptr);
#else
  int rc = mbedtls_pk_parse_key(&pkey->pk,
                                reinterpret_cast<const unsigned char*>(pem.c_str()),
                                pem.size() + 1,
                                pwd,
                                pwd_len);
#endif
  if (rc != 0) {
    delete pkey;
    return nullptr;
  }
  pkey->has_key = true;
  pkey->pem = pem;
  if (x) *x = pkey;
  return pkey;
}

int PEM_write_bio_X509(BIO* bp, X509* x) {
  if (!bp || !x || bp->kind != BioKind::Memory || !x->crt.raw.p) return 0;
  std::array<unsigned char, 8192> out{};
  size_t olen = 0;
  int rc = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                    "-----END CERTIFICATE-----\n",
                                    x->crt.raw.p,
                                    x->crt.raw.len,
                                    out.data(),
                                    out.size(),
                                    &olen);
  if (rc != 0) return 0;
  bp->data.insert(bp->data.end(), out.data(), out.data() + olen);
  return 1;
}

int PEM_write_bio_PrivateKey(BIO* bp, EVP_PKEY* x, const void* /*enc*/, unsigned char* /*kstr*/,
                             int /*klen*/, void* /*cb*/, void* /*u*/) {
  if (!bp || !x || bp->kind != BioKind::Memory || !x->has_key) return 0;
  if (!x->pem.empty()) {
    bp->data.insert(bp->data.end(), x->pem.begin(), x->pem.end());
    if (!x->pem.empty() && x->pem.back() != '\n') bp->data.push_back('\n');
    return 1;
  }

  std::array<unsigned char, 8192> out{};
  int rc = mbedtls_pk_write_key_pem(&x->pk, out.data(), out.size());
  if (rc != 0) return 0;
  auto len = std::strlen(reinterpret_cast<const char*>(out.data()));
  bp->data.insert(bp->data.end(), out.data(), out.data() + len);
  return 1;
}

STACK_OF_X509_INFO* PEM_X509_INFO_read_bio(BIO* bp, STACK_OF_X509_INFO* sk,
                                           void* /*cb*/, void* /*u*/) {
  if (!bp) return nullptr;
  if (!sk) sk = new STACK_OF_X509_INFO();

  while (true) {
    auto* cert = PEM_read_bio_X509(bp, nullptr, nullptr, nullptr);
    if (!cert) break;
    auto* info = new X509_INFO();
    info->x509 = cert;
    info->crl = nullptr;
    sk->items.push_back(info);
  }
  return sk;
}

/* ===== SSL methods/context ===== */
const SSL_METHOD* TLS_client_method(void) { return &g_client_method; }
const SSL_METHOD* TLS_server_method(void) { return &g_server_method; }
const SSL_METHOD* SSLv23_client_method(void) { return &g_client_method; }
const SSL_METHOD* SSLv23_server_method(void) { return &g_server_method; }

SSL_CTX* SSL_CTX_new(const SSL_METHOD* method) {
  auto* ctx = new SSL_CTX();
  ctx->is_client = !(method && method->endpoint == MBEDTLS_SSL_IS_SERVER);
  ctx->verify_mode = SSL_VERIFY_NONE;
  ctx->cert_store = X509_STORE_new();

  if (!setup_ssl_context(ctx)) {
    delete ctx;
    return nullptr;
  }

  return ctx;
}

void SSL_CTX_free(SSL_CTX* ctx) { delete ctx; }

void SSL_CTX_set_verify(SSL_CTX* ctx, int mode,
                        int (*verify_callback)(int, X509_STORE_CTX*)) {
  if (!ctx) return;
  ctx->verify_mode = mode;
  ctx->verify_callback = verify_callback;
  apply_ctx_verify_mode(ctx);
  apply_ctx_ca_store(ctx);
}

void SSL_CTX_set_verify_depth(SSL_CTX* ctx, int depth) {
  if (ctx) ctx->verify_depth = depth;
}

long SSL_CTX_set_mode(SSL_CTX* ctx, long mode) {
  if (!ctx) return 0;
  ctx->mode |= mode;
  return ctx->mode;
}

long SSL_CTX_clear_mode(SSL_CTX* ctx, long mode) {
  if (!ctx) return 0;
  ctx->mode &= ~mode;
  return ctx->mode;
}

long SSL_CTX_set_options(SSL_CTX* ctx, long options) {
  if (!ctx) return 0;
  ctx->options |= options;
  return ctx->options;
}

int SSL_CTX_set_session_cache_mode(SSL_CTX* ctx, int mode) {
  if (!ctx) return 0;
  ctx->session_cache_mode = mode;
  return mode;
}

static std::string normalize_cipher_token(std::string token) {
  token = trim(token);
  for (auto& c : token) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return token;
}

static void append_default_ciphers(std::vector<int>& out) {
  const int* defaults = mbedtls_ssl_list_ciphersuites();
  if (!defaults) return;
  for (const int* p = defaults; *p != 0; ++p) {
    out.push_back(*p);
  }
}

static bool add_cipher_from_token(const std::string& token, std::vector<int>& out) {
  const char* mbedtls_name = nullptr;
  if (token == "ECDHE-ECDSA-AES128-GCM-SHA256") {
    mbedtls_name = "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "ECDHE-ECDSA-AES256-GCM-SHA384") {
    mbedtls_name = "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "ECDHE-RSA-AES128-GCM-SHA256") {
    mbedtls_name = "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "ECDHE-RSA-AES256-GCM-SHA384") {
    mbedtls_name = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "DHE-RSA-AES128-GCM-SHA256") {
    mbedtls_name = "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "DHE-RSA-AES256-GCM-SHA384") {
    mbedtls_name = "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "AES128-GCM-SHA256") {
    mbedtls_name = "TLS-RSA-WITH-AES-128-GCM-SHA256";
  } else if (token == "AES256-GCM-SHA384") {
    mbedtls_name = "TLS-RSA-WITH-AES-256-GCM-SHA384";
  } else if (token == "ECDHE-ECDSA-CHACHA20-POLY1305" ||
             token == "ECDHE-ECDSA-CHACHA20-POLY1305-SHA256") {
    mbedtls_name = "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256";
  } else if (token == "ECDHE-RSA-CHACHA20-POLY1305" ||
             token == "ECDHE-RSA-CHACHA20-POLY1305-SHA256") {
    mbedtls_name = "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256";
  }

  if (!mbedtls_name) return false;
  int id = mbedtls_ssl_get_ciphersuite_id(mbedtls_name);
  if (id == 0) return false;
  out.push_back(id);
  return true;
}

static bool parse_cipher_list_string(const char* str, std::vector<int>& out) {
  if (!str) return false;
  std::string input(str);
  if (input.empty()) return false;

  std::vector<int> ciphers;
  std::string token;
  auto flush = [&]() {
    if (token.empty()) return;
    std::string normalized = normalize_cipher_token(token);
    token.clear();
    if (normalized.empty()) return;
    if (normalized[0] == '!') return;
    if (normalized == "DEFAULT" || normalized == "HIGH" || normalized == "SECURE") {
      append_default_ciphers(ciphers);
      return;
    }
    add_cipher_from_token(normalized, ciphers);
  };

  for (char ch : input) {
    if (ch == ':' || ch == ',' || ch == ';' || std::isspace(static_cast<unsigned char>(ch))) {
      flush();
    } else {
      token.push_back(ch);
    }
  }
  flush();

  if (ciphers.empty()) return false;
  out = std::move(ciphers);
  return true;
}

int SSL_CTX_set_cipher_list(SSL_CTX* ctx, const char* str) {
  if (!ctx || !str) return 0;
  std::vector<int> parsed;
  if (!parse_cipher_list_string(str, parsed)) {
    set_error_message("SSL_CTX_set_cipher_list: no matching cipher suites");
    return 0;
  }

  parsed.push_back(0);
  ctx->ciphersuites = std::move(parsed);
  ctx->ciphersuites_set = true;
  mbedtls_ssl_conf_ciphersuites(&ctx->conf, ctx->ciphersuites.data());
  return 1;
}

int SSL_CTX_set_ciphersuites(SSL_CTX* ctx, const char* str) {
  return SSL_CTX_set_cipher_list(ctx, str);
}

int SSL_CTX_load_verify_locations(SSL_CTX* ctx, const char* ca_file, const char* ca_path) {
  if (!ctx || !ctx->cert_store) return 0;
  bool loaded = false;

  if (ca_file && *ca_file) {
    loaded = load_ca_file_into_store(ctx->cert_store, ca_file) || loaded;
  }

  if (ca_path && *ca_path) {
    std::error_code ec;
    for (auto const& entry : std::filesystem::directory_iterator(ca_path, ec)) {
      if (ec) break;
      if (!entry.is_regular_file()) continue;
      auto p = entry.path().string();
      loaded = load_ca_file_into_store(ctx->cert_store, p.c_str()) || loaded;
    }
  }

  if (loaded) apply_ctx_ca_store(ctx);
  return loaded ? 1 : 0;
}

int SSL_CTX_set_default_verify_paths(SSL_CTX* ctx) {
  if (!ctx || !ctx->cert_store) return 0;
  bool loaded = load_default_ca_paths(ctx->cert_store);
  if (loaded) apply_ctx_ca_store(ctx);
  return loaded ? 1 : 0;
}

int SSL_CTX_default_verify_paths(SSL_CTX* ctx) {
  return SSL_CTX_set_default_verify_paths(ctx);
}

int SSL_CTX_use_certificate_file(SSL_CTX* ctx, const char* file, int /*type*/) {
  if (!ctx || !file) return 0;
  mbedtls_x509_crt_free(&ctx->own_cert_chain);
  mbedtls_x509_crt_init(&ctx->own_cert_chain);
  int rc = mbedtls_x509_crt_parse_file(&ctx->own_cert_chain, file);
  if (rc != 0) return 0;
  ctx->own_cert_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX* ctx, const char* file) {
  return SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX* ctx, const char* file, int /*type*/) {
  if (!ctx || !file) return 0;
  mbedtls_pk_free(&ctx->own_key);
  mbedtls_pk_init(&ctx->own_key);

#if MBEDTLS_VERSION_MAJOR >= 3
  int rc = mbedtls_pk_parse_keyfile(&ctx->own_key, file,
      ctx->passwd_userdata ? static_cast<const char*>(ctx->passwd_userdata) : nullptr,
      mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
#else
  int rc = mbedtls_pk_parse_keyfile(&ctx->own_key, file,
      ctx->passwd_userdata ? static_cast<const char*>(ctx->passwd_userdata) : nullptr);
#endif
  if (rc != 0) return 0;
  ctx->own_key_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_certificate(SSL_CTX* ctx, X509* x) {
  if (!ctx || !x || !x->crt.raw.p) return 0;
  mbedtls_x509_crt_free(&ctx->own_cert_chain);
  mbedtls_x509_crt_init(&ctx->own_cert_chain);
  int rc = mbedtls_x509_crt_parse_der(&ctx->own_cert_chain, x->crt.raw.p, x->crt.raw.len);
  if (rc != 0) return 0;
  ctx->own_cert_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_use_PrivateKey(SSL_CTX* ctx, EVP_PKEY* pkey) {
  if (!ctx || !pkey || !pkey->has_key) return 0;
  mbedtls_pk_free(&ctx->own_key);
  mbedtls_pk_init(&ctx->own_key);

  int rc = 0;
  if (!pkey->pem.empty()) {
#if MBEDTLS_VERSION_MAJOR >= 3
    rc = mbedtls_pk_parse_key(&ctx->own_key,
                              reinterpret_cast<const unsigned char*>(pkey->pem.c_str()),
                              pkey->pem.size() + 1,
                              nullptr,
                              0,
                              mbedtls_ctr_drbg_random,
                              &ctx->ctr_drbg);
#else
    rc = mbedtls_pk_parse_key(&ctx->own_key,
                              reinterpret_cast<const unsigned char*>(pkey->pem.c_str()),
                              pkey->pem.size() + 1,
                              nullptr,
                              0);
#endif
  } else {
    return 0;
  }

  if (rc != 0) return 0;
  ctx->own_key_loaded = true;
  return apply_ctx_own_cert(ctx) ? 1 : 0;
}

int SSL_CTX_check_private_key(const SSL_CTX* ctx) {
  if (!ctx || !ctx->own_cert_loaded || !ctx->own_key_loaded) return 0;
#if MBEDTLS_VERSION_MAJOR >= 3
  return mbedtls_pk_check_pair(&ctx->own_cert_chain.pk, &ctx->own_key,
                               mbedtls_ctr_drbg_random,
                               const_cast<mbedtls_ctr_drbg_context*>(&ctx->ctr_drbg)) == 0
             ? 1
             : 0;
#else
  return mbedtls_pk_check_pair(&ctx->own_cert_chain.pk, &ctx->own_key) == 0 ? 1 : 0;
#endif
}

void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX* ctx, void* u) {
  if (ctx) ctx->passwd_userdata = u;
}

X509_STORE* SSL_CTX_get_cert_store(const SSL_CTX* ctx) {
  return ctx ? ctx->cert_store : nullptr;
}

void SSL_CTX_set_cert_store(SSL_CTX* ctx, X509_STORE* store) {
  if (!ctx || !store) return;
  if (ctx->cert_store == store) return;
  if (ctx->cert_store) X509_STORE_free(ctx->cert_store);
  ctx->cert_store = store;
  apply_ctx_ca_store(ctx);
}

void SSL_CTX_set_client_CA_list(SSL_CTX* ctx, STACK_OF_X509_NAME* list) {
  if (!ctx) return;
  if (ctx->client_ca_list) sk_X509_NAME_pop_free(ctx->client_ca_list, X509_NAME_free);
  ctx->client_ca_list = list;
}

int SSL_CTX_set_min_proto_version(SSL_CTX* ctx, int version) {
  if (!ctx) return 0;
  ctx->min_proto_version = version;

  mbedtls_ssl_protocol_version v = MBEDTLS_SSL_VERSION_TLS1_2;
  switch (version) {
    case TLS1_VERSION:
    case TLS1_1_VERSION:
    case TLS1_2_VERSION:
      v = MBEDTLS_SSL_VERSION_TLS1_2;
      break;
#ifdef MBEDTLS_SSL_VERSION_TLS1_3
    case TLS1_3_VERSION:
      v = MBEDTLS_SSL_VERSION_TLS1_3;
      break;
#endif
    default:
      v = MBEDTLS_SSL_VERSION_TLS1_2;
      break;
  }

  mbedtls_ssl_conf_min_tls_version(&ctx->conf, v);
  return 1;
}

int SSL_CTX_set_alpn_protos(SSL_CTX* ctx, const unsigned char* protos, unsigned int len) {
  if (!ctx || !protos || len == 0) return 1;
  parse_alpn_blob(ctx, protos, len);
  return 0; // OpenSSL returns 0 on success
}

/* ===== SSL object ===== */
SSL* SSL_new(SSL_CTX* ctx) {
  if (!ctx) return nullptr;
  auto* ssl = new SSL();
  ssl->ctx = ctx;
  ssl->verify_mode = ctx->verify_mode;
  ssl->verify_callback = ctx->verify_callback;
  if (!setup_ssl_instance(ssl)) {
    delete ssl;
    return nullptr;
  }
  return ssl;
}

void SSL_free(SSL* ssl) { delete ssl; }

int SSL_set_fd(SSL* ssl, int fd) {
  if (!ssl) return 0;
  ssl->fd = fd;
  if (ssl->ssl_setup) {
    mbedtls_ssl_set_bio(&ssl->ssl, &ssl->fd, ssl_send_cb, ssl_recv_cb, nullptr);
  }
  return 1;
}

void SSL_set_bio(SSL* ssl, BIO* rbio, BIO* wbio) {
  if (!ssl) return;
  if (ssl->rbio) {
    if (ssl->wbio == ssl->rbio) BIO_free(ssl->rbio);
    else {
      BIO_free(ssl->rbio);
      if (ssl->wbio) BIO_free(ssl->wbio);
    }
  }
  ssl->rbio = rbio;
  ssl->wbio = wbio;

  if (rbio && rbio->kind == BioKind::Socket) {
    ssl->fd = rbio->fd;
    if (ssl->ssl_setup)
      mbedtls_ssl_set_bio(&ssl->ssl, &ssl->fd, ssl_send_cb, ssl_recv_cb, nullptr);
  }
}

BIO* SSL_get_rbio(const SSL* ssl) { return ssl ? ssl->rbio : nullptr; }

int SSL_set_tlsext_host_name(SSL* ssl, const char* name) {
  if (!ssl || !name) return 0;
  ssl->hostname = name;

  if (ssl->ssl_setup) {
    if (!ssl->hostname.empty() && !is_ip_literal(ssl->hostname)) {
      return mbedtls_ssl_set_hostname(&ssl->ssl, ssl->hostname.c_str()) == 0 ? 1 : 0;
    }
    return 1;
  }
  return 1;
}

long SSL_ctrl(SSL* ssl, int cmd, long larg, void* parg) {
  if (!ssl) return 0;
  if (cmd == SSL_CTRL_SET_TLSEXT_HOSTNAME && larg == TLSEXT_NAMETYPE_host_name) {
    return SSL_set_tlsext_host_name(ssl, static_cast<const char*>(parg));
  }
  return 0;
}

void SSL_set_verify(SSL* ssl, int mode,
                    int (*verify_callback)(int, X509_STORE_CTX*)) {
  if (!ssl) return;
  ssl->verify_mode = mode;
  ssl->verify_callback = verify_callback;
  if (ssl->ssl_setup && ssl->ctx) {
    int auth = MBEDTLS_SSL_VERIFY_NONE;
    if (mode & SSL_VERIFY_PEER) {
      auth = verify_mode_to_authmode(mode, !ssl->ctx->is_client);
    } else if (ssl->ctx->is_client && ctx_has_ca_store(ssl->ctx)) {
      auth = MBEDTLS_SSL_VERIFY_REQUIRED;
    } else if (!(mode & SSL_VERIFY_PEER) && (ssl->ctx->verify_mode & SSL_VERIFY_PEER)) {
      auth = verify_mode_to_authmode(ssl->ctx->verify_mode, !ssl->ctx->is_client);
    }
    mbedtls_ssl_set_hs_authmode(&ssl->ssl, auth);
  }
}

int SSL_set_ecdh_auto(SSL* /*ssl*/, int /*onoff*/) { return 1; }

int SSL_connect(SSL* ssl) {
  if (!ssl || !ssl->ssl_setup) return -1;

  int effective_verify_mode = ssl->verify_mode ? ssl->verify_mode : ssl->ctx->verify_mode;

  if (ssl->hostname.empty() && !ssl->param.host.empty()) {
    ssl->hostname = ssl->param.host;
  }

  if (!ssl->hostname.empty() && !is_ip_literal(ssl->hostname)) {
    mbedtls_ssl_set_hostname(&ssl->ssl, ssl->hostname.c_str());
  }

  ssl->ignore_verify_result = false;

  int ret = 0;
  do {
    ret = mbedtls_ssl_handshake(&ssl->ssl);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl->ssl);

    bool verify_disabled = !(effective_verify_mode & SSL_VERIFY_PEER);
    bool hostname_mismatch_only =
        (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) &&
        ((flags & ~MBEDTLS_X509_BADCERT_CN_MISMATCH) == 0);

    bool hostname_disabled_but_chain_ok =
        (ssl->param.host.empty() && !ssl->hostname.empty() && hostname_mismatch_only);

    if (verify_disabled || hostname_disabled_but_chain_ok) {
      ssl->ignore_verify_result = true;
      ret = 0;
    }
  }

  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);

  if (ret == 0) {
    if (!run_verify_callback_if_any(ssl)) {
      ssl->last_error = SSL_ERROR_SSL;
      set_error_message("verify callback rejected certificate");
      return -1;
    }
    if ((effective_verify_mode & SSL_VERIFY_PEER) && !ssl->param.host.empty()) {
      auto* cert = SSL_get_peer_certificate(ssl);
      bool ok = cert && cert_matches_hostname(cert, ssl->param.host, is_ip_literal(ssl->param.host));
      if (cert) X509_free(cert);
      if (!ok) {
        ssl->last_error = SSL_ERROR_SSL;
        set_error_message("hostname verification failed", X509_V_ERR_HOSTNAME_MISMATCH);
        return -1;
      }
    }
    auto* alpn = mbedtls_ssl_get_alpn_protocol(&ssl->ssl);
    ssl->selected_alpn = alpn ? alpn : "";
    return 1;
  }

  char err[256] = {0};
  mbedtls_strerror(ret, err, sizeof(err));
  set_error_message(std::string("SSL_connect failed: ") + err);
  return -1;
}

int SSL_accept(SSL* ssl) {
  if (!ssl || !ssl->ssl_setup) return -1;

  ssl->ignore_verify_result = false;

  int ret = 0;
  do {
    ret = mbedtls_ssl_handshake(&ssl->ssl);
  } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);

  if (ret == 0) {
    if (!run_verify_callback_if_any(ssl)) {
      ssl->last_error = SSL_ERROR_SSL;
      set_error_message("verify callback rejected peer certificate");
      return -1;
    }
    auto* alpn = mbedtls_ssl_get_alpn_protocol(&ssl->ssl);
    ssl->selected_alpn = alpn ? alpn : "";
    return 1;
  }

  char err[256] = {0};
  mbedtls_strerror(ret, err, sizeof(err));
  set_error_message(std::string("SSL_accept failed: ") + err);
  return -1;
}

int SSL_read(SSL* ssl, void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;

  if (!ssl->peeked_plaintext.empty()) {
    int n = std::min<int>(num, static_cast<int>(ssl->peeked_plaintext.size()));
    std::memcpy(buf, ssl->peeked_plaintext.data(), static_cast<size_t>(n));
    ssl->peeked_plaintext.erase(ssl->peeked_plaintext.begin(), ssl->peeked_plaintext.begin() + n);
    ssl->last_ret = n;
    ssl->last_error = SSL_ERROR_NONE;
    return n;
  }

  int ret = mbedtls_ssl_read(&ssl->ssl, static_cast<unsigned char*>(buf), static_cast<size_t>(num));
  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);
  if (ret < 0 && ssl->last_error == SSL_ERROR_SSL) {
    char err[256] = {0};
    mbedtls_strerror(ret, err, sizeof(err));
    set_error_message(std::string("SSL_read failed: ") + err);
  }
  return ret;
}

int SSL_write(SSL* ssl, const void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;
  int ret = mbedtls_ssl_write(&ssl->ssl, static_cast<const unsigned char*>(buf), static_cast<size_t>(num));
  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);
  if (ret < 0 && ssl->last_error == SSL_ERROR_SSL) {
    char err[256] = {0};
    mbedtls_strerror(ret, err, sizeof(err));
    set_error_message(std::string("SSL_write failed: ") + err);
  }
  return ret;
}

int SSL_peek(SSL* ssl, void* buf, int num) {
  if (!ssl || !buf || num <= 0) return -1;

  if (ssl->peeked_plaintext.empty()) {
    std::vector<unsigned char> tmp(static_cast<size_t>(num));
    int ret = mbedtls_ssl_read(&ssl->ssl, tmp.data(), tmp.size());
    ssl->last_ret = ret;
    ssl->last_error = map_mbedtls_to_ssl_error(ret);
    if (ret <= 0) return ret;
    ssl->peeked_plaintext.assign(tmp.begin(), tmp.begin() + ret);
  }

  int n = std::min<int>(num, static_cast<int>(ssl->peeked_plaintext.size()));
  std::memcpy(buf, ssl->peeked_plaintext.data(), static_cast<size_t>(n));
  ssl->last_ret = n;
  ssl->last_error = SSL_ERROR_NONE;
  return n;
}

int SSL_pending(const SSL* ssl) {
  if (!ssl) return 0;
  return static_cast<int>(ssl->peeked_plaintext.size()) +
         static_cast<int>(mbedtls_ssl_get_bytes_avail(&ssl->ssl));
}

int SSL_shutdown(SSL* ssl) {
  if (!ssl) return 0;
  int ret = mbedtls_ssl_close_notify(&ssl->ssl);
  ssl->last_ret = ret;
  ssl->last_error = map_mbedtls_to_ssl_error(ret);
  return ret == 0 ? 1 : 0;
}

int SSL_get_error(const SSL* ssl, int /*ret*/) {
  if (!ssl) return SSL_ERROR_SSL;
  return ssl->last_error;
}

X509* SSL_get_peer_certificate(const SSL* ssl) {
  if (!ssl) return nullptr;
  auto* cert = mbedtls_ssl_get_peer_cert(&ssl->ssl);
  if (!cert || !cert->raw.p) return nullptr;
  return x509_from_der(cert->raw.p, cert->raw.len);
}

X509* SSL_get1_peer_certificate(const SSL* ssl) { return SSL_get_peer_certificate(ssl); }

long SSL_get_verify_result(const SSL* ssl) {
  if (!ssl) return X509_V_ERR_UNSPECIFIED;
  if (ssl->ignore_verify_result) return X509_V_OK;
  uint32_t flags = mbedtls_ssl_get_verify_result(&ssl->ssl);
  if (flags == 0) return X509_V_OK;
  if (flags & MBEDTLS_X509_BADCERT_EXPIRED) return X509_V_ERR_CERT_HAS_EXPIRED;
  if (flags & MBEDTLS_X509_BADCERT_FUTURE) return X509_V_ERR_CERT_NOT_YET_VALID;
  if (flags & MBEDTLS_X509_BADCERT_REVOKED) return X509_V_ERR_CERT_REVOKED;
  if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) return X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
  return X509_V_ERR_UNSPECIFIED;
}

X509_VERIFY_PARAM* SSL_get0_param(SSL* ssl) {
  if (!ssl) return nullptr;
  return &ssl->param;
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void) { return 0; }

const char* SSL_get_servername(const SSL* ssl, const int type) {
  if (!ssl || type != TLSEXT_NAMETYPE_host_name) return nullptr;
  return ssl->hostname.empty() ? nullptr : ssl->hostname.c_str();
}

void SSL_get0_alpn_selected(const SSL* ssl, const unsigned char** data, unsigned int* len) {
  if (data) *data = nullptr;
  if (len) *len = 0;
  if (!ssl || ssl->selected_alpn.empty()) return;
  if (data) *data = reinterpret_cast<const unsigned char*>(ssl->selected_alpn.data());
  if (len) *len = static_cast<unsigned int>(ssl->selected_alpn.size());
}

void SSL_clear_mode(SSL* ssl, long mode) {
  if (!ssl || !ssl->ctx) return;
  ssl->ctx->mode &= ~mode;
}

STACK_OF_X509_NAME* SSL_load_client_CA_file(const char* file) {
  if (!file) return nullptr;
  mbedtls_x509_crt chain;
  mbedtls_x509_crt_init(&chain);
  if (mbedtls_x509_crt_parse_file(&chain, file) < 0) {
    mbedtls_x509_crt_free(&chain);
    return nullptr;
  }

  auto* list = sk_X509_NAME_new_null();
  for (mbedtls_x509_crt* p = &chain; p && p->raw.p; p = p->next) {
    auto* tmp = x509_from_der(p->raw.p, p->raw.len);
    if (!tmp) continue;
    auto* dup = X509_NAME_dup(X509_get_subject_name(tmp));
    if (dup) sk_X509_NAME_push(list, dup);
    X509_free(tmp);
  }
  mbedtls_x509_crt_free(&chain);

  if (sk_X509_NAME_num(list) == 0) {
    sk_X509_NAME_free(list);
    return nullptr;
  }
  return list;
}

} // extern "C"
