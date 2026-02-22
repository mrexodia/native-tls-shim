# C++ libraries that use OpenSSL and could work with a native-TLS shim

**A shim providing OpenSSL-compatible headers backed by platform-native TLS (Schannel, SecureTransport, mbedTLS) can support the vast majority of popular C++ networking libraries.** The core OpenSSL API surface used across these libraries is remarkably consistent — `SSL_CTX_new/free`, `SSL_new/free`, `SSL_read/write`, `SSL_connect/accept`, certificate loading, and `ERR_*` error handling appear in virtually every library. The biggest differentiator for shim feasibility is whether a library only uses `libssl` (TLS) APIs or also requires `libcrypto` (EVP ciphers, HMAC, RSA, EC) for non-TLS operations. Libraries that only need TLS are excellent shim candidates; those requiring deep cryptographic primitives are substantially harder.

---

## Tier 1: Excellent shim candidates with contained OpenSSL usage

These libraries include OpenSSL headers directly in isolated files, use a moderate and well-defined API surface, and several already support multiple TLS backends — proving the abstraction is feasible.

**cpp-httplib** (~14k stars, [github.com/yhirose/cpp-httplib](https://github.com/yhirose/cpp-httplib)) enables OpenSSL via `#define CPPHTTPLIB_OPENSSL_SUPPORT` and already supports mbedTLS as an alternative backend. It includes `openssl/ssl.h`, `openssl/err.h`, and `openssl/x509.h` directly. The existing multi-backend design confirms the API surface is abstractable. This is the canonical example of a library the shim targets.

**uWebSockets / uSockets** (~18k stars, [github.com/uNetworking/uWebSockets](https://github.com/uNetworking/uWebSockets)) isolates all OpenSSL code in a single C file (`uSockets/src/crypto/openssl.c`), enabled by `LIBUS_USE_OPENSSL`. It includes `openssl/ssl.h`, `openssl/bio.h`, `openssl/err.h`, and `openssl/x509v3.h`. Already supports WolfSSL and BoringSSL as alternatives. The clean single-file isolation makes this an **ideal shim target**.

**mongoose** (~12.5k stars, [github.com/cesanta/mongoose](https://github.com/cesanta/mongoose)) confines OpenSSL to `src/tls_openssl.c`, activated by `-DMG_TLS=MG_TLS_OPENSSL`. Headers: `openssl/ssl.h`, `openssl/err.h`, `openssl/x509.h`, `openssl/pem.h`, `openssl/bio.h`, `openssl/crypto.h`. Supports **four** TLS backends (OpenSSL, mbedTLS, WolfSSL, and a built-in TLS 1.3 implementation with zero dependencies). The layered architecture and single-file isolation make shimming trivial.

**Oat++ (oatpp)** (~8k stars, [github.com/oatpp/oatpp](https://github.com/oatpp/oatpp)) uses a fully pluggable `ConnectionProvider` interface with separate modules: `oatpp-openssl`, `oatpp-libressl`, and `oatpp-mbedtls`. OpenSSL usage is contained within the `oatpp-openssl` module. The plugin architecture means one could simply create an `oatpp-nativetls` provider without touching OpenSSL at all, or shim the existing OpenSSL module.

**Drogon / Trantor** (~13.5k stars, [github.com/drogonframework/drogon](https://github.com/drogonframework/drogon)) isolates OpenSSL in `trantor/net/inner/tlsprovider/OpenSSLProvider.cc` behind a `TLSProvider` abstraction, selected via `TRANTOR_USE_TLS=openssl`. Includes `openssl/ssl.h`, `openssl/err.h`, `openssl/x509.h`, and uses `SSL_CONF_cmd()` for configuration. Already supports **Botan** as an alternative backend. The provider architecture proves backend-swappability, and a shim would only need to satisfy one contained source file.

| Library | Stars | Compile flag | OpenSSL headers | Alt backends | Isolation |
|---------|-------|-------------|-----------------|--------------|-----------|
| cpp-httplib | ~14k | `CPPHTTPLIB_OPENSSL_SUPPORT` | ssl.h, err.h, x509.h | mbedTLS | Internal abstraction |
| uWebSockets | ~18k | `LIBUS_USE_OPENSSL` | ssl.h, bio.h, err.h, x509v3.h | WolfSSL, BoringSSL | Single C file |
| mongoose | ~12.5k | `MG_TLS=MG_TLS_OPENSSL` | ssl.h, err.h, x509.h, pem.h, bio.h | mbedTLS, WolfSSL, built-in | Single C file |
| Oat++ | ~8k | Separate module | In oatpp-openssl module | LibreSSL, mbedTLS | Plugin module |
| Drogon/Trantor | ~13.5k | `TRANTOR_USE_TLS=openssl` | ssl.h, err.h, x509.h | Botan | Provider file |

---

## Tier 2: High compatibility through Boost.Asio's SSL layer

A large family of C++ libraries delegate TLS entirely to Boost.Asio (or standalone Asio), which itself wraps OpenSSL through `boost/asio/ssl/detail/openssl_types.hpp`. **Making the shim work with Boost.Asio automatically enables all of these libraries.** Asio includes `openssl/ssl.h`, `openssl/err.h`, `openssl/conf.h`, `openssl/engine.h`, `openssl/dh.h`, `openssl/rsa.h`, `openssl/x509.h`, and `openssl/x509v3.h`. It uses BIO pairs for async I/O and exposes `native_handle()` for raw `SSL*` access. The API surface is broad but standard.

**Crow** (~4.5k stars, [github.com/CrowCpp/Crow](https://github.com/CrowCpp/Crow)) has **zero direct OpenSSL calls** — it delegates entirely to Asio's `ssl::context` and `ssl::stream` via `CROW_ENABLE_SSL`. This is the easiest Asio-based library to support.

**websocketpp** (~7.5k stars, [github.com/zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp)) uses `websocketpp/transport/asio/security/tls.hpp` wrapping Boost.Asio SSL. No direct OpenSSL includes. TLS configs (`asio_tls`, `asio_tls_client`) require OpenSSL at link time.

**Restbed** (~1.9k stars, [github.com/Corvusoft/restbed](https://github.com/Corvusoft/restbed)) uses Asio SSL for most TLS, plus a few direct calls to `SSL_set_cipher_list()` and `SSL_set_renegotiate_mode()` guarded by `BUILD_SSL`. Has been tested with BoringSSL.

**mailio** (~400 stars, [github.com/karastojko/mailio](https://github.com/karastojko/mailio)) is an SMTP/POP3/IMAP library using Boost.Asio SSL. OpenSSL is mandatory (no alternative backends). All TLS goes through `boost::asio::ssl::stream`.

**cpp-netlib** (~2k stars, [github.com/cpp-netlib/cpp-netlib](https://github.com/cpp-netlib/cpp-netlib)) enables HTTPS via `CPP-NETLIB_ENABLE_HTTPS=ON`, using Boost.Asio SSL. No direct OpenSSL calls.

**Cinatra** (~2k stars, [github.com/qicosmos/cinatra](https://github.com/qicosmos/cinatra)) is a C++20 HTTP framework using Asio SSL. All OpenSSL access is indirect through Asio's wrapper.

The key insight: **Boost.Asio's SSL layer is the single most important shim target.** Making `native-tls-shim` work with Boost.Asio automatically unlocks Crow, websocketpp, Restbed, mailio, cpp-netlib, Cinatra, and any other Asio-based library. Asio's OpenSSL usage is concentrated in `boost/asio/ssl/detail/impl/engine.ipp` and `openssl_init.ipp`, which call `SSL_CTX_new`, `SSL_new`, `SSL_read/write`, `BIO_new/read/write`, `SSL_CTX_set_verify`, `SSL_CTX_load_verify_locations`, `ERR_get_error`, and related functions.

---

## Tier 3: Good candidates with moderate OpenSSL surface

**Pistache** (~3.2k stars, [github.com/pistacheio/pistache](https://github.com/pistacheio/pistache)) uses raw OpenSSL calls directly in its listener and transport code, guarded by `PISTACHE_USE_SSL`. Headers: `openssl/ssl.h`, `openssl/err.h`. Uses `SSL_set_fd()`, `SSL_accept()`, `SSL_read/write()` directly (socket-level, not through Asio). Has RAII wrappers (`SSLCtxPtr`, `SSLBioPtr`) in `ssl_wrappers.h`. No alternative backends. The API surface is moderate and well-contained.

**Mosquitto** (~9k stars, [github.com/eclipse-mosquitto/mosquitto](https://github.com/eclipse-mosquitto/mosquitto)) includes `openssl/ssl.h` and `openssl/err.h` in `tls_mosq.c` and `net_mosq.c`, guarded by `WITH_TLS`. Uses `SSL_CTX_new()`, `SSL_CTX_set_cipher_list()`, `SSL_CTX_set_alpn_protos()`, ENGINE APIs (conditional on `OPENSSL_NO_ENGINE`), and `OPENSSL_VERSION_NUMBER` checks for API compatibility. Also works with LibreSSL. The ENGINE usage and version-conditional code add complexity, but the overall surface is manageable.

**Eclipse Paho MQTT C/C++** (C: ~1.9k stars, C++: ~1.2k stars, [github.com/eclipse-paho/paho.mqtt.c](https://github.com/eclipse-paho/paho.mqtt.c)) enables OpenSSL via `PAHO_WITH_SSL=ON`, which defines the `OPENSSL` preprocessor macro. The C++ library delegates entirely to the C library for TLS. Uses `openssl/ssl.h` and standard SSL context/session APIs. Also supports LibreSSL.

**libevent** (~11k stars, [github.com/libevent/libevent](https://github.com/libevent/libevent)) builds a separate `libevent_openssl` library containing `bufferevent_openssl.c`. Exposes `SSL*` objects through its public API (`bufferevent_openssl_socket_new()`). Uses `SSL_set_shutdown()`, `SSL_shutdown()`, `SSL_renegotiate()`. Currently OpenSSL-only for its SSL bufferevent layer (mbedTLS support has been discussed but not implemented).

**nghttp2** (~4.7k stars, [github.com/nghttp2/nghttp2](https://github.com/nghttp2/nghttp2)) has a **zero-dependency core library** (`libnghttp2`). Only the bundled tools (`nghttp`, `nghttpx`, `h2load`) require OpenSSL for TLS. Uses `openssl/ssl.h`, `openssl/err.h`, `openssl/conf.h` with ALPN support (`SSL_CTX_set_alpn_protos()`). Supports WolfSSL, LibreSSL, AWS-LC, and BoringSSL as alternatives.

---

## Tier 4: Curl-based libraries — shim may be unnecessary

**libcurl already supports platform-native TLS** via its vtls abstraction: Schannel on Windows (`--with-schannel`), and wolfSSL/mbedTLS/Rustls on other platforms. On macOS, SecureTransport support has been **removed from recent curl versions** (Apple deprecated it; only TLS 1.2). This means curl-based libraries may not need an OpenSSL shim at all on Windows, but macOS remains a gap.

**curlpp** (~1.8k stars, [github.com/jpbarrette/curlpp](https://github.com/jpbarrette/curlpp)) contains **zero OpenSSL includes** — it is a pure C++ wrapper around libcurl. All TLS is handled by libcurl's backend. No shim needed; just build libcurl with the desired TLS backend.

**cpr** (~7.3k stars, [github.com/libcpr/cpr](https://github.com/libcpr/cpr)) has one file (`cpr/ssl_ctx.cpp`) that conditionally includes `openssl/bio.h`, `openssl/err.h`, `openssl/pem.h`, `openssl/ssl.h`, `openssl/x509.h` when `OPENSSL_BACKEND_USED` is defined. This code implements loading CA certificates from memory buffers via `CURLOPT_SSL_CTX_FUNCTION`. On Windows, `CPR_FORCE_WINSSL_BACKEND=ON` avoids OpenSSL entirely. On Linux, the shim would need to provide `SSL_CTX`, `X509_STORE`, `BIO`, and `PEM_read_bio_X509` — a narrow surface focused on certificate manipulation.

**Azure SDK for C++** (~600 stars, [github.com/Azure/azure-sdk-for-cpp](https://github.com/Azure/azure-sdk-for-cpp)) uses WinHTTP on Windows (no OpenSSL needed) and libcurl on Linux/macOS. Design guidelines explicitly prohibit OpenSSL types in public headers. Minimal internal crypto usage (HMAC-SHA256 for Storage auth). On Windows, the OpenSSL dependency was **completely eliminated** in November 2023.

---

## Tier 5: Challenging targets requiring deep crypto API coverage

These libraries use OpenSSL's `libcrypto` extensively for cryptographic primitives beyond TLS — symmetric ciphers, HMAC, key derivation, X509 manipulation, PKCS12, and more. A TLS-only shim is insufficient; these require a comprehensive `libcrypto` implementation.

**POCO C++ Libraries** (~8.5k stars, [github.com/pocoproject/poco](https://github.com/pocoproject/poco)) has the widest API surface of any library studied. Its `NetSSL_OpenSSL` and `Crypto` modules include `openssl/ssl.h`, `openssl/evp.h`, `openssl/rsa.h`, `openssl/ec.h`, `openssl/dh.h`, `openssl/bn.h`, `openssl/pem.h`, `openssl/pkcs12.h`, `openssl/x509v3.h`, `openssl/core_names.h` (OpenSSL 3.0+), and `openssl/fips.h`. However, POCO already has a **`NetSSL_Win` module** using Schannel with an identical public API, proving the architecture supports backend swapping at the Poco API level.

**aws-sdk-cpp** (~2.2k stars, [github.com/aws/aws-sdk-cpp](https://github.com/aws/aws-sdk-cpp)) uses OpenSSL for **cryptographic operations independent of TLS**: AES-CBC/CTR/GCM encryption, HMAC-SHA256 for Sigv4 request signing, SHA-256/MD5 hashing, and `RAND_bytes()` for secure random. Headers: `openssl/evp.h`, `openssl/err.h`, `openssl/hmac.h`, `openssl/rand.h`. On Windows it uses BCrypt (no OpenSSL), on macOS it can use CommonCrypto (`-DENABLE_COMMONCRYPTO_ENCRYPTION=ON`). The shim would need to implement ~30+ EVP cipher and HMAC APIs. TLS itself goes through libcurl.

**gRPC C++** (~43.9k stars, [github.com/grpc/grpc](https://github.com/grpc/grpc)) defaults to BoringSSL but supports OpenSSL via `gRPC_SSL_PROVIDER=package`. Its `ssl_transport_security.cc` includes `openssl/bio.h`, `openssl/crypto.h`, `openssl/engine.h`, `openssl/err.h`, `openssl/ssl.h`, `openssl/tls1.h`, `openssl/x509.h`, `openssl/x509v3.h`. Uses ENGINE API, ALPN callbacks, X509v3 extensions, and version-conditional code (`OPENSSL_VERSION_NUMBER`). The broad surface and ENGINE usage make shimming non-trivial, but compatibility with both BoringSSL and OpenSSL proves the API subset is well-defined.

**Proxygen / Fizz** (Proxygen ~8.3k stars, [github.com/facebook/proxygen](https://github.com/facebook/proxygen); Fizz ~3.5k stars) implements its own TLS 1.3 state machine and uses OpenSSL **only for crypto primitives** (`openssl/evp.h`, `openssl/hmac.h`, `openssl/aes.h`). The dependency chain is Proxygen → Wangle → Fizz → OpenSSL. Not a practical shim target.

**libwebsockets** (~5k stars, [github.com/warmcat/libwebsockets](https://github.com/warmcat/libwebsockets)) has well-organized TLS code in `lib/tls/openssl/` with a parallel mbedTLS backend. However, it uses an extremely wide API surface: `openssl/ssl.h`, `openssl/evp.h`, `openssl/bio.h`, `openssl/pem.h`, `openssl/rand.h`, `openssl/hmac.h`, `openssl/sha.h`, `openssl/rsa.h`, `openssl/ec.h`, `openssl/dh.h`, `openssl/aes.h`, `openssl/ocsp.h`, and more. Supports mbedTLS, BoringSSL, LibreSSL, AWS-LC, and WolfSSL as alternatives.

---

## The minimum viable shim: which OpenSSL APIs matter most

Across all 25+ libraries analyzed, the OpenSSL API usage follows a clear Pareto distribution. A shim implementing the following headers would cover the Tier 1 and Tier 2 libraries (representing **~80% of the target ecosystem**):

- **`openssl/ssl.h`** — Used by every library. Core functions: `SSL_CTX_new/free`, `SSL_new/free`, `SSL_read`, `SSL_write`, `SSL_connect`, `SSL_accept`, `SSL_shutdown`, `SSL_get_error`, `SSL_CTX_use_certificate_chain_file`, `SSL_CTX_use_PrivateKey_file`, `SSL_CTX_set_verify`, `SSL_CTX_load_verify_locations`, `SSL_CTX_set_cipher_list`, `SSL_CTX_set_min_proto_version`, `SSL_CTX_set_alpn_protos`, `SSL_CTX_set_alpn_select_cb`, `SSL_set_tlsext_host_name` (SNI)
- **`openssl/err.h`** — Used by nearly all. Functions: `ERR_get_error`, `ERR_error_string`, `ERR_error_string_n`, `ERR_clear_error`, `ERR_print_errors_fp`
- **`openssl/x509.h`** / **`openssl/x509v3.h`** — Certificate handling. Functions: `X509_free`, `X509_STORE_add_cert`, `SSL_CTX_get_cert_store`, `X509_STORE_CTX_get_ex_data`
- **`openssl/bio.h`** — BIO abstraction. Functions: `BIO_new`, `BIO_new_mem_buf`, `BIO_read`, `BIO_write`, `BIO_free`. Critical for Boost.Asio (uses BIO pairs for async I/O)
- **`openssl/pem.h`** — Certificate loading from buffers: `PEM_read_bio_X509`, `PEM_read_bio_PrivateKey`
- **`openssl/crypto.h`** — `OPENSSL_free`, `OPENSSL_VERSION_NUMBER`, init functions
- **`openssl/opensslv.h`** — Version macros

**ALPN support is critical** for HTTP/2: `SSL_CTX_set_alpn_protos()` and `SSL_CTX_set_alpn_select_cb()` appear in Drogon, gRPC, nghttp2, Mosquitto, and any library supporting HTTP/2.

**Version-conditional code is universal.** Libraries check `OPENSSL_VERSION_NUMBER` to branch between OpenSSL 1.0.x (`SSL_library_init`), 1.1.x (`OPENSSL_init_ssl`), and 3.x APIs. The shim should report a version ≥ 1.1.1 to trigger modern code paths and avoid deprecated API requirements.

---

## Libraries where a shim is unnecessary

**nng** (~4.4k stars) defaults to mbedTLS and has a pluggable TLS engine interface — a custom engine plugin is the better approach than shimming OpenSSL. **libmicrohttpd** uses GnuTLS exclusively and has no OpenSSL code. **curlpp** and the **Azure SDK for C++ on Windows** have zero OpenSSL dependency. **POCO** already ships `NetSSL_Win` using Schannel natively. For curl-based libraries on Windows, building libcurl with Schannel eliminates the need for any OpenSSL shim.

## Conclusion

The native-tls-shim project has a clearly viable path. The **minimum viable shim** covering `openssl/ssl.h`, `openssl/err.h`, `openssl/bio.h`, `openssl/x509.h`, `openssl/pem.h`, and `openssl/crypto.h` — implementing roughly **40–50 core functions** — would unlock compatibility with cpp-httplib, uWebSockets, mongoose, Crow, Drogon, Pistache, Restbed, websocketpp, Mosquitto, Paho MQTT, libevent, mailio, Cinatra, cpp-netlib, Oat++, and every Boost.Asio-based library. The hardest gap is `libcrypto` primitives (EVP ciphers, HMAC, RSA/EC key operations) needed by aws-sdk-cpp, POCO's Crypto module, gRPC, libwebsockets, and Proxygen — but these libraries already have platform-native crypto alternatives on Windows and macOS. Boost.Asio is the single highest-leverage target: making the shim work with Asio's SSL layer automatically enables at least six downstream libraries with zero additional effort.