# native-tls-shim

OpenSSL header shim for projects that expect `openssl/*` APIs (notably `cpp-httplib` and `IXWebSocket`).

## Status

- ✅ OpenSSL-compatible header surface (`openssl/`)
- ✅ mbedTLS-backed implementation
- ✅ Schannel backend implementation on Windows (`src/tls_schannel.*`) with no mbedTLS dependency
- ✅ Apple Security (SecureTransport) backend on macOS (`src/tls_apple.*`)

## Build

`NATIVE_TLS_SHIM_BACKEND` supports `AUTO`, `MBEDTLS`, `SCHANNEL`, and `APPLE`.
`AUTO` selects SCHANNEL on Windows, APPLE on macOS, and MBEDTLS elsewhere.

Example mbedTLS build:

```bash
cmake -S . -B build -DNATIVE_TLS_SHIM_BACKEND=MBEDTLS
cmake --build build
```

For Schannel backend build (no mbedTLS dependency):

```bash
cmake -S . -B build-schannel -DNATIVE_TLS_SHIM_BACKEND=SCHANNEL -DNATIVE_TLS_SHIM_FETCH_MBEDTLS=OFF
cmake --build build-schannel
```

For Apple backend build (no mbedTLS dependency):

```bash
cmake -S . -B build-apple -DNATIVE_TLS_SHIM_BACKEND=APPLE -DNATIVE_TLS_SHIM_FETCH_MBEDTLS=OFF
cmake --build build-apple
```

When this project is the **top-level** CMake project, tests/examples are
enabled by default.
When consumed via **FetchContent/add_subdirectory**, tests/examples/install
rules are disabled by default to avoid target pollution.

## Examples

Built example targets include:

- `httplib_example`
- `httplib_https_server_example` (HTTPS server on `https://localhost:8443`)
- `ixwebsocket_example` (WSS client; accepts args)
- `ixwebsocket_wss_server_example` (WSS echo server on `wss://localhost:9450`)

The server examples use pre-generated localhost certificates from
`test/fixtures` (`trusted-server-crt.pem`, `trusted-server-key.pem`).

`ixwebsocket_example` usage:

```bash
ixwebsocket_example [url] [ca_file] [message]
# example against local WSS server:
ixwebsocket_example wss://127.0.0.1:9450 test/fixtures/trusted-ca-crt.pem hello
```

## FetchContent usage

```cmake
include(FetchContent)

FetchContent_Declare(native_tls_shim
  GIT_REPOSITORY <this-repo-url>
  GIT_TAG main)
FetchContent_MakeAvailable(native_tls_shim)

# then add dependencies that call find_package(OpenSSL)
# (native_tls_shim propagates its FindOpenSSL module path)
```

The project defines:

- `OpenSSL::SSL`
- `OpenSSL::Crypto`

both forwarding to `native_tls_shim`.

## Install + find_package(OpenSSL)

```bash
cmake -S . -B build -DNATIVE_TLS_SHIM_ENABLE_INSTALL=ON
cmake --build build --target install
```

This installs an `OpenSSLConfig.cmake` package so downstream projects can resolve
`find_package(OpenSSL)` to this shim.

## Tests

Integration tests are in `test/` and use direct `add_subdirectory` of:

- `test/cpp-httplib`
- `test/IXWebSocket`

with `CPPHTTPLIB_OPENSSL_SUPPORT` and `IXWEBSOCKET_USE_OPEN_SSL` active.

TLS fixture certificates are provided in:

- `test/fixtures`

Current test set covers:

- cpp-httplib HTTPS client
- cpp-httplib local SSL server roundtrip
- cpp-httplib peer verification disabled
- cpp-httplib hostname mismatch failure
- cpp-httplib in-memory CA loading
- cpp-httplib peer certificate inspection callback
- cpp-httplib mTLS (client cert required)
- EVP MD5/SHA-256 vectors
- IXWebSocket public WSS client
- IXWebSocket local WSS server roundtrip
- IXWebSocket peer verification disabled
- IX Http TLS matrix (trusted/untrusted/hostname/in-memory-CA)
- IXWebSocket mTLS (client cert required)

## Cipher suites

The Apple SecureTransport backend defaults to AEAD-only cipher suites
(AES-GCM and ChaCha20-Poly1305). `SSL_CTX_set_cipher_list` and
`SSL_CTX_set_ciphersuites` accept OpenSSL-style tokens, but are filtered
to AEAD suites; empty/unsupported lists are rejected.

## Current mbedTLS backend note

For interoperability and compatibility with verification-disabled mode,
the mbedTLS backend is currently configured with a TLS 1.2 max version.
TLS 1.3 enablement can be revisited once verification behavior is aligned
across all compatibility paths.
