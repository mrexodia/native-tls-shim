# native-tls-shim

OpenSSL header shim for projects that expect `openssl/*` APIs (notably `cpp-httplib` and `IXWebSocket`).

## Status

- ✅ OpenSSL-compatible header surface (`openssl/`)
- ✅ mbedTLS-backed implementation (current functional backend)
- 🚧 Schannel backend placeholders (`src/tls_schannel.*`)
- 🚧 Apple Security backend placeholders (`src/tls_apple.*`)

## Build

```bash
cmake -S . -B build -DNATIVE_TLS_SHIM_BACKEND=MBEDTLS
cmake --build build
```

When this project is the **top-level** CMake project, tests/examples are
enabled by default.
When consumed via **FetchContent/add_subdirectory**, tests/examples/install
rules are disabled by default to avoid target pollution.

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

## Current mbedTLS backend note

For interoperability and compatibility with verification-disabled mode,
the mbedTLS backend is currently configured with a TLS 1.2 max version.
TLS 1.3 enablement can be revisited once verification behavior is aligned
across all compatibility paths.
