#include <httplib.h>

#include "tls_paths.h"

#include <openssl/ssl.h>

#include <chrono>
#include <iostream>
#include <thread>

int main() {
#if defined(NATIVE_TLS_SHIM_BACKEND_SCHANNEL)
  std::cout << "Skipping TLS 1.3-only test on Schannel backend\n";
  return 0;
#endif

  const int port = 9471;
  std::string cert = ix_cert("trusted-server-crt.pem");
  std::string key = ix_cert("trusted-server-key.pem");
  std::string ca = ix_cert("trusted-ca-crt.pem");

  httplib::SSLServer svr(cert.c_str(), key.c_str());
  if (!svr.is_valid()) {
    std::cerr << "SSLServer init failed\n";
    return 1;
  }
  if (auto* ctx = svr.ssl_context()) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  }

  svr.Get("/tls13", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", port); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", port);
  cli.set_ca_cert_path(ca.c_str());
  if (auto* ctx = cli.ssl_context()) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  }

  auto res = cli.Get("/tls13");

  svr.stop();
  if (t.joinable()) t.join();

  if (!res) {
    std::cerr << "TLS 1.3 request failed, error=" << static_cast<int>(res.error()) << "\n";
    return 1;
  }

  return (res->status == 200 && res->body == "ok") ? 0 : 1;
}
