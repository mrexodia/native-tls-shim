#include <httplib.h>

#include "tls_paths.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
  std::string cert = ix_cert("trusted-server-crt.pem");
  std::string key = ix_cert("trusted-server-key.pem");
  std::string ca = ix_cert("trusted-ca-crt.pem");

  httplib::SSLServer svr(cert.c_str(), key.c_str());
  if (!svr.is_valid()) {
    std::cerr << "SSLServer init failed\n";
    return 1;
  }

  svr.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("pong", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9443); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", 9443);
  cli.set_ca_cert_path(ca.c_str());
  auto res = cli.Get("/ping");

  svr.stop();
  if (t.joinable()) t.join();

  if (!res) {
    std::cerr << "roundtrip failed, error=" << static_cast<int>(res.error()) << "\n";
    return 1;
  }

  return (res->status == 200 && res->body == "pong") ? 0 : 1;
}
