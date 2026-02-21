#include <httplib.h>

#include "tls_paths.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
  std::string cert = ix_cert("trusted-server-crt.pem");
  std::string key = ix_cert("trusted-server-key.pem");
  std::string spoofed_ca = ix_cert("spoofed-ca-crt.pem");

  httplib::SSLServer svr(cert.c_str(), key.c_str());
  if (!svr.is_valid()) {
    std::cerr << "SSLServer init failed" << "\n";
    return 1;
  }

  svr.Get("/spoof", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9471); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", 9471);
  cli.set_ca_cert_path(spoofed_ca.c_str());
  cli.enable_server_certificate_verification(true);
  cli.enable_server_hostname_verification(false);

  auto res = cli.Get("/spoof");

  svr.stop();
  if (t.joinable()) t.join();

  if (res) {
    std::cerr << "spoofed CA unexpectedly trusted" << "\n";
    return 1;
  }

  auto err = res.error();
  bool ok = (err == httplib::Error::SSLServerVerification ||
             err == httplib::Error::SSLConnection ||
             err == httplib::Error::SSLServerHostnameVerification);
  return ok ? 0 : 1;
}
