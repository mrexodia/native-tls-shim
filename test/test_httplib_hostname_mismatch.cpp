#include <httplib.h>

#include "tls_paths.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
  std::string cert = ix_cert("wrong-name-server-crt.pem");
  std::string key = ix_cert("wrong-name-server-key.pem");
  std::string ca = ix_cert("trusted-ca-crt.pem");

  httplib::SSLServer svr(cert.c_str(), key.c_str());
  if (!svr.is_valid()) return 1;

  svr.Get("/hn", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9460); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", 9460);
  cli.set_ca_cert_path(ca.c_str());
  cli.enable_server_certificate_verification(true);
  cli.enable_server_hostname_verification(true);

  auto res = cli.Get("/hn");

  svr.stop();
  if (t.joinable()) t.join();

  if (res) {
    std::cerr << "hostname mismatch test unexpectedly succeeded\n";
    return 1;
  }

  auto e = res.error();
  bool ok = (e == httplib::Error::SSLServerHostnameVerification ||
             e == httplib::Error::SSLServerVerification);
  return ok ? 0 : 1;
}
