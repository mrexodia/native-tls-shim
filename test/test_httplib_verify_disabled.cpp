#include <httplib.h>

#include "tls_paths.h"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
  std::string cert = ix_cert("wrong-name-server-crt.pem");
  std::string key = ix_cert("wrong-name-server-key.pem");

  httplib::SSLServer svr(cert.c_str(), key.c_str());
  if (!svr.is_valid()) {
    std::cerr << "SSLServer init failed\n";
    return 1;
  }

  svr.Get("/v", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9444); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", 9444);
  cli.enable_server_certificate_verification(false);
  cli.enable_server_hostname_verification(false);

  auto res = cli.Get("/v");

  svr.stop();
  if (t.joinable()) t.join();

  if (!res) {
    std::cerr << "verify-disabled request failed\n";
    return 1;
  }

  return (res->status == 200 && res->body == "ok") ? 0 : 1;
}
