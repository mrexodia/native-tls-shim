#include <httplib.h>

#include "tls_paths.h"

#include <chrono>
#include <thread>

int main() {
  std::string cert = ix_cert("trusted-server-crt.pem");
  std::string key = ix_cert("trusted-server-key.pem");
  std::string ca_pem = read_text_file(ix_cert("trusted-ca-crt.pem"));

  httplib::SSLServer svr(cert.c_str(), key.c_str());
  if (!svr.is_valid()) return 1;

  svr.Get("/memca", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9461); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", 9461);
  cli.load_ca_cert_store(ca_pem.c_str(), ca_pem.size());
  auto res = cli.Get("/memca");

  svr.stop();
  if (t.joinable()) t.join();

  return (res && res->status == 200 && res->body == "ok") ? 0 : 1;
}
