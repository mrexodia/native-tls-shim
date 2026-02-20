#include <httplib.h>

#include "tls_paths.h"

#include <chrono>
#include <thread>

int main() {
  std::string server_cert = ix_cert("trusted-server-crt.pem");
  std::string server_key = ix_cert("trusted-server-key.pem");
  std::string ca = ix_cert("trusted-ca-crt.pem");
  std::string client_cert = ix_cert("trusted-client-crt.pem");
  std::string client_key = ix_cert("trusted-client-key.pem");

  httplib::SSLServer svr(server_cert.c_str(), server_key.c_str(), ca.c_str());
  if (!svr.is_valid()) return 1;

  svr.Get("/pc", [](const httplib::Request& req, httplib::Response& res) {
    auto cn = req.peer_cert().subject_cn();
    if (cn.empty()) cn = "<empty>";
    res.set_content(cn, "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9445); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient cli("127.0.0.1", 9445, client_cert.c_str(), client_key.c_str());
  cli.set_ca_cert_path(ca.c_str());

  auto res = cli.Get("/pc");

  svr.stop();
  if (t.joinable()) t.join();

  return (res && res->status == 200 && !res->body.empty() && res->body != "<empty>") ? 0 : 1;
}
