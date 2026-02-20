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

  svr.Get("/mtls", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("mtls", "text/plain");
  });

  std::thread t([&] { svr.listen("127.0.0.1", 9462); });
  std::this_thread::sleep_for(std::chrono::milliseconds(250));

  httplib::SSLClient no_cert("127.0.0.1", 9462);
  no_cert.set_ca_cert_path(ca.c_str());
  auto res_no_cert = no_cert.Get("/mtls");

  httplib::SSLClient with_cert("127.0.0.1", 9462, client_cert.c_str(), client_key.c_str());
  with_cert.set_ca_cert_path(ca.c_str());
  auto res_with_cert = with_cert.Get("/mtls");

  svr.stop();
  if (t.joinable()) t.join();

  bool no_cert_failed = !res_no_cert;
  bool with_cert_ok = res_with_cert && res_with_cert->status == 200 &&
                      res_with_cert->body == "mtls";

  return (no_cert_failed && with_cert_ok) ? 0 : 1;
}
