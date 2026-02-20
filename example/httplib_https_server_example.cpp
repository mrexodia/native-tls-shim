#include <httplib.h>

#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace {
std::string fixture_path(const char* name) {
#ifdef NTS_SOURCE_DIR
  return (std::filesystem::path(NTS_SOURCE_DIR) / "test" / "fixtures" / name).generic_string();
#else
  return (std::filesystem::path("test") / "fixtures" / name).generic_string();
#endif
}
} // namespace

int main() {
  const std::string cert = fixture_path("trusted-server-crt.pem");
  const std::string key = fixture_path("trusted-server-key.pem");
  const std::string ca = fixture_path("trusted-ca-crt.pem");

  httplib::SSLServer svr(cert.c_str(), key.c_str());
  if (!svr.is_valid()) {
    std::cerr << "Failed to create HTTPS server (cert/key load failed).\n";
    return 1;
  }

  svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
    std::cout << "[httplib] " << req.remote_addr << ":" << req.remote_port << " "
              << req.method << " " << req.path << " -> " << res.status << "\n";
  });

  svr.set_error_logger([](const httplib::Error& err, const httplib::Request* req) {
    std::cerr << "[httplib] error=" << static_cast<int>(err);
    if (req) {
      std::cerr << " on " << req->method << " " << req->path;
    }
    std::cerr << "\n";
  });

  svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
    res.set_content("hello from httplib https server\n", "text/plain");
  });

  constexpr int port = 8443;
  std::thread t([&] {
    if (!svr.listen("127.0.0.1", port)) {
      std::cerr << "listen failed\n";
    }
  });

  std::cout << "HTTPS server running at https://localhost:" << port << "/\n";
  std::cout << "Fixture CA cert: " << ca << "\n";
  std::cout << "Try: curl --cacert \"" << ca << "\" https://localhost:" << port << "/\n";
#ifdef _WIN32
  std::cout << "Windows curl(Schannel) may need: --ssl-no-revoke\n";
  std::cout << "Try: curl --ssl-no-revoke --cacert \"" << ca << "\" https://localhost:" << port << "/\n";
#endif
  std::cout << "(If nothing is logged below, TLS failed before HTTP reached the server.)\n";
  std::cout << "Press Enter to stop...\n";

  std::string line;
  std::getline(std::cin, line);

  svr.stop();
  if (t.joinable()) t.join();
  return 0;
}
