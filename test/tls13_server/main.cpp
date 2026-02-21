#include "../cpp-httplib/httplib.h"

#include <openssl/ssl.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

namespace {
struct Options {
  int port = 9471;
  std::string cert;
  std::string key;
};

bool parse_args(int argc, char** argv, Options& out) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      out.port = std::stoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
      out.cert = argv[++i];
    } else if (std::strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
      out.key = argv[++i];
    } else {
      return false;
    }
  }
  return !out.cert.empty() && !out.key.empty();
}
}  // namespace

int main(int argc, char** argv) {
  Options opts;
  if (!parse_args(argc, argv, opts)) {
    std::cerr << "Usage: tls13_only_server --cert <path> --key <path> [--port <port>]\n";
    return 1;
  }

  httplib::SSLServer svr(opts.cert.c_str(), opts.key.c_str());
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

  std::cout << "TLS 1.3 server listening on 127.0.0.1:" << opts.port << "\n";
  if (!svr.listen("127.0.0.1", opts.port)) {
    std::cerr << "Server listen failed\n";
    return 1;
  }

  return 0;
}
