#include <asio.hpp>
#include <asio/ssl.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  int port = 9553;
  std::string host = "127.0.0.1";
  std::string ca_file;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (arg == "--host" && i + 1 < argc) {
      host = argv[++i];
    } else if (arg == "--ca" && i + 1 < argc) {
      ca_file = argv[++i];
    }
  }

  if (ca_file.empty()) {
    std::cerr << "usage: test_asio_https_client --port <p> --host <host> --ca <ca.pem>\n";
    return 2;
  }

  try {
    asio::io_context io;
    asio::ssl::context ctx(asio::ssl::context::tls_client);
    ctx.load_verify_file(ca_file);

    asio::ssl::stream<asio::ip::tcp::socket> stream(io, ctx);
    stream.set_verify_mode(asio::ssl::verify_peer);

    asio::ip::tcp::resolver resolver(io);
    auto endpoints = resolver.resolve(host, std::to_string(port));
    asio::connect(stream.next_layer(), endpoints);

    stream.handshake(asio::ssl::stream_base::client);

    std::string req =
        "GET /ping HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Connection: close\r\n"
        "\r\n";
    asio::write(stream, asio::buffer(req));

    std::string data;
    std::array<char, 4096> buf{};
    asio::error_code ec;
    while (true) {
      auto n = stream.read_some(asio::buffer(buf), ec);
      if (n > 0) data.append(buf.data(), n);
      if (ec == asio::error::eof) break;
      if (ec) throw asio::system_error(ec);
    }

    if (data.find("200 OK") == std::string::npos || data.find("pong") == std::string::npos) {
      std::cerr << "unexpected response: " << data << "\n";
      return 1;
    }
  } catch (const std::exception& ex) {
    std::cerr << "asio https client failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}
