#include <asio.hpp>
#include <asio/ssl.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
  int port = 9553;
  std::string cert;
  std::string key;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (arg == "--cert" && i + 1 < argc) {
      cert = argv[++i];
    } else if (arg == "--key" && i + 1 < argc) {
      key = argv[++i];
    }
  }

  if (cert.empty() || key.empty()) {
    std::cerr << "usage: test_asio_https_server --port <p> --cert <cert.pem> --key <key.pem>\n";
    return 2;
  }

  try {
    asio::io_context io;
    asio::ssl::context ctx(asio::ssl::context::tls_server);
    ctx.use_certificate_chain_file(cert);
    ctx.use_private_key_file(key, asio::ssl::context::pem);

    asio::ip::tcp::acceptor acceptor(
        io,
        asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(port)));

    asio::ip::tcp::socket socket(io);
    acceptor.accept(socket);

    asio::ssl::stream<asio::ip::tcp::socket> stream(std::move(socket), ctx);
    stream.handshake(asio::ssl::stream_base::server);

    asio::streambuf request;
    asio::read_until(stream, request, "\r\n\r\n");

    const std::string response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
        "pong";

    asio::write(stream, asio::buffer(response));

    asio::error_code ec;
    stream.shutdown(ec);
  } catch (const std::exception& ex) {
    std::cerr << "asio https server failed: " << ex.what() << "\n";
    return 1;
  }

  return 0;
}
