#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocketServer.h>

#include <filesystem>
#include <iostream>
#include <string>

namespace {
std::string fixture_path(const char* name) {
#ifdef NTS_SOURCE_DIR
  return (std::filesystem::path(NTS_SOURCE_DIR) / "test" / "fixtures" / name).generic_string();
#else
  return (std::filesystem::path("test") / "fixtures" / name).generic_string();
#endif
}
} // namespace

int main(int argc, char** argv) {
  const int port = (argc > 1) ? std::stoi(argv[1]) : 9450;

  const std::string cert = fixture_path("trusted-server-crt.pem");
  const std::string key = fixture_path("trusted-server-key.pem");
  const std::string ca = fixture_path("trusted-ca-crt.pem");

  ix::initNetSystem();

  ix::SocketTLSOptions tls;
  tls.tls = true;
  tls.certFile = cert;
  tls.keyFile = key;
  tls.caFile = "NONE";

  auto onClientMessage = [](std::shared_ptr<ix::ConnectionState>, ix::WebSocket& webSocket,
                            const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
      std::cout << "[wss-server] client connected\n";
    } else if (msg->type == ix::WebSocketMessageType::Message) {
      std::cout << "[wss-server] recv: " << msg->str << "\n";
      webSocket.send(msg->str, msg->binary);
      std::cout << "[wss-server] echoed\n";
    } else if (msg->type == ix::WebSocketMessageType::Error) {
      std::cerr << "[wss-server] client error: " << msg->errorInfo.reason << "\n";
    } else if (msg->type == ix::WebSocketMessageType::Close) {
      std::cout << "[wss-server] client closed\n";
    }
  };

  ix::WebSocketServer server4(port, "127.0.0.1", ix::SocketServer::kDefaultTcpBacklog,
                              ix::SocketServer::kDefaultMaxConnections,
                              ix::WebSocketServer::kDefaultHandShakeTimeoutSecs, AF_INET);
  server4.setTLSOptions(tls);
  server4.setOnClientMessageCallback(onClientMessage);

  ix::WebSocketServer server6(port, "::1", ix::SocketServer::kDefaultTcpBacklog,
                              ix::SocketServer::kDefaultMaxConnections,
                              ix::WebSocketServer::kDefaultHandShakeTimeoutSecs, AF_INET6);
  server6.setTLSOptions(tls);
  server6.setOnClientMessageCallback(onClientMessage);

  bool up4 = false;
  bool up6 = false;

  auto r4 = server4.listen();
  if (r4.first) {
    server4.start();
    up4 = true;
  } else {
    std::cerr << "IPv4 listen failed: " << r4.second << "\n";
  }

  auto r6 = server6.listen();
  if (r6.first) {
    server6.start();
    up6 = true;
  } else {
    std::cerr << "IPv6 listen failed: " << r6.second << "\n";
  }

  if (!up4 && !up6) {
    std::cerr << "Neither IPv4 nor IPv6 server could start\n";
    ix::uninitNetSystem();
    return 1;
  }

  std::cout << "WSS echo server running on localhost:" << port << "\n";
  std::cout << "  IPv4: " << (up4 ? "enabled (127.0.0.1)" : "disabled") << "\n";
  std::cout << "  IPv6: " << (up6 ? "enabled (::1)" : "disabled") << "\n";
  std::cout << "Server cert: " << cert << "\n";
  std::cout << "Server key : " << key << "\n";
  std::cout << "Client should trust CA: " << ca << "\n";
  std::cout << "\nClient example:\n"
            << "  ixwebsocket_example wss://localhost:" << port << " \"" << ca
            << "\" \"hello\"\n";
  std::cout << "Press Enter to stop...\n";

  std::string line;
  std::getline(std::cin, line);

  if (up4) server4.stop();
  if (up6) server6.stop();
  ix::uninitNetSystem();
  return 0;
}
