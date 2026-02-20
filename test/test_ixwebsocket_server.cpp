#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketServer.h>

#include "tls_paths.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

int main() {
  ix::initNetSystem();

  const int port = 9450;
  ix::WebSocketServer server(port, "127.0.0.1");

  ix::SocketTLSOptions serverTls;
  serverTls.tls = true;
  serverTls.certFile = ix_cert("trusted-server-crt.pem");
  serverTls.keyFile = ix_cert("trusted-server-key.pem");
  serverTls.caFile = "NONE";
  server.setTLSOptions(serverTls);

  server.setOnClientMessageCallback(
      [](std::shared_ptr<ix::ConnectionState>, ix::WebSocket& webSocket,
         const ix::WebSocketMessagePtr& msg) {
        if (msg->type == ix::WebSocketMessageType::Message) {
          webSocket.send(msg->str, msg->binary);
        }
      });

  auto listenRes = server.listen();
  if (!listenRes.first) {
    std::cerr << "Server listen failed: " << listenRes.second << "\n";
    ix::uninitNetSystem();
    return 1;
  }
  server.start();

  std::atomic<bool> gotEcho{false};
  std::atomic<bool> failed{false};

  ix::WebSocket client;
  client.setUrl("wss://localhost:9450");

  ix::SocketTLSOptions clientTls;
  clientTls.caFile = ix_cert("trusted-ca-crt.pem");
  client.setTLSOptions(clientTls);

  client.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
      client.send("hello", false);
    } else if (msg->type == ix::WebSocketMessageType::Message) {
      gotEcho = (msg->str == "hello");
    } else if (msg->type == ix::WebSocketMessageType::Error) {
      std::cerr << "Client error: " << msg->errorInfo.reason << "\n";
      failed = true;
    }
  });

  client.start();
  for (int i = 0; i < 120 && !gotEcho && !failed; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  client.stop();
  server.stop();
  ix::uninitNetSystem();

  return (gotEcho && !failed) ? 0 : 1;
}
