#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketServer.h>

#include "tls_paths.h"

#include <atomic>
#include <chrono>
#include <thread>

int main() {
  ix::initNetSystem();

  const int port = 9451;
  ix::WebSocketServer server(port, "127.0.0.1");

  ix::SocketTLSOptions serverTls;
  serverTls.tls = true;
  serverTls.certFile = ix_cert("wrong-name-server-crt.pem");
  serverTls.keyFile = ix_cert("wrong-name-server-key.pem");
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
    ix::uninitNetSystem();
    return 1;
  }
  server.start();

  std::atomic<bool> gotEcho{false};
  std::atomic<bool> failed{false};

  ix::WebSocket client;
  client.setUrl("wss://localhost:9451");

  ix::SocketTLSOptions clientTls;
  clientTls.caFile = "NONE";
  clientTls.disable_hostname_validation = true;
  client.setTLSOptions(clientTls);

  client.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
      client.send("skip-verify", false);
    } else if (msg->type == ix::WebSocketMessageType::Message) {
      gotEcho = (msg->str == "skip-verify");
    } else if (msg->type == ix::WebSocketMessageType::Error) {
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
