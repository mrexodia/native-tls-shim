#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocket.h>

#include <chrono>
#include <iostream>
#include <thread>

int main() {
  ix::initNetSystem();

  ix::WebSocket ws;
  ws.setUrl("wss://ws.ifelse.io");

  ix::SocketTLSOptions tls;
  tls.caFile = "SYSTEM";
  ws.setTLSOptions(tls);

  ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
      ws.send("hello from example", false);
    } else if (msg->type == ix::WebSocketMessageType::Message) {
      std::cout << "echo: " << msg->str << "\n";
      ws.stop();
    }
  });

  ws.start();
  std::this_thread::sleep_for(std::chrono::seconds(5));
  ws.stop();

  ix::uninitNetSystem();
  return 0;
}
