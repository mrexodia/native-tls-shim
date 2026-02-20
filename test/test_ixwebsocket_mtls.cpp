#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketServer.h>

#include "tls_paths.h"

#include <atomic>
#include <chrono>
#include <thread>

static bool run_client(const std::string& url,
                       const ix::SocketTLSOptions& tls,
                       const std::string& payload) {
  std::atomic<bool> got_echo{false};
  std::atomic<bool> failed{false};

  ix::WebSocket client;
  client.setUrl(url);
  client.setTLSOptions(tls);

  client.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
      client.send(payload, false);
    } else if (msg->type == ix::WebSocketMessageType::Message) {
      got_echo = (msg->str == payload);
    } else if (msg->type == ix::WebSocketMessageType::Error) {
      failed = true;
    }
  });

  client.start();
  for (int i = 0; i < 120 && !got_echo && !failed; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  client.stop();

  return got_echo && !failed;
}

int main() {
  ix::initNetSystem();

  const int port = 9468;
  ix::WebSocketServer server(port, "127.0.0.1");

  ix::SocketTLSOptions server_tls;
  server_tls.tls = true;
  server_tls.certFile = ix_cert("trusted-server-crt.pem");
  server_tls.keyFile = ix_cert("trusted-server-key.pem");
  server_tls.caFile = ix_cert("trusted-ca-crt.pem");
  server.setTLSOptions(server_tls);

  server.setOnClientMessageCallback(
      [](std::shared_ptr<ix::ConnectionState>, ix::WebSocket& webSocket,
         const ix::WebSocketMessagePtr& msg) {
        if (msg->type == ix::WebSocketMessageType::Message) {
          webSocket.send(msg->str, msg->binary);
        }
      });

  auto listen_res = server.listen();
  if (!listen_res.first) {
    ix::uninitNetSystem();
    return 1;
  }
  server.start();

  ix::SocketTLSOptions no_client_cert_tls;
  no_client_cert_tls.caFile = ix_cert("trusted-ca-crt.pem");

  ix::SocketTLSOptions with_client_cert_tls;
  with_client_cert_tls.caFile = ix_cert("trusted-ca-crt.pem");
  with_client_cert_tls.certFile = ix_cert("trusted-client-crt.pem");
  with_client_cert_tls.keyFile = ix_cert("trusted-client-key.pem");

  bool no_cert_ok = run_client("wss://localhost:9468", no_client_cert_tls, "mtls-no-cert");
  bool with_cert_ok = run_client("wss://localhost:9468", with_client_cert_tls, "mtls-with-cert");

  server.stop();
  ix::uninitNetSystem();

  return (!no_cert_ok && with_cert_ok) ? 0 : 1;
}
