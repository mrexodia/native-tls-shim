#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>
#include <ixwebsocket/IXWebSocket.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main(int argc, char** argv) {
  if (argc > 1 && std::string(argv[1]) == "--help") {
    std::cout << "Usage: ixwebsocket_example [url] [ca_file] [message]\n"
              << "  url      default: wss://echo.websocket.org/\n"
              << "  ca_file  default: SYSTEM (or path to PEM CA cert)\n"
              << "  message  default: hello from example\n";
    return 0;
  }

  const std::string url = (argc > 1) ? argv[1] : "wss://echo.websocket.org/";
  const std::string caFile = (argc > 2) ? argv[2] : "SYSTEM";
  const std::string payload = (argc > 3) ? argv[3] : "hello from example";

  ix::initNetSystem();

  ix::WebSocket ws;
  ws.setUrl(url);
  ws.setHandshakeTimeout(10);

  ix::SocketTLSOptions tls;
  tls.caFile = caFile;
  ws.setTLSOptions(tls);

  auto t0 = std::chrono::steady_clock::now();
  std::atomic<long long> openMs{-1};
  std::atomic<long long> echoMs{-1};

  std::atomic<bool> opened{false};
  std::atomic<bool> gotEcho{false};
  std::atomic<bool> hadError{false};
  std::atomic<bool> done{false};

  ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
      opened = true;
      const auto now = std::chrono::steady_clock::now();
      openMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
      std::cout << "[ixws] connected in " << openMs.load() << " ms\n";
      ws.send(payload, false);
      std::cout << "[ixws] sent: " << payload << "\n";
    } else if (msg->type == ix::WebSocketMessageType::Message) {
      const auto now = std::chrono::steady_clock::now();
      echoMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
      std::cout << "[ixws] received in " << echoMs.load() << " ms: " << msg->str << "\n";
      if (msg->str == payload) {
        gotEcho = true;
        done = true;
      }
    } else if (msg->type == ix::WebSocketMessageType::Error) {
      hadError = true;
      done = true;
      std::cerr << "[ixws] error: " << msg->errorInfo.reason << "\n";
    } else if (msg->type == ix::WebSocketMessageType::Close) {
      std::cout << "[ixws] closed\n";
    }
  });

  std::cout << "[ixws] connecting to " << url << "\n";
  std::cout << "[ixws] tls caFile=" << caFile << "\n";
  ws.start();

  for (int i = 0; i < 80 && !done; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }

  if (!done) {
    std::cerr << "[ixws] timeout waiting for echo\n";
  }

  ws.stop();
  ix::uninitNetSystem();

  if (!opened) {
    std::cerr << "[ixws] failed: connection did not open\n";
    return 1;
  }
  if (hadError || !gotEcho) {
    std::cerr << "[ixws] failed: no echo response\n";
    return 1;
  }

  std::cout << "[ixws] success";
  if (openMs.load() >= 0) {
    std::cout << ", handshake=" << openMs.load() << "ms";
  }
  if (echoMs.load() >= 0) {
    std::cout << ", echo=" << echoMs.load() << "ms";
  }
  std::cout << "\n";
  return 0;
}
