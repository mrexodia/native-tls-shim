#include <ixwebsocket/IXHttpClient.h>
#include <ixwebsocket/IXHttpServer.h>
#include <ixwebsocket/IXNetSystem.h>
#include <ixwebsocket/IXSocketTLSOptions.h>

#include "tls_paths.h"

#include <chrono>
#include <iostream>
#include <thread>
#include <tuple>

static std::tuple<ix::HttpErrorCode, int>
run_https_case(int port,
               const std::string& server_cert,
               const std::string& server_key,
               const ix::SocketTLSOptions& client_tls,
               const std::string& host) {
  ix::HttpServer server(port, "127.0.0.1");

  ix::SocketTLSOptions server_tls;
  server_tls.tls = true;
  server_tls.caFile = "NONE";
  server_tls.certFile = server_cert;
  server_tls.keyFile = server_key;
  server.setTLSOptions(server_tls);

  server.setOnConnectionCallback(
      [](ix::HttpRequestPtr, std::shared_ptr<ix::ConnectionState>) -> ix::HttpResponsePtr {
        return std::make_shared<ix::HttpResponse>(200, "OK", ix::HttpErrorCode::Ok,
                                                  ix::WebSocketHttpHeaders(), "ok");
      });

  auto listen_res = server.listen();
  if (!listen_res.first) return std::make_tuple(ix::HttpErrorCode::CannotConnect, 0);
  server.start();

  ix::HttpClient client;
  client.setTLSOptions(client_tls);

  std::string url = "https://" + host + ":" + std::to_string(port);
  auto args = client.createRequest(url);
  args->connectTimeout = 10;
  args->transferTimeout = 10;

  auto response = client.get(url, args);

  server.stop();
  return std::make_tuple(response->errorCode, response->statusCode);
}

int main() {
  ix::initNetSystem();

  const std::string trusted_server_cert = ix_cert("trusted-server-crt.pem");
  const std::string trusted_server_key = ix_cert("trusted-server-key.pem");
  const std::string wrong_name_cert = ix_cert("wrong-name-server-crt.pem");
  const std::string wrong_name_key = ix_cert("wrong-name-server-key.pem");
  const std::string trusted_ca = ix_cert("trusted-ca-crt.pem");
  const std::string untrusted_ca = ix_cert("untrusted-ca-crt.pem");

  ix::SocketTLSOptions tls_trusted;
  tls_trusted.caFile = trusted_ca;

  ix::SocketTLSOptions tls_untrusted;
  tls_untrusted.caFile = untrusted_ca;

  ix::SocketTLSOptions tls_in_memory;
  tls_in_memory.caFile = read_text_file(trusted_ca);

  auto trusted_ok = run_https_case(9463, trusted_server_cert, trusted_server_key,
                                   tls_trusted, "127.0.0.1");
  auto wrong_name_fail = run_https_case(9464, wrong_name_cert, wrong_name_key,
                                        tls_trusted, "127.0.0.1");
  auto untrusted_fail = run_https_case(9466, trusted_server_cert, trusted_server_key,
                                       tls_untrusted, "127.0.0.1");
  auto in_memory_ok = run_https_case(9467, trusted_server_cert, trusted_server_key,
                                     tls_in_memory, "127.0.0.1");

  ix::uninitNetSystem();

  bool ok1 = trusted_ok == std::make_tuple(ix::HttpErrorCode::Ok, 200);
  bool ok2 = std::get<0>(wrong_name_fail) == ix::HttpErrorCode::CannotConnect;
  bool ok3 = std::get<0>(untrusted_fail) == ix::HttpErrorCode::CannotConnect;
  bool ok4 = in_memory_ok == std::make_tuple(ix::HttpErrorCode::Ok, 200);

  if (!(ok1 && ok2 && ok3 && ok4)) {
    std::cerr << "trusted_ok=" << static_cast<int>(std::get<0>(trusted_ok)) << ","
              << std::get<1>(trusted_ok) << "\n";
    std::cerr << "wrong_name_fail=" << static_cast<int>(std::get<0>(wrong_name_fail))
              << "," << std::get<1>(wrong_name_fail) << "\n";
    std::cerr << "untrusted_fail=" << static_cast<int>(std::get<0>(untrusted_fail)) << ","
              << std::get<1>(untrusted_fail) << "\n";
    std::cerr << "in_memory_ok=" << static_cast<int>(std::get<0>(in_memory_ok)) << ","
              << std::get<1>(in_memory_ok) << "\n";
  }

  return (ok1 && ok2 && ok3 && ok4) ? 0 : 1;
}
