#include <httplib.h>

#include <iostream>

int main() {
  httplib::SSLClient cli("httpbin.org", 443);
  auto res = cli.Get("/ip");
  if (!res) {
    std::cerr << "request failed\n";
    return 1;
  }
  std::cout << res->body << "\n";
  return 0;
}
