#include <httplib.h>

#include <iostream>

int main() {
  httplib::Client cli("https://www.howsmyssl.com");
  auto res = cli.Get("/a/check");
  if (!res) {
    std::cerr << "request failed\n";
    return 1;
  }
  std::cout << res->body << "\n";
  return 0;
}
