#include <httplib.h>

#include <iostream>

int main() {
  httplib::SSLClient cli("httpbin.org", 443);
  cli.set_follow_location(true);
  cli.set_connection_timeout(10, 0);
  cli.set_read_timeout(30, 0);

  auto res = cli.Get("/get");
  if (!res) {
    std::cerr << "HTTPS GET failed, error=" << static_cast<int>(res.error()) << "\n";
    return 1;
  }

  std::cout << "status=" << res->status << "\n";
  return (res->status >= 200 && res->status < 300) ? 0 : 1;
}
