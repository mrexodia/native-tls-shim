#pragma once

#include "openssl/err.h"

#include <ctime>
#include <string>
#include <vector>

struct asn1_string_st {
  std::vector<unsigned char> bytes;
};

struct asn1_time_st {
  time_t epoch = 0;
};

struct bignum_st {
  std::vector<unsigned char> bytes;
};

namespace native_tls {

void set_last_error(unsigned long code, const std::string& message);
unsigned long peek_last_error_code();
unsigned long pop_last_error_code();
std::string get_last_error_string(unsigned long code);

unsigned long make_error_code(int lib, int reason);
void set_error_message(const std::string& msg, int reason = 1, int lib = ERR_LIB_X509);
void clear_error_message();

std::string trim(std::string s);
std::string extract_dn_component(const std::string& dn, const std::string& key);
bool wildcard_match(const std::string& pattern, const std::string& host);
bool set_fd_nonblocking(int fd, bool on);
bool is_ip_literal(const std::string& s);

} // namespace native_tls
