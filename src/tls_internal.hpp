#pragma once

#include <string>

namespace native_tls {

void set_last_error(unsigned long code, const std::string& message);
unsigned long peek_last_error_code();
unsigned long pop_last_error_code();
std::string get_last_error_string(unsigned long code);

} // namespace native_tls
