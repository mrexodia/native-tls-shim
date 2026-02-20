#pragma once

#include <fstream>
#include <sstream>
#include <string>

inline std::string nts_source_dir() { return std::string(NTS_SOURCE_DIR); }

inline std::string ix_cert(const std::string& name) {
  return nts_source_dir() + "/test/fixtures/" + name;
}

inline std::string read_text_file(const std::string& path) {
  std::ifstream ifs(path, std::ios::binary);
  std::ostringstream oss;
  oss << ifs.rdbuf();
  return oss.str();
}
