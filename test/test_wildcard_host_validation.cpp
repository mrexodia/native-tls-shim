#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "tls_paths.h"

#include <iostream>
#include <string>

static X509* load_cert(const std::string& path) {
  auto pem = read_text_file(path);
  if (pem.empty()) return nullptr;

  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) return nullptr;

  X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  return cert;
}

int main() {
  X509* invalid = load_cert(ix_cert("invalid-wildcard-crt.pem"));
  X509* valid = load_cert(ix_cert("valid-wildcard-crt.pem"));

  if (!invalid || !valid) {
    if (invalid) X509_free(invalid);
    if (valid) X509_free(valid);
    return 1;
  }

  bool invalid_match = X509_check_host(invalid, "foo.example.com", 0, 0, nullptr) == 1;
  bool invalid_sub_match =
      X509_check_host(invalid, "bar.foo.example.com", 0, 0, nullptr) == 1;

  bool valid_match = X509_check_host(valid, "host.example.com", 0, 0, nullptr) == 1;
  bool valid_sub_match = X509_check_host(valid, "host.sub.example.com", 0, 0, nullptr) == 1;

  X509_free(invalid);
  X509_free(valid);

  if (invalid_match || invalid_sub_match || !valid_match || valid_sub_match) {
    std::cerr << "wildcard hostname validation failed" << "\n";
    return 1;
  }

  return 0;
}
