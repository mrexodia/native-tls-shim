#include <openssl/evp.h>

#include <cstring>
#include <string>

static std::string to_hex(const unsigned char* data, unsigned int len) {
  static const char* h = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (unsigned int i = 0; i < len; ++i) {
    out.push_back(h[(data[i] >> 4) & 0x0F]);
    out.push_back(h[data[i] & 0x0F]);
  }
  return out;
}

static bool hash_one(const EVP_MD* md, const char* input, const char* expected_hex) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) return false;

  unsigned char out[EVP_MAX_MD_SIZE] = {0};
  unsigned int out_len = 0;

  bool ok = EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
            EVP_DigestUpdate(ctx, input, std::strlen(input)) == 1 &&
            EVP_DigestFinal_ex(ctx, out, &out_len) == 1;

  EVP_MD_CTX_free(ctx);
  if (!ok) return false;

  return to_hex(out, out_len) == expected_hex;
}

int main() {
  bool md5_ok = hash_one(EVP_md5(), "abc", "900150983cd24fb0d6963f7d28e17f72");
  bool sha256_ok =
      hash_one(EVP_sha256(), "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  return (md5_ok && sha256_ok) ? 0 : 1;
}
