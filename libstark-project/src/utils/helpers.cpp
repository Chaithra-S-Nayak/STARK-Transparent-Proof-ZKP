#include <iostream>
#include <openssl/sha.h>
#include <vector>

namespace utils {

std::vector<unsigned char> sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    return std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}

void printHash(const std::vector<unsigned char>& hash) {
    for (const auto& byte : hash) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
}

} // namespace utils