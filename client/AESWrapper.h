#pragma once

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>

#include <stdexcept>
#include <string>
#include <immintrin.h>  // _rdrand32_step
#include <cstdint>
#include <cstring>

class AESWrapper {
private:
    static const unsigned int DEFAULT_KEYLENGTH = 32; // 256-bit key length
    std::string _key; // Changed to std::string

    // Generate a random AES key
    std::string GenerateKey(unsigned int length); // Change return type to std::string

public:
    AESWrapper();
    AESWrapper(const std::string& key); // Change parameter to std::string
    ~AESWrapper();

    const std::string& getKey() const; // Return type changed to const std::string&
    std::string encrypt(const char* plain, unsigned int length);
    std::string decrypt(const char* cipher, unsigned int length);
};
