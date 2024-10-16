#pragma once

#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <string>

class RSAEncryptor {
public:
    RSAEncryptor();

    // Generate RSA keys
    void GenerateKeys(uint64_t keySize);

    // Get the public key in string form
    std::string GetPublicKey() const;

    // Get the private key in string form
    std::string GetPrivateKey() const;

    // Set keys from strings
    void SetPublicKey(const std::string& publicKeyStr);
    void SetPrivateKey(const std::string& privateKeyStr);

    // Encrypt and Decrypt methods
    std::string Encrypt(const std::string& plaintext);
    std::string Decrypt(const std::string& ciphertext);

private:
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;

    std::string KeyToString(const CryptoPP::RSA::PublicKey& key) const;
    std::string KeyToString(const CryptoPP::RSA::PrivateKey& key) const;
    void StringToPublicKey(const std::string& keyStr, CryptoPP::RSA::PublicKey& key);
    void StringToPrivateKey(const std::string& keyStr, CryptoPP::RSA::PrivateKey& key);
};
