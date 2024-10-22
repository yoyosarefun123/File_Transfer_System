#include "RSAEncryption.h"
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/pssr.h>
#include <iostream>

RSAEncryptor::RSAEncryptor() {
    // Constructor: Initialize RNG
}

// Generates public and private keys with the specified key size
void RSAEncryptor::GenerateKeys(uint64_t keySize) {
    privateKey.GenerateRandomWithKeySize(rng, keySize);
    publicKey.AssignFrom(privateKey);
}

// Converts public key to string
std::string RSAEncryptor::GetPublicKey() const {
    return KeyToString(publicKey);
}

// Converts private key to string
std::string RSAEncryptor::GetPrivateKey() const {
    return KeyToString(privateKey);
}

// Sets the public key from string
void RSAEncryptor::SetPublicKey(const std::string& publicKeyStr) {
    StringToPublicKey(publicKeyStr, publicKey);
}

// Sets the private key from string
void RSAEncryptor::SetPrivateKey(const std::string& privateKeyStr) {
    StringToPrivateKey(privateKeyStr, privateKey);
}

// Encrypts the plaintext using the public key
std::string RSAEncryptor::Encrypt(const std::string& plaintext) {
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

    std::string ciphertext;
    CryptoPP::StringSource ss1(plaintext, true,
        new CryptoPP::PK_EncryptorFilter(rng, encryptor,
            new CryptoPP::StringSink(ciphertext)
        )
    );
    return ciphertext;
}

// Decrypts the ciphertext using the private key
std::string RSAEncryptor::Decrypt(const std::string& ciphertext) {
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);

    std::string decrypted;
    CryptoPP::StringSource ss2(ciphertext, true,
        new CryptoPP::PK_DecryptorFilter(rng, decryptor,
            new CryptoPP::StringSink(decrypted)
        )
    );
    return decrypted;
}

// Converts RSA public key to a string
std::string RSAEncryptor::KeyToString(const CryptoPP::RSA::PublicKey& key) const {
    std::string keyStr;
    CryptoPP::StringSink ss(keyStr);
    key.DEREncode(ss);
    return keyStr;
}

// Converts RSA private key to a string
std::string RSAEncryptor::KeyToString(const CryptoPP::RSA::PrivateKey& key) const {
    std::string keyStr;
    CryptoPP::StringSink ss(keyStr);
    key.DEREncode(ss);
    return keyStr;
}

// Loads public key from string
void RSAEncryptor::StringToPublicKey(const std::string& keyStr, CryptoPP::RSA::PublicKey& key) {
    CryptoPP::StringSource ss(keyStr, true);
    key.BERDecode(ss);
}

// Loads private key from string
void RSAEncryptor::StringToPrivateKey(const std::string& keyStr, CryptoPP::RSA::PrivateKey& key) {
    CryptoPP::StringSource ss(keyStr, true);
    key.BERDecode(ss);
}
