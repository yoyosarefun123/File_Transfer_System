#include "AESWrapper.h"

using std::uint8_t;

std::string AESWrapper::GenerateKey(unsigned int length)
{
    std::string buffer(length, '\0'); // Initialize the buffer with zeros
    for (size_t i = 0; i < length; i += sizeof(unsigned int))
        _rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
    return buffer;
}

AESWrapper::AESWrapper()
    : _key(GenerateKey(DEFAULT_KEYLENGTH)) // Use GenerateKey to initialize _key
{
}

AESWrapper::AESWrapper(const std::string& key)
{
    if (key.size() != DEFAULT_KEYLENGTH)
        throw std::length_error("key length must be 32 bytes");
    _key = key; // Directly assign the key
}

AESWrapper::~AESWrapper()
{
}

const std::string& AESWrapper::getKey() const
{
    return _key; // Return reference to _key
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
    uint8_t iv[CryptoPP::AES::BLOCKSIZE] = { 0 }; // IV should be random for practical use

    std::cout << "Plaintext length before encryption: " << length << std::endl;

    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const uint8_t*>(_key.data()), _key.size());
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    std::string cipher;
    CryptoPP::StreamTransformationFilter stfEncryptor(
        cbcEncryption,
        new CryptoPP::StringSink(cipher),
        CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING // Enable PKCS7 padding
    );

    stfEncryptor.Put(reinterpret_cast<const uint8_t*>(plain), length);
    stfEncryptor.MessageEnd();

    std::cout << "Ciphertext length after encryption: " << cipher.length() << std::endl;
    return cipher;
}


std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
    uint8_t iv[CryptoPP::AES::BLOCKSIZE] = { 0 }; // For practical use, IV should never be a fixed value!

    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const uint8_t*>(_key.data()), _key.size()); // Use key data
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    std::string decrypted;
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
    stfDecryptor.Put(reinterpret_cast<const uint8_t*>(cipher), length);
    stfDecryptor.MessageEnd();

    return decrypted;
}
