#pragma once

#include <stdexcept>
#include <string>
#include <vector>
#include <cstdint>
#include "utils.h"

using std::string;
using std::vector;

// ResponseCode enum
enum class ResponseCode : uint16_t {
    REGISTER_OK = 1600,
    REGISTER_FAIL = 1601,
    AES_SEND_KEY = 1602,
    FILE_OK = 1603,
    MESSAGE_OK = 1604,
    LOGIN_OK_SEND_AES = 1605,
    LOGIN_FAIL = 1606,
    GENERAL_ERROR = 1607
};

// ResponseHeader class
class ResponseHeader {
private:
    ResponseCode responseCode;
    uint32_t payloadSize;
    uint8_t version;

public:
    ResponseHeader(ResponseCode responseCode, uint32_t payloadSize, uint8_t version);

    // Getters
    ResponseCode getResponseCode() const;
    uint32_t getPayloadSize() const;
    uint8_t getVersion() const;

    // Setters
    void setResponseCode(ResponseCode responseCode);
    void setPayloadSize(uint32_t payloadSize);
    void setVersion(uint8_t version);

    static ResponseHeader deserializeHeader(const vector<uint8_t>& data);
};

// Individual Payload Classes

class RegisterOkPayload {
private:
    string clientID; // 16 bytes

public:
    RegisterOkPayload(const string& clientID);
    static RegisterOkPayload deserialize(const vector<uint8_t>& data);
    const string& getClientID() const;
};

class RegisterFailPayload {
public:
    static RegisterFailPayload deserialize(const vector<uint8_t>& data);
};

class AESSendKeyPayload {
private:
    string clientID;  // 16 bytes
    string aesKey;    // Changed to std::string

public:
    AESSendKeyPayload(const string& clientID, const string& aesKey);
    static AESSendKeyPayload deserialize(const vector<uint8_t>& data);
    const string& getClientID() const;
    const string& getAesKey() const;
};

class FileOkPayload {
private:
    string clientID;      // 16 bytes
    uint32_t contentSize; // 4 bytes
    string fileName;      // 255 bytes
    uint32_t checksum;    // 4 bytes

public:
    FileOkPayload(const string& clientID, uint32_t contentSize, const string& fileName, uint32_t checksum);
    static FileOkPayload deserialize(const vector<uint8_t>& data);
    const string& getClientID() const;
    uint32_t getContentSize() const;
    const string& getFileName() const;
    uint32_t getChecksum() const;
};

class MessageOkPayload {
private:
    string clientID;

public:
    MessageOkPayload(const string& clientID);
    static MessageOkPayload deserialize(const vector<uint8_t>& data);
    const string& getClientID() const;
};

class LoginOkPayload {
private:
    string clientID;
    string encryptedAESKey;

public:
    LoginOkPayload(const string& clientID, const string& encryptedAESKey);
    static LoginOkPayload deserialize(const vector<uint8_t>& data);
    const string& getClientID() const;
    const string& getEncryptedAESKey() const;
};

class LoginFailPayload {
private:
    string clientID;

public:
    LoginFailPayload(const string& clientID);
    static LoginFailPayload deserialize(const vector<uint8_t>& data);
    const string& getClientID() const;
};

class GeneralErrorPayload {
public:
    static GeneralErrorPayload deserialize(const vector<uint8_t>& data);
};
