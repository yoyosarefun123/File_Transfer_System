#include "ResponseUnpacker.h"

// ResponseHeader class implementation
ResponseHeader::ResponseHeader(ResponseCode responseCode, uint32_t payloadSize, uint8_t version)
    : responseCode(responseCode), payloadSize(payloadSize), version(version) {}

ResponseCode ResponseHeader::getResponseCode() const {
    return responseCode;
}

uint32_t ResponseHeader::getPayloadSize() const {
    return payloadSize;
}

uint8_t ResponseHeader::getVersion() const {
    return version;
}

void ResponseHeader::setResponseCode(ResponseCode responseCode) {
    this->responseCode = responseCode;
}

void ResponseHeader::setPayloadSize(uint32_t payloadSize) {
    this->payloadSize = payloadSize;
}

void ResponseHeader::setVersion(uint8_t version) {
    this->version = version;
}

ResponseHeader ResponseHeader::deserializeHeader(const vector<uint8_t>& data) {
    if (data.size() < 6) {
        throw std::runtime_error("Data size is too small for header deserialization");
    }

    uint8_t version = data[0];
    uint16_t responseCodeValue = deserializeShort(data, 1);
    uint32_t payloadSize = deserializeInt(data, 3);

    ResponseCode responseCode = static_cast<ResponseCode>(responseCodeValue);
    return ResponseHeader(responseCode, payloadSize, version);
}

// RegisterOkPayload class implementation
RegisterOkPayload::RegisterOkPayload(const string& clientID) : clientID(clientID) {
    if (clientID.size() != 16) {
        throw std::invalid_argument("clientID must be 16 bytes");
    }
}

RegisterOkPayload RegisterOkPayload::deserialize(const vector<uint8_t>& data) {
    if (data.size() != 16) {
        throw std::runtime_error("Data size is incorrect for RegisterOkPayload deserialization");
    }

    string clientID(data.begin(), data.end());
    return RegisterOkPayload(clientID);
}

const string& RegisterOkPayload::getClientID() const {
    return clientID;
}

// RegisterFailPayload class implementation
RegisterFailPayload RegisterFailPayload::deserialize(const vector<uint8_t>& data) {
    // No data to deserialize as this is an empty payload
    return RegisterFailPayload();
}

// AESSendKeyPayload class implementation
AESSendKeyPayload::AESSendKeyPayload(const string& clientID, const string& aesKey)
    : clientID(clientID), aesKey(aesKey) {
    if (clientID.size() != 16) {
        throw std::length_error("clientID must be 16 bytes");
    }
}

AESSendKeyPayload AESSendKeyPayload::deserialize(const vector<uint8_t>& data) {
    if (data.size() < 144) {
        throw std::invalid_argument("Insufficient data for deserialization");
    }

    string clientID(data.begin(), data.begin() + 16);
    string aesKey(data.begin() + 16, data.begin() + 144);
    return AESSendKeyPayload(clientID, aesKey);
}

const string& AESSendKeyPayload::getClientID() const {
    return clientID;
}

const string& AESSendKeyPayload::getAesKey() const {
    return aesKey;
}

// FileOkPayload class implementation
FileOkPayload::FileOkPayload(const string& clientID, uint32_t contentSize, const string& fileName, uint32_t checksum)
    : clientID(clientID), contentSize(contentSize), fileName(fileName), checksum(checksum) {
    if (clientID.size() != 16) {
        throw std::invalid_argument("clientID must be 16 bytes");
    }
    if (fileName.size() > 255) {
        throw std::invalid_argument("fileName must not exceed 255 bytes");
    }
}

FileOkPayload FileOkPayload::deserialize(const vector<uint8_t>& data) {
    if (data.size() < 275) {
        throw std::runtime_error("Data size is too small for FileOkPayload deserialization");
    }

    string clientID(data.begin(), data.begin() + 16);
    uint32_t contentSize = deserializeInt(data, 16);
    string fileName(data.begin() + 20, data.begin() + 275);
    uint32_t checksum = deserializeInt(data, 275);

    return FileOkPayload(clientID, contentSize, fileName, checksum);
}

const string& FileOkPayload::getClientID() const {
    return clientID;
}

uint32_t FileOkPayload::getContentSize() const {
    return contentSize;
}

const string& FileOkPayload::getFileName() const {
    return fileName;
}

uint32_t FileOkPayload::getChecksum() const {
    return checksum;
}

// MessageOkPayload class implementation
MessageOkPayload::MessageOkPayload(const string& clientID) : clientID(clientID) {
    if (clientID.size() != 16) {
        throw std::invalid_argument("clientID must be 16 bytes");
    }
}

MessageOkPayload MessageOkPayload::deserialize(const vector<uint8_t>& data) {
    if (data.size() != 16) {
        throw std::runtime_error("Data size is incorrect for MessageOkPayload deserialization");
    }

    string clientID(data.begin(), data.end());
    return MessageOkPayload(clientID);
}

const string& MessageOkPayload::getClientID() const {
    return clientID;
}

// LoginOkPayload class implementation
LoginOkPayload::LoginOkPayload(const string& clientID, const string& encryptedAESKey)
    : clientID(clientID), encryptedAESKey(encryptedAESKey) {
    if (clientID.size() != 16) {
        throw std::invalid_argument("clientID must be 16 bytes");
    }
}

LoginOkPayload LoginOkPayload::deserialize(const vector<uint8_t>& data) {
    if (data.size() < 16) {
        throw std::runtime_error("Data size is too small for LoginOkPayload deserialization");
    }

    string clientID(data.begin(), data.begin() + 16);
    string encryptedAESKey(data.begin() + 16, data.end());

    return LoginOkPayload(clientID, encryptedAESKey);
}

const string& LoginOkPayload::getClientID() const {
    return clientID;
}

const string& LoginOkPayload::getEncryptedAESKey() const {
    return encryptedAESKey;
}

// LoginFailPayload class implementation
LoginFailPayload::LoginFailPayload(const string& clientID) : clientID(clientID) {
    if (clientID.size() != 16) {
        throw std::invalid_argument("clientID must be 16 bytes");
    }
}

LoginFailPayload LoginFailPayload::deserialize(const vector<uint8_t>& data) {
    if (data.size() != 16) {
        throw std::runtime_error("Data size is incorrect for LoginFailPayload deserialization");
    }

    string clientID(data.begin(), data.end());
    return LoginFailPayload(clientID);
}

const string& LoginFailPayload::getClientID() const {
    return clientID;
}

// GeneralErrorPayload class implementation
GeneralErrorPayload GeneralErrorPayload::deserialize(const vector<uint8_t>& data) {
    // No data to deserialize as this is an empty payload
    return GeneralErrorPayload();
}
