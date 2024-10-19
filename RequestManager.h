#pragma once

#include <cstdint>
#include <vector>
#include "Payload.h"
#include <memory>

constexpr int CLIENT_VERSION = 3;

enum CODES {
	REGISTER_CODE = 825,
	SEND_KEY_CODE = 826,
	LOGIN_CODE = 827,
	SEND_FILE_CODE = 828,

	CHECKSUM_CORRECT_CODE = 900,
	CHECKSUM_FAILED_CODE = 901,
	CHECKSUM_SHUTDOWN_CODE = 902
};

using std::uint8_t, std::uint16_t, std::uint32_t, std::vector, std::unique_ptr, std::string;

class Header {
private:
	string clientID;
	uint8_t version;
	uint16_t code;
	uint32_t payloadSize;

public:
	Header(const string& clientID, uint16_t code, uint32_t payloadSize, uint8_t version = CLIENT_VERSION);
	vector<uint8_t> serializeHeader() const;
};

class Packet {
private:
	unique_ptr<Header> header;
	unique_ptr<Payload> payload;

public:
	Packet(unique_ptr<Header> header, unique_ptr<Payload> payload);
	unique_ptr<Header> getHeader();
	unique_ptr<Payload> getPayload();
};

unique_ptr<Packet> registrationPacket(
	const string &clientID, 
	const string& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = REGISTER_CODE);

unique_ptr<Packet> sendKeyPacket(
	const string& clientID,
	const string& name,
	const string& publicKey,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = SEND_KEY_CODE);

unique_ptr<Packet> loginPacket(
	const string& clientID, 
	const string& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = LOGIN_CODE);

unique_ptr<Packet> sendFilePacket(
	const string& clientID,  
	uint32_t contentSize,
	uint32_t originalFileSize,
	uint16_t packetNumber,
	uint16_t totalPackets,
	const string& fileName,
	const string& messageContent,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = SEND_FILE_CODE);

unique_ptr<Packet> checksumCorrectPacket(
	const string& clientID,  
	const string& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = CHECKSUM_CORRECT_CODE);

unique_ptr<Packet> checksumFailedPacket(
	string& clientID, 
	const string& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = CHECKSUM_FAILED_CODE);

unique_ptr<Packet> checksumShutDownPacket(
	const string& clientID, 
	const string& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = CHECKSUM_SHUTDOWN_CODE);


