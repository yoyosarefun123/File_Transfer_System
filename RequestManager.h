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
};

unique_ptr<Packet> registrationPacket(
	vector<uint8_t> &clientID, 
	const vector<uint8_t>& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = REGISTER_CODE);

unique_ptr<Packet> sendKeyPacket(
	vector<uint8_t>& clientID,
	const vector<uint8_t>& name,
	string publicKey,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = SEND_KEY_CODE);

unique_ptr<Packet> loginPacket(
	vector<uint8_t>& clientID, 
	const vector<uint8_t>& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = LOGIN_CODE);

unique_ptr<Packet> sendFilePacket(
	vector<uint8_t>& clientID,  
	uint32_t originalFileSize,
	uint16_t packetNumber,
	uint16_t totalPackets,
	const vector<uint8_t>& fileName,
	const vector<uint8_t>& messageContent,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = SEND_FILE_CODE);

unique_ptr<Packet> checksumCorrectPacket(
	vector<uint8_t>& clientID,  
	const vector<uint8_t>& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = CHECKSUM_CORRECT_CODE);

unique_ptr<Packet> checksumFailedPacket(
	vector<uint8_t>& clientID, 
	const vector<uint8_t>& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = CHECKSUM_FAILED_CODE);

unique_ptr<Packet> checksumShutDownPacket(
	vector<uint8_t>& clientID, 
	const vector<uint8_t>& name,
	uint8_t version = CLIENT_VERSION,
	uint16_t code = CHECKSUM_SHUTDOWN_CODE);


