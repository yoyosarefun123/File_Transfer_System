#include "PacketManager.h"
#include <iostream>

#define NAME_SIZE 255

Packet::Packet(unique_ptr<Header> header, unique_ptr<Payload> payload)
	: header(std::move(header)), payload(std::move(payload)) {}

Header::Header(const vector<uint8_t>& clientID, uint16_t code, uint32_t payloadSize, uint8_t version) 
	: clientID(clientID), version(version), code(code), payloadSize(payloadSize) {}

unique_ptr<Packet> registrationPacket(
	vector<uint8_t>& clientID,
	const vector<uint8_t>& name,
	uint8_t version,
	uint16_t code)
{
	if (name.size() != NAME_SIZE) {
		throw std::invalid_argument("Error: Invalid name size in creation of registrationPacket");
	}

	uint32_t payloadSize = name.size();
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize), 
									std::make_unique<RegisterPayload>(name));
}

unique_ptr<Packet> loginPacket(
	vector<uint8_t>& clientID,
	const vector<uint8_t>& name, 
	uint8_t version,
	uint16_t code)
{
	if (name.size() != NAME_SIZE) {
		throw std::invalid_argument("Error: Invalid name size in creation of loginPacket");
	}

	uint32_t payloadSize = name.size();
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize),
		std::make_unique<LoginPayload>(name));
}

unique_ptr<Packet> sendFilePacket(
	vector<uint8_t>& clientID,
	uint32_t originalFileSize,
	uint16_t packetNumber,
	uint16_t totalPackets,
	const vector<uint8_t>& fileName,
	const vector<uint8_t>& messageContent,
	uint8_t version,
	uint16_t code)
{
	if (fileName.size() != NAME_SIZE) {
		throw std::invalid_argument("Error: Invalid file name size in creation of sendFilePacket");
	}

	uint32_t contentSize = fileName.size() + messageContent.size();
	uint32_t payloadSize = contentSize + sizeof(originalFileSize) + sizeof(packetNumber) + sizeof(totalPackets);
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize), 
									std::make_unique<SendFilePayload>(contentSize, originalFileSize, packetNumber, totalPackets, fileName, messageContent));
}

unique_ptr<Packet> checksumCorrectPacket(
	vector<uint8_t>& clientID,
	const vector<uint8_t>& name,
	uint8_t version,
	uint16_t code)
{
	if (name.size() != NAME_SIZE) {
		throw std::invalid_argument("Error: Invalid name size in creation of checksumCorrectPacket");
	}
	
	uint32_t payloadSize = name.size();
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize),
		std::make_unique<ChecksumCorrectPayload>(name));
}

unique_ptr<Packet> checksumFailedPacket(
	vector<uint8_t>& clientID,
	const vector<uint8_t>& name,
	uint8_t version,
	uint16_t code)
{
	if (name.size() != NAME_SIZE) {
		throw std::invalid_argument("Error: Invalid name size in creation of checksumFailedPacket");
	}

	uint32_t payloadSize = name.size();
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize),
		std::make_unique<ChecksumFailedPayload>(name));
}

unique_ptr<Packet> checksumShutDownPacket(
	vector<uint8_t>& clientID,
	const vector<uint8_t>& name,
	uint8_t version,
	uint16_t code)
{
	
	if (name.size() != NAME_SIZE) {
		throw std::invalid_argument("Error: Invalid name size in creation of checksumShutDownPacket");
	}

	uint32_t payloadSize = name.size();
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize),
		std::make_unique<ChecksumShutDownPayload>(name));
}


