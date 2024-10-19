#include "RequestManager.h"
#include <stdexcept>
#include "utils.h"

constexpr int NAME_SIZE = 255;
constexpr int KEY_SIZE = 160;

Packet::Packet(unique_ptr<Header> header, unique_ptr<Payload> payload)
	: header(std::move(header)), payload(std::move(payload)) {}


unique_ptr<Header> Packet::getHeader() {
	return std::move(this->header);
}

unique_ptr<Payload> Packet::getPayload() {
	return std::move(this->payload);
}

Header::Header(const string& clientID, uint16_t code, uint32_t payloadSize, uint8_t version) 
	: clientID(clientID), code(code), payloadSize(payloadSize), version(version) {}

vector<uint8_t> Header::serializeHeader() const {
	vector<uint8_t> serializedData;

	vector<uint8_t> serializedClientID = serializeString(this->clientID);
	serializedData.insert(serializedData.end(), serializedClientID.begin(), serializedClientID.end());

	vector<uint8_t> serializedVersion = serializeByte(this->version);
	serializedData.insert(serializedData.end(), serializedVersion.begin(), serializedVersion.end());

	vector<uint8_t> serializedCode = serializeShort(code);
	serializedData.insert(serializedData.end(), serializedCode.begin(), serializedCode.end());
	
	vector<uint8_t> serializedPayloadSize = serializeInt(payloadSize);
	serializedData.insert(serializedData.end(), serializedPayloadSize.begin(), serializedPayloadSize.end());

	return serializedData;
}

unique_ptr<Packet> registrationPacket(
	string& clientID,
	const string& name,
	uint8_t version,
	uint16_t code)
{
	if (name.size() != NAME_SIZE) 
		throw std::invalid_argument("Error: Invalid name size in creation of registrationPacket");

	uint32_t payloadSize = name.size();
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize), 
									std::make_unique<RegisterPayload>(name));
}

unique_ptr<Packet> sendKeyPacket(
	const string& clientID,
	const string& name,
	const string& publicKey,
	uint8_t version,
	uint16_t code)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of sendKeyPacket");
	if (publicKey.size() != KEY_SIZE)
		throw std::invalid_argument("Error: Invalid public key size in creation of sendKeyPacket");

	uint32_t payloadSize = name.size() + publicKey.size();
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize),
									std::make_unique<SendKeyPayload>(name, publicKey));
}

unique_ptr<Packet> loginPacket(
	const string& clientID,
	const string& name, 
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
	const string& clientID,
	uint32_t contentSize,
	uint32_t originalFileSize,
	uint16_t packetNumber,
	uint16_t totalPackets,
	const string& fileName,
	const string& messageContent,
	uint8_t version,
	uint16_t code)
{
	if (fileName.size() != NAME_SIZE) {
		throw std::invalid_argument("Error: Invalid file name size in creation of sendFilePacket");
	}

	uint32_t payloadSize = contentSize + sizeof(originalFileSize) + sizeof(packetNumber) + sizeof(totalPackets);
	return std::make_unique<Packet>(std::make_unique<Header>(clientID, version, code, payloadSize), 
									std::make_unique<SendFilePayload>(contentSize, originalFileSize, packetNumber, totalPackets, fileName, messageContent));
}

unique_ptr<Packet> checksumCorrectPacket(
	const string& clientID,
	const string& name,
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
	const string& clientID,
	const string& name,
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
	const string& clientID,
	const string& name,
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


