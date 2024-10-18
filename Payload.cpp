#include "Payload.h"
#include <cstdint>
#include <vector>
#include <stdexcept>

constexpr int NAME_SIZE = 255;
constexpr int KEY_SIZE = 160;

using std::uint32_t, std::uint16_t, std::uint8_t, std::vector, std::string;

RegisterPayload::RegisterPayload(const string &name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of RegisterPayload");
}

vector<uint8_t> RegisterPayload::serializePayload() {
	return serializeString(this->name);
}

SendKeyPayload::SendKeyPayload(const string &name, const string &publicKey)
	: name(name), publicKey(publicKey)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of SendKeyPayload");
	if (publicKey.size() != KEY_SIZE)
		throw std::invalid_argument("Error: Invalid rsa key size in creation of SendKeyPayload");
}

vector<uint8_t> SendKeyPayload::serializePayload() {
	vector<uint8_t> serializedData;

	vector<uint8_t> serializedName = serializeString(this->name);
	serializedData.insert(serializedData.end(), serializedName.begin(), serializedName.end());

	vector<uint8_t> serializedKey = serializeString(this->publicKey);
	serializedData.insert(serializedData.end(), serializedKey.begin(), serializedKey.end());

	return serializedData;
}

LoginPayload::LoginPayload(const string &name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of LoginPayload");
}

vector<uint8_t> LoginPayload::serializePayload() {
	return serializeString(this->name);
}

SendFilePayload::SendFilePayload(
	uint32_t contentSize,
	uint32_t originalFileSize,
	uint16_t packetNumber,
	uint16_t totalPackets,
	const string& fileName,
	const string& messageContent)
	: contentSize(contentSize), originalFileSize(originalFileSize), packetNumber(packetNumber), totalPackets(totalPackets), fileName(fileName), messageContent(messageContent)
{
	if (fileName.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid file name size in creation of SendFilePayload");
}

vector<uint8_t> SendFilePayload::serializePayload() {
	vector<uint8_t> serializedData;
	
	vector<uint8_t> serializedContentSize = serializeInt(this->contentSize);
	serializedData.insert(serializedData.end(), serializedContentSize.begin(), serializedContentSize.end());

	vector<uint8_t> serializedOriginalFileSize = serializeInt(this->originalFileSize);
	serializedData.insert(serializedData.end(), serializedOriginalFileSize.begin(), serializedOriginalFileSize.end());

	vector<uint8_t> serializedPacketNumber = serializeShort(this->packetNumber);
	serializedData.insert(serializedData.end(), serializedPacketNumber.begin(), serializedPacketNumber.end());

	vector<uint8_t> serializedTotalPackets = serializeShort(this->totalPackets);
	serializedData.insert(serializedData.end(), serializedTotalPackets.begin(), serializedTotalPackets.end());

	vector<uint8_t> serializedFileName = serializeString(this->fileName);
	serializedData.insert(serializedData.end(), serializedFileName.begin(), serializedFileName.end());

	vector<uint8_t> serializedMessageContent = serializeString(this->messageContent);
	serializedData.insert(serializedData.end(), serializedMessageContent.begin(), serializedMessageContent.end());

	return serializedData;
}

ChecksumCorrectPayload::ChecksumCorrectPayload(const string& name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumCorrectPayload");
}

vector<uint8_t> ChecksumCorrectPayload::serializePayload() {
	return serializeString(this->name);
}

ChecksumFailedPayload::ChecksumFailedPayload(const string& name)
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumFailedPayload");
}

vector<uint8_t> ChecksumFailedPayload::serializePayload() {
	return serializeString(this->name);
}

ChecksumShutDownPayload::ChecksumShutDownPayload(const string& name)
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumShutDownPayload");
}

vector<uint8_t> ChecksumShutDownPayload::serializePayload() {
	return serializeString(this->name);
}