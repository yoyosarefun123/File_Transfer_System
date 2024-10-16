#include "Payload.h"
#include <cstdint>
#include <vector>
#include <stdexcept>

constexpr int NAME_SIZE = 255;
constexpr int KEY_SIZE = 160;

using std::uint32_t, std::uint16_t, std::uint8_t, std::vector, std::string;

RegisterPayload::RegisterPayload(const vector<uint8_t> &name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of RegisterPayload");
}

SendKeyPayload::SendKeyPayload(const vector<uint8_t>& name, string publicKey)
	: name(name), publicKey(publicKey)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of SendKeyPayload");
	if (publicKey.size() != KEY_SIZE)
		throw std::invalid_argument("Error: Invalid rsa key size in creation of SendKeyPayload");
}

LoginPayload::LoginPayload(const vector<uint8_t> &name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of LoginPayload");
}

SendFilePayload::SendFilePayload(uint32_t contentSize,
								 uint32_t originalFileSize,
								 uint16_t packetNumber,
								 uint16_t totalPackets,
								 const vector<uint8_t>& fileName,
								 const vector<uint8_t>& messageContent) 
	: contentSize(contentSize), originalFileSize(originalFileSize), packetNumber(packetNumber), totalPackets(totalPackets), fileName(fileName), messageContent(messageContent)
{
	if (fileName.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid file name size in creation of SendFilePayload");
}

ChecksumCorrectPayload::ChecksumCorrectPayload(const vector<uint8_t>& name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumCorrectPayload");
}

ChecksumFailedPayload::ChecksumFailedPayload(const vector<uint8_t>& name)
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumFailedPayload");
}

ChecksumShutDownPayload::ChecksumShutDownPayload(const vector<uint8_t>& name)
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumShutDownPayload");
}