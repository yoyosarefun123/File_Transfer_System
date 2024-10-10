#include "Payload.h"
#include <cstdint>
#include <vector>
#include <iostream>

#define NAME_SIZE 255

using std::uint32_t, std::uint16_t, std::uint8_t;

RegisterPayload::RegisterPayload(const std::vector<uint8_t> &name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("ERROR: Invalid name size in creation of RegisterPayload");
}

LoginPayload::LoginPayload(const std::vector<uint8_t> &name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of LoginPayload");
}

SendFilePayload::SendFilePayload(uint32_t contentSize,
								 uint32_t originalFileSize,
								 uint16_t packetNumber,
								 uint16_t totalPackets,
								 const std::vector<uint8_t>& fileName,
								 const std::vector<uint8_t>& messageContent) 
	: contentSize(contentSize), originalFileSize(originalFileSize), packetNumber(packetNumber), totalPackets(totalPackets), fileName(fileName), messageContent(messageContent)
{
	if (fileName.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid file name size in creation of SendFilePayload");
}

ChecksumCorrectPayload::ChecksumCorrectPayload(const std::vector<uint8_t>& name) 
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumCorrectPayload");
}

ChecksumFailedPayload::ChecksumFailedPayload(const std::vector<uint8_t>& name)
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumFailedPayload");
}

ChecksumShutDownPayload::ChecksumShutDownPayload(const std::vector<uint8_t>& name)
	: name(name)
{
	if (name.size() != NAME_SIZE)
		throw std::invalid_argument("Error: Invalid name size in creation of ChecksumShutDownPayload");
}