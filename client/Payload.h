#pragma once

#include <cstdint>
#include <vector>
#include <string>

using std::uint8_t, std::uint16_t, std::uint32_t, std::string, std::vector;

class Payload {
public:
	virtual vector<uint8_t> serializePayload() const = 0;
};

class RegisterPayload : public Payload { // code 825 - registration
private:
	string name;

public:
	RegisterPayload(const string &name);
	vector<uint8_t> serializePayload() const override;
};

class SendKeyPayload : public Payload { // code 826 - send public key
private:
	string name;
	string publicKey;

public: 
	SendKeyPayload(const string &name, const string &publicKey);
	vector<uint8_t> serializePayload() const override;
};

class LoginPayload : public Payload { // code 827 - login
private:
	string name;

public: 
	LoginPayload(const string &name);
	vector<uint8_t> serializePayload() const override; 
};

class SendFilePayload : public Payload { // code 828 - send file
private:
	uint32_t contentSize;
	uint32_t originalFileSize;
	uint16_t packetNumber;
	uint16_t totalPackets;
	string fileName;
	string messageContent;

public:
	SendFilePayload(
		uint32_t contentSize, 
		uint32_t originalFileSize, 
		uint16_t packetNumber, 
		uint16_t totalPackets, 
		const string &fileName, 
		const string &messageContent);
	vector<uint8_t> serializePayload() const override;
};

class ChecksumCorrectPayload : public Payload { // code 900 - CRC success
private:
	string name;

public: 
	ChecksumCorrectPayload(const string &name);
	vector<uint8_t> serializePayload() const override;
};

class ChecksumFailedPayload : public Payload { // code 901 - CRC failed, sending again
private:
	string name;

public:
	ChecksumFailedPayload(const string &name);
	vector<uint8_t> serializePayload() const override;
};

class ChecksumShutDownPayload : public Payload { // code 902 - CRC failed 4th time, shutting  down
private:
	string name;

public:
	ChecksumShutDownPayload(const string &name);
	vector<uint8_t> serializePayload() const override;
};
