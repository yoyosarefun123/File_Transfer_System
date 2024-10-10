#pragma one

#include <cstdint>
#include <vector>

using std::uint8_t, std::uint16_t, std::uint32_t;

class Payload {
public:
	//virtual void makeBytes(Payload payload) const;
};

class RegisterPayload : public Payload { // code 825 - registration
private:
	std::vector<uint8_t> name;

public:
	RegisterPayload(const std::vector<uint8_t>& name);
	//void makeBytes(Register payload);
};

class SendKeyPayload : public Payload { // code 826 - send public key
private:
	std::vector<uint8_t> name;
	uint8_t publicKey[160];
public: 
	SendKeyPayload(const std::vector<uint8_t> name, 
					uint8_t publicKey[160]);
};

class LoginPayload : public Payload { // code 827 - login
private:
	std::vector<uint8_t> name;

public: 
	LoginPayload(const std::vector<uint8_t> &name);
};

class SendFilePayload : public Payload { // code 828 - send file
private:
	uint32_t contentSize;
	uint32_t originalFileSize;
	uint16_t packetNumber;
	uint16_t totalPackets;
	std::vector<uint8_t> fileName;
	std::vector<uint8_t> messageContent;

public:
	SendFilePayload(uint32_t contentSize, 
					uint32_t originalFileSize, 
					uint16_t packetNumber, 
					uint16_t totalPackets, 
					const std::vector<uint8_t> &fileName, 
					const std::vector<uint8_t> &messageContent);
};

class ChecksumCorrectPayload : public Payload { // code 900 - CRC success
private:
	std::vector<uint8_t> name;

public: 
	ChecksumCorrectPayload(const std::vector<uint8_t>& name);
};

class ChecksumFailedPayload : public Payload { // code 901 - CRC failed, sending again
private:
	std::vector<uint8_t> name;

public:
	ChecksumFailedPayload(const std::vector<uint8_t>& name);
};

class ChecksumShutDownPayload : public Payload { // code 902 - CRC failed 4th time, shutting  down
private:
	std::vector<uint8_t> name;

public:
	ChecksumShutDownPayload(const std::vector<uint8_t>& name);
};