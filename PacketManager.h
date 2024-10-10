#pragma one

#include <cstdint>
#include <vector>

class Packet {
	Header header;
	Payload payload;
};

struct Header {
	std::uint8_t clientID[16];
	std::uint8_t version;
	std::uint16_t code;
	std::uint32_t payloadSize;
};

class Payload {
	std::vector<std::uint8_t> payload;
};
