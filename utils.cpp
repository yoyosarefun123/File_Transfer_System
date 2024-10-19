#include "utils.h"
#include <string>
#include <vector>

using std::string, std::vector;

vector<uint8_t> serializeByte(uint8_t num)
{
	vector<uint8_t> serializedByte = { num };
	return serializedByte;
}

vector<uint8_t> serializeShort(uint16_t num)
{
	vector<uint8_t> serializedShort(2);
	serializedShort[0] = static_cast<uint8_t>(num & 0xFF);
	serializedShort[1] = static_cast<uint8_t>((num >> 8) & 0xFF);
	return serializedShort;
}

vector<uint8_t> serializeInt(uint32_t num)
{
	vector<uint8_t> serializedInt(4);
	serializedInt[0] = static_cast<uint8_t>(num & 0xFFFF);
	serializedInt[1] = static_cast<uint8_t>((num >> 8) & 0xFFFF);
	serializedInt[2] = static_cast<uint8_t>((num >> 16) & 0xFFFF);
	serializedInt[3] = static_cast<uint8_t>((num >> 24) & 0xFFFF);
	return serializedInt;
}

vector<uint8_t> serializeString(const string& input) {
	vector<uint8_t> serialized(input.begin(), input.end());  // Copy each character as uint8_t
	return serialized;
}

vector<vector<uint8_t>> splitIntoChunks(const vector<uint8_t>& data, size_t chunkSize) {
	vector<vector<uint8_t>> chunks;
	size_t totalSize = data.size();

	for (size_t i = 0; i < totalSize; i += chunkSize) {
		size_t end = std::min(i + chunkSize, totalSize);
		vector<uint8_t> chunk(data.begin() + i, data.begin() + end);
		chunks.push_back(chunk);
	}

	return chunks;
}
