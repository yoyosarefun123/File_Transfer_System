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

string adjustStringSize(const string& str, size_t size) {
	// Create a string with the required size initialized to null terminators
	string result(size, '\0');

	// Copy the original string into the result, ensuring it fits within the specified size
	if (str.size() <= size) {
		// If the string fits, copy it to the result
		result.replace(0, str.length(), str);
	}
	else {
		// If the string is too long, truncate it
		result.replace(0, size, str, 0, size);
	}

	return result;
}

#include <vector>
#include <string>
#include <cstdint>
#include <stdexcept>

using std::vector;
using std::string;

uint8_t deserializeByte(const vector<uint8_t>& data, size_t offset) {
	if (offset >= data.size()) {
		throw std::out_of_range("Offset out of range for deserializing byte");
	}
	return data[offset];
}

uint16_t deserializeShort(const vector<uint8_t>& data, size_t offset) {
	if (offset + 1 >= data.size()) {
		throw std::out_of_range("Offset out of range for deserializing short");
	}
	uint16_t value = data[offset] | (data[offset + 1] << 8);
	return value;  // Already little-endian
}

uint32_t deserializeInt(const vector<uint8_t>& data, size_t offset) {
	if (offset + 3 >= data.size()) {
		throw std::out_of_range("Offset out of range for deserializing int");
	}
	uint32_t value = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
	return value;  // Already little-endian
}

string deserializeString(const vector<uint8_t>& data, size_t offset, size_t length) {
	if (offset + length > data.size()) {
		throw std::out_of_range("Offset out of range for deserializing string");
	}
	return string(data.begin() + offset, data.begin() + offset + length);
}

string trimString(const string& str) {
	size_t first = str.find_first_not_of(" \t\n\r");
	size_t last = str.find_last_not_of(" \t\n\r");
	return (first == string::npos || last == string::npos) ? "" : str.substr(first, last - first + 1);
}

string hexToBytes(const string& hex) {
	std::string bytes;
	for (size_t i = 0; i < hex.length(); i += 2) {
		unsigned char byte = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
		bytes.push_back(byte);
	}
	return bytes;
}

string removeNullPadding(const string& str) {
	// Find the position of the first null terminator ('\0') in the string
	size_t nullPos = str.find('\0');

	// If null terminator is found, return substring up to that point
	// Otherwise, return the original string (no padding)
	if (nullPos != string::npos) {
		return str.substr(0, nullPos);
	}

	return str;
}