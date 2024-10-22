#pragma once

#include <cstdint>
#include <vector>
#include <string>
using std::uint8_t, std::uint16_t, std::uint32_t, std::vector, std::string;

vector<uint8_t> serializeByte(uint8_t num);
vector<uint8_t> serializeShort(uint16_t num);
vector<uint8_t> serializeInt(uint32_t num);
vector<uint8_t> serializeString(const string &input);
vector<vector<uint8_t>> splitIntoChunks(const vector<uint8_t>& data, size_t chunkSize);
string adjustStringSize(const string& str, size_t size);
uint8_t deserializeByte(const vector<uint8_t>& data, size_t offset);
uint16_t deserializeShort(const vector<uint8_t>& data, size_t offset);
uint32_t deserializeInt(const vector<uint8_t>& data, size_t offset);
string deserializeString(const vector<uint8_t>& data, size_t offset, size_t length);
string trimString(const string& str);
string hexToBytes(const string& hex);
string removeNullPadding(const string& str);
