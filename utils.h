#pragma once

#include <cstdint>
#include <vector>
using std::uint8_t, std::uint16_t, std::uint32_t, std::vector;

vector<uint8_t> serializeByte(uint8_t num);
vector<uint8_t> serializeShort(uint16_t num);
vector<uint8_t> serializeInt(uint32_t num);
vector<uint8_t> serializeString(const string& input);