#pragma once

#include <cstddef>    // For size_t
#include <string>     // For std::string

// Function to compute the CRC for a memory block
unsigned long memcrc(char* b, size_t n);

// Function to read a file and return a CRC checksum with additional info
std::string readfile(std::string fname);