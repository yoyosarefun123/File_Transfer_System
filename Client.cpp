#include "Client.h"
#include <boost/asio.hpp>
#include <stdexcept>
#include "AESWrapper.h"
#include "utils.h"
#include <fstream>
#include "RequestManager.h"

Client::Client(boost::asio::io_context &io_context, const string& address, const string& port, const string &RSAPublicKey, const string &RSAPrivateKey, const string &AESKey)
	: socket(io_context), resolver(io_context), address(address), port(port), RSAPublicKey(RSAPublicKey), RSAPrivateKey(RSAPrivateKey), AESKey(AESKey) 
{
	boost::asio::connect(socket, resolver.resolve(address, port));
}

void Client::sendPacket(unique_ptr<Packet> packet) {
    // Serialize the packet's header and payload
    vector<uint8_t> serializedData = packet->getHeader()->serializeHeader();
    vector<uint8_t> serializedPayload = packet->getPayload()->serializePayload();

    // Combine header and payload into one packet to send
    serializedData.insert(serializedData.end(), serializedPayload.begin(), serializedPayload.end());

    // Send the packet over the socket
    boost::asio::write(this->socket, boost::asio::buffer(serializedData));
}


void Client::sendFile(std::filesystem::path path) {
    // Step 1: Read the file contents
    if (!std::filesystem::exists(path)) {
        throw std::runtime_error("File does not exist");
    }

    // Open file as binary and read the contents
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file");
    }

    // Get the file size
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read the entire file into a string
    std::vector<uint8_t> fileContent(fileSize);
    file.read(reinterpret_cast<char*>(fileContent.data()), fileSize);
    file.close();

    // Step 2: Encrypt the file content using AES encryption
    AESWrapper aes(reinterpret_cast<const uint8_t*>(AESKey.c_str()), AESKey.size());
    std::string encryptedContent = aes.encrypt(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

    // Step 3: Split encrypted content into chunks of 1024 bytes
    std::vector<uint8_t> encryptedData(encryptedContent.begin(), encryptedContent.end());
    std::vector<std::vector<uint8_t>> chunks = splitIntoChunks(encryptedData, 1024);

    // Step 4: Prepare and send packets
    uint16_t totalPackets = static_cast<uint16_t>(chunks.size());
    uint16_t packetNumber = 1;
    std::string fileName = path.filename().string();

    for (const auto& chunk : chunks) {
        // Create the packet payload
        auto packet = sendFilePacket(
            this->clientID,
            static_cast<uint32_t> (chunk.size() + fileName.size()),
            static_cast<uint32_t>(fileSize),
            packetNumber,
            totalPackets,
            fileName,
            string(chunk.begin(), chunk.end())
            );

        sendPacket(std::move(packet));

        packetNumber++;  // Increment packet number
    }
}
