#include "Client.h"
#include <boost/asio.hpp>
#include <stdexcept>
#include "AESWrapper.h"
#include "RSAWrapper.h"
#include "utils.h"
#include <fstream>
#include "RequestManager.h"
#include "ResponseUnpacker.h"
#include <iostream>
#include "Checksum.h"
#include "Base64Wrapper.h"

constexpr size_t SERVER_HEADER_SIZE = 7;
constexpr size_t NAME_SIZE = 255;

Client::Client(boost::asio::io_context& io_context)
    : socket(io_context), resolver(io_context), address(""), port(""), RSAPublicKey(""), RSAPrivateKey(""), AESKey(""), clientID(""), name(""), path("") 
{}

void Client::connect() {
    boost::asio::connect(this->socket, this->resolver.resolve(this->address, this->port));
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

void Client::setName(const string& name) {
    if (name.length() > 100)
        throw std::runtime_error("Name too long (more than 100 character)");
    this->name = adjustStringSize(name, NAME_SIZE);
}

void Client::registrate() {
    for (int i = 0; i < 3; i++) {
        auto packet = registrationPacket(adjustStringSize(this->clientID, 16), adjustStringSize(this->name, 255));
        sendPacket(std::move(packet));
        vector<uint8_t> responseHeaderData(7);
        boost::system::error_code error;
        // Read exactly 7 bytes

        std::cout << "Reading header: " << std::endl;

        size_t bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responseHeaderData), error);

        std::cout << "Read " << bytesRead << " bytes" << std::endl;

        // Handle errors
        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }
        // Ensure we read exactly 7 bytes
        if (bytesRead != SERVER_HEADER_SIZE) {
            throw std::runtime_error("Expected to read 7 bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }


        std::cout << "Checking that registration was a success: " << std::endl;

        auto header = ResponseHeader::deserializeHeader(responseHeaderData);
        std::cout << "Response code: " << static_cast<int>(header.getResponseCode()) << std::endl;

        if (header.getResponseCode() == ResponseCode::REGISTER_FAIL or header.getResponseCode() == ResponseCode::GENERAL_ERROR) {
            if (i == 2)
                std::cout << ("Registration failed for third time - exiting.") << std::endl;
            else
                std::cout << ("Registration failed. Trying again!") << std::endl;
            continue;
        }

        std::cout << "payload size according to header: " << header.getPayloadSize() << std::endl;

        vector<uint8_t> responsePayloadData(header.getPayloadSize());
        bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responsePayloadData), error);

        std::cout << "read " << bytesRead << " bytes into payload" << std::endl;

        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }

        if (bytesRead != header.getPayloadSize()) {
            throw std::runtime_error("Expected to read " + std::to_string(header.getPayloadSize()) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }

        if (header.getResponseCode() == ResponseCode::REGISTER_OK) {
            std::cout << "Registering you!" << std::endl;
            auto payload = RegisterOkPayload::deserialize(responsePayloadData);
            this->clientID = payload.getClientID();
            return;
        }
        else {
            throw std::runtime_error("Illegal header response code for registration attempt.");
        }
    }
    throw std::runtime_error("Failed to register 3 times - aborting.");
}


void Client::sendRSAreceiveAES() {
    // Generate RSA keys
    RSAPrivateWrapper privateWrapper; // Generates a new RSA key pair
    RSAPublicWrapper publicWrapper(privateWrapper.getPublicKey()); // Get the public key from the private key

    std::cout << "Generating RSA keys." << std::endl;

    // Set the generated keys in the object parameters
    RSAPublicKey = publicWrapper.getPublicKey(); // Set the public key
    RSAPrivateKey = privateWrapper.getPrivateKey(); // Set the private key

    // Create priv.key 
    std::cout << "Saving private key in priv.key." << std::endl;
    savePrivateKey();

    for (int i = 0; i < 3; i++) {
        auto packet = sendKeyPacket(this->clientID, this->name, this->RSAPublicKey);
        std::cout << "Sending public RSA key to server." << std::endl;
        sendPacket(std::move(packet));

        vector<uint8_t> responseHeaderData(SERVER_HEADER_SIZE);
        boost::system::error_code error;

        std::cout << "Reading header: " << std::endl;
        size_t bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responseHeaderData), error);
        std::cout << "Read " << bytesRead << " bytes from response header" << std::endl;
        // Handle errors
        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }

        // Ensure we read exactly SERVER_HEADER_SIZE bytes
        if (bytesRead != SERVER_HEADER_SIZE) {
            throw std::runtime_error("Expected to read " + std::to_string(SERVER_HEADER_SIZE) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }

        auto header = ResponseHeader::deserializeHeader(responseHeaderData);
        std::cout << "Header response code: " << static_cast<int>(header.getResponseCode()) << std::endl;
        if (header.getResponseCode() == ResponseCode::GENERAL_ERROR) {
            std::cout << "Server failure trying to send AES key. Trying again!" << std::endl;
            continue;
        }

        if (header.getResponseCode() != ResponseCode::AES_SEND_KEY) {
            throw std::runtime_error("Illegal header response code for send AES request.");
        }

        // Read the payload data
        vector<uint8_t> responsePayloadData(header.getPayloadSize());
        std::cout << "Reading payload: " << std::endl;
        bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responsePayloadData), error);
        std::cout << "Read " << bytesRead << " bytes into payload." << std::endl;

        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }

        if (bytesRead != header.getPayloadSize()) {
            throw std::runtime_error("Expected to read " + std::to_string(header.getPayloadSize()) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }

        // Deserialize the payload
        auto payload = AESSendKeyPayload::deserialize(responsePayloadData);

        // Decrypt the AES key using the RSA private key
        std::string encryptedAESKey = payload.getAesKey(); // Assuming this retrieves the encrypted AES key
        std::string aesKey;

        try {
            aesKey = privateWrapper.decrypt(encryptedAESKey); // Decrypting with the private key
        }
        catch (const std::exception& e) {
            throw std::runtime_error("Failed to decrypt AES key: " + std::string(e.what()));
        }

        // Now aesKey holds the decrypted AES key. You can store it or use it as needed.
        this->AESKey = aesKey; // Set the decrypted AES key in the client
        std::cout << "Successfully decrypted AES key." << std::endl;
        break;
    }
}


void Client::login() {
    for (int i = 0; i < 3; i++) {
        auto packet = loginPacket(adjustStringSize(this->clientID, 16), adjustStringSize(this->name, 255));
        sendPacket(std::move(packet));
        vector<uint8_t> responseHeaderData(7);
        boost::system::error_code error;
        // Read exactly 7 bytes
        size_t bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responseHeaderData), error);

        // Handle errors
        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }
        // Ensure we read exactly 7 bytes
        if (bytesRead != SERVER_HEADER_SIZE) {
            throw std::runtime_error("Expected to read 7 bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }
        auto header = ResponseHeader::deserializeHeader(responseHeaderData);
        if (header.getResponseCode() == ResponseCode::LOGIN_FAIL or header.getResponseCode() == ResponseCode::GENERAL_ERROR) {
            if (i == 2)
                std::cout << ("Login failed for third time - exiting.") << std::endl;
            else
                std::cout << ("Login failed. Trying again!") << std::endl;
            continue;
        }
        vector<uint8_t> responsePayloadData(header.getPayloadSize());
        bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responsePayloadData), error);

        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }

        if (bytesRead != header.getPayloadSize()) {
            throw std::runtime_error("Expected to read " + std::to_string(header.getPayloadSize()) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }

        if (header.getResponseCode() == ResponseCode::LOGIN_OK_SEND_AES) {
            std::cout << "Logging in!" << std::endl;
            auto payload = LoginOkPayload::deserialize(responsePayloadData);
            std::cout << "Deserialized payload..." << std::endl;
            string encryptedAESKey = payload.getEncryptedAESKey(); // Assuming this retrieves the encrypted AES key

            
            RSAPrivateWrapper privateWrapper(this->RSAPrivateKey);
            RSAPublicWrapper publicWrapper(this->RSAPublicKey);

            try {
                std::cout << "Encrypted AES key size: " << encryptedAESKey.size() << std::endl;
                this->AESKey = privateWrapper.decrypt(encryptedAESKey);
            }
            catch (const std::exception& e) {
                throw std::runtime_error("Error in decrypting aes key after login.");
            }

            std::cout << "Login succesful. New AES key received and updated." << std::endl;
            return;
        }
        else {
            throw std::runtime_error("Illegal header response code for registration attempt.");
        }
    }
    throw std::runtime_error("Failed to register 3 times - aborting.");
}


void Client::sendFile() {
    // Step 1: Read the file contents
    if (!std::filesystem::exists(this->path)) {
        throw std::runtime_error("File does not exist");
    }

    // Open the file as binary and read the contents
    std::ifstream file(path, std::ios::binary | std::ios::ate); // Open and move to the end to get size
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file");
    }

    // Get the file size
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg); // Go back to the beginning of the file

    // Read the entire file into a vector of bytes
    std::vector<uint8_t> fileContent(fileSize);
    file.read(reinterpret_cast<char*>(fileContent.data()), fileSize);
    file.close();

    uint32_t checksum = static_cast<uint32_t>(memcrc(reinterpret_cast<char*>(fileContent.data()), fileSize));

    // Step 2: Encrypt the file content using AES encryption
    AESWrapper aes(this->AESKey); // Ensure the AES key is 16 bytes (default length)
    std::string encryptedContent = aes.encrypt(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

    // Step 3: Split the encrypted content into chunks of 1024 bytes
    std::vector<uint8_t> encryptedData(encryptedContent.begin(), encryptedContent.end());
    std::cout << "Size of encryptedData vector: " << encryptedData.size() << std::endl;
    std::vector<std::vector<uint8_t>> chunks = splitIntoChunks(encryptedData, 1024);
    std::cout << "Size of first chunk: " << chunks[0].size() << std::endl;

    // Step 4: Prepare and send packets
    uint16_t totalPackets = static_cast<uint16_t>(chunks.size());
    uint16_t packetNumber = 1;
    std::string fileName = path.filename().string();
    for (int i = 0; i < 3; i++) {
        for (const auto& chunk : chunks) {
            // Create the packet payload
            auto packet = sendFilePacket(
                adjustStringSize(this->clientID, 16),             // 16-byte client ID
                static_cast<uint32_t>(chunk.size()),              // Content size: size of the chunk
                static_cast<uint32_t>(fileSize),                  // Original file size
                packetNumber,                                     // Current packet number
                totalPackets,                                     // Total number of packets
                adjustStringSize(fileName, NAME_SIZE),                  // 255-byte file name
                std::string(chunk.begin(), chunk.end())           // Chunk data as string
            );

            sendPacket(std::move(packet));  // Send the packet
            packetNumber++;                 // Increment packet number
        }

        vector<uint8_t> responseHeaderData(SERVER_HEADER_SIZE);
        boost::system::error_code error;
        size_t bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responseHeaderData), error);

        // Handle errors
        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }

        // Ensure we read exactly SERVER_HEADER_SIZE bytes
        if (bytesRead != SERVER_HEADER_SIZE) {
            throw std::runtime_error("Expected to read " + std::to_string(SERVER_HEADER_SIZE) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }

        auto header = ResponseHeader::deserializeHeader(responseHeaderData);
        if (header.getResponseCode() == ResponseCode::GENERAL_ERROR) {
            std::cout << "Server failure trying to send CRC. Trying again!" << std::endl;
            continue;
        }
        if (header.getResponseCode() != ResponseCode::FILE_OK)
            throw std::runtime_error("Illegal header response code for send file request.");
        else {
            vector<uint8_t> responsePayloadData(header.getPayloadSize());
            bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responsePayloadData), error);

            if (error) {
                throw std::runtime_error("Error reading from socket: " + error.message());
            }

            if (bytesRead != header.getPayloadSize()) {
                throw std::runtime_error("Expected to read " + std::to_string(header.getPayloadSize()) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
            }

            // Deserialize the payload
            auto payload = FileOkPayload::deserialize(responsePayloadData);
            if (payload.getChecksum() != checksum) {
                if (i < 2)
                    handleCRCFailure();
                else if (i == 2)
                    handleCRCShutdown();
            }
            else {
                handleCRCSuccess();
                return;
            }
        }
    }
    throw std::runtime_error("Failed to send file three times. aborting");
}

void Client::handleCRCSuccess() {
    auto packet = checksumCorrectPacket(this->clientID, this->name);
    sendPacket(std::move(packet));
    for (int i = 0; i < 3; i++) {
        vector<uint8_t> responseHeaderData(SERVER_HEADER_SIZE);
        boost::system::error_code error;
        size_t bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responseHeaderData), error);

        // Handle errors
        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }

        // Ensure we read exactly SERVER_HEADER_SIZE bytes
        if (bytesRead != SERVER_HEADER_SIZE) {
            throw std::runtime_error("Expected to read " + std::to_string(SERVER_HEADER_SIZE) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }

        auto header = ResponseHeader::deserializeHeader(responseHeaderData);
        if (header.getResponseCode() == ResponseCode::GENERAL_ERROR) {
            std::cout << "Server failure trying to confirm CRC. Trying again!" << std::endl;
            continue;
        }
        if (header.getResponseCode() != ResponseCode::MESSAGE_OK)
            throw std::runtime_error("Illegal header response code received in handle crc success.");
        else {
            std::cout << "File received succesfully, checksum ok, done!" << std::endl;
            closeConnection();
            return;
        }
    }
}

void Client::handleCRCFailure() {
    auto packet = checksumFailedPacket(this->clientID, this->name);
    sendPacket(std::move(packet));
}

void Client::handleCRCShutdown() {
    auto packet = checksumShutDownPacket(this->clientID, this->name);
    sendPacket(std::move(packet));
    for (int i = 0; i < 3; i++) {
        vector<uint8_t> responseHeaderData(SERVER_HEADER_SIZE);
        boost::system::error_code error;
        size_t bytesRead = boost::asio::read(this->socket, boost::asio::buffer(responseHeaderData), error);

        // Handle errors
        if (error) {
            throw std::runtime_error("Error reading from socket: " + error.message());
        }

        // Ensure we read exactly SERVER_HEADER_SIZE bytes
        if (bytesRead != SERVER_HEADER_SIZE) {
            throw std::runtime_error("Expected to read " + std::to_string(SERVER_HEADER_SIZE) + " bytes, but got " + std::to_string(bytesRead) + " bytes.");
        }

        auto header = ResponseHeader::deserializeHeader(responseHeaderData);
        if (header.getResponseCode() == ResponseCode::GENERAL_ERROR) {
            std::cout << "Server failure trying to fix CRC. Trying again!" << std::endl;
            continue;
        }
        if (header.getResponseCode() != ResponseCode::MESSAGE_OK)
            throw std::runtime_error("Illegal header response code received in handle crc success.");
        else {
            std::cout << "Checksum invalid for third time - exiting." << std::endl;
            closeConnection();
            break;
        }
    }
}

void Client::closeConnection() {
    if (this->socket.is_open()) {
        this->socket.close(); // Close the socket
        std::cout << "Socket closed successfully." << std::endl;
    }
    else {
        std::cout << "Socket is already closed." << std::endl;
    }
}

void Client::loadTransferInfo() {
    std::filesystem::path transferFilePath = std::filesystem::current_path() / "transfer.info";

    std::ifstream transferFile(transferFilePath);

    if (!transferFile.is_open()) {
        throw std::runtime_error("Failed to open transfer.info file.");
    }

    string line;

    // Step 1: Read the first line for the address and port
    if (std::getline(transferFile, line)) {
        size_t delimiterPos = line.find(':');
        if (delimiterPos != string::npos) {
            this->address = trimString(line.substr(0, delimiterPos));   // Extract the address
            this->port = trimString(line.substr(delimiterPos + 1));    // Extract the port
        }
        else {
            throw std::runtime_error("Invalid format for address and port in transfer.info");
        }
    }
    else {
        throw std::runtime_error("transfer.info file is missing the address:port line.");
    }

    // Step 2: Read the second line for the client name
    if (std::getline(transferFile, line)) {
        std::cout << "Name is " << trimString(line).length() << " bytes long." << std::endl;
        this->setName(trimString(line));  // Ensure the name is no more than 100 characters
    }
    else {
        throw std::runtime_error("transfer.info file is missing the client name line.");
    }

    // Step 3: Read the third line for the file path
    if (std::getline(transferFile, line)) {
        std::filesystem::path filePath = std::filesystem::path(trimString(line));

        // Ensure the file exists
        if (!std::filesystem::exists(filePath)) {
            throw std::runtime_error("The file specified in transfer.info does not exist: " + filePath.string());
        }

        this->path = filePath;  // Set the path for the file to be sent
    }
    else {
        throw std::runtime_error("transfer.info file is missing the file path line.");
    }

    // Close the file after reading
    transferFile.close();

    std::cout << "Transfer info loaded successfully:\n";
    std::cout << "Address: " << this->address << "\n";
    std::cout << "Port: " << this->port << "\n";
    std::cout << "Client Name: " << this->name << "\n";
    std::cout << "File Path: " << this->path << "\n";
}

void Client::loadMeInfo() {
    std::filesystem::path meFilePath = std::filesystem::current_path() / "me.info";

    std::ifstream meFile(meFilePath);

    if (!meFile.is_open()) {
        throw std::runtime_error("Failed to open me.info file.");
    }

    string line;

    // Step 1: Read the first line for the client name
    if (std::getline(meFile, line)) {
        this->setName(trimString(line));
        std::cout << "Name loaded from me.info: " << this->name << std::endl;
    }
    else {
        throw std::runtime_error("me.info file is missing the client name line.");
    }

    // Step 2: Read the second line for the user ID in hex format (32 ASCII chars)
    if (std::getline(meFile, line)) {
        string hexClientID = trimString(line);
        if (hexClientID.length() != 32) {
            throw std::runtime_error("Invalid user ID length in me.info. Expected 32 characters.");
        }
        std::cout << "Client id (in hex) loaded from me.info" << hexClientID << std::endl;
        this->clientID = hexToBytes(hexClientID);  // Convert from hex to bytes
    }
    else {
        throw std::runtime_error("me.info file is missing the user ID line.");
    }

    // Step 3: Read the third line for the RSA private key in base64 format
    //if (std::getline(meFile, line)) {
    //    string base64PrivateKey = trimString(line);

    //    // Decode the RSA private key from base64
    //    this->RSAPrivateKey = Base64Wrapper::decode(base64PrivateKey);

    //    // Initialize the RSA private key and derive the public key
    //    RSAPrivateWrapper privateKeyWrapper(this->RSAPrivateKey);
    //    this->RSAPublicKey = privateKeyWrapper.getPublicKey();  // Derive the public key
    //}
    //else {
    //    throw std::runtime_error("me.info file is missing the RSA private key line.");
    //}

    // Close the file after reading
    meFile.close();

    std::cout << "Me info loaded successfully:\n";
    std::cout << "Client Name: " << this->name << "\n";
    std::cout << "Client ID (Hex): " << line << "\n";  // Display hex, but clientID is in byte form internally
    /*std::cout << "RSA Public Key: " << this->RSAPublicKey << "\n";*/
}


void Client::saveClientInfo() {
    // Create or open the "me.info" file in the current directory
    std::filesystem::path meInfoPath = std::filesystem::current_path() / "me.info";
    std::ofstream meInfoFile(meInfoPath);

    if (!meInfoFile.is_open()) {
        throw std::runtime_error("Failed to open me.info for writing");
    }

    // Write client name
    std::cout << "Saving client name: " << this->name << std::endl;
    meInfoFile << removeNullPadding(this->name) << "\n";

    // Write client ID as hex (16 bytes = 32 hex characters)
    std::stringstream ss;
    for (unsigned char c : this->clientID) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    std::cout << "Saving client ID in hex: " << ss.str() << std::endl;
    meInfoFile << ss.str() << "\n";

    // Write RSA private key as base64
    std::string encodedPrivateKey = Base64Wrapper::encode(this->RSAPrivateKey);
    std::cout << "Saving base64 private key: " << encodedPrivateKey << std::endl;
    meInfoFile << encodedPrivateKey << "\n";

    meInfoFile.close();
}

void Client::savePrivateKey() {
    // Create or open the "priv.key" file in the current directory
    std::filesystem::path privKeyPath = std::filesystem::current_path() / "priv.key";
    std::ofstream privKeyFile(privKeyPath);

    if (!privKeyFile.is_open()) {
        throw std::runtime_error("Failed to open priv.key for writing");
    }

    // Write RSA private key as base64
    std::string encodedPrivateKey = Base64Wrapper::encode(this->RSAPrivateKey);
    privKeyFile << encodedPrivateKey;

    privKeyFile.close();
}

void Client::loadPrivateKey() {
    // Open the "priv.key" file in the current directory
    std::filesystem::path privKeyPath = std::filesystem::current_path() / "priv.key";
    std::ifstream privKeyFile(privKeyPath);

    if (!privKeyFile.is_open()) {
        throw std::runtime_error("Failed to open priv.key for reading");
    }

    // Read the base64-encoded private key from the file
    std::string encodedPrivateKey((std::istreambuf_iterator<char>(privKeyFile)), std::istreambuf_iterator<char>());
    encodedPrivateKey = trimString(encodedPrivateKey);
    // Decode the private key
    this->RSAPrivateKey = Base64Wrapper::decode(encodedPrivateKey);
    RSAPrivateWrapper privateKeyWrapper(this->RSAPrivateKey);
    this->RSAPublicKey = privateKeyWrapper.getPublicKey();

    privKeyFile.close();
}