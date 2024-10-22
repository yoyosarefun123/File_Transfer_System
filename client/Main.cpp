#include <iostream>
#include <boost/asio.hpp>
#include <filesystem>
#include <memory>
#include "Client.h" // Include your Client class header file

using namespace std;

int main() {
    // Initialize Boost ASIO context
    boost::asio::io_context io_context;

    // Define server address and port
    const string address = "127.0.0.1"; // or use your server's IP address
    const string port = "12345"; // Port your server is listening on

    // Example RSA and AES keys (replace these with actual keys)
    string RSAPublicKey = "your_public_key_here";
    string RSAPrivateKey = "your_private_key_here";
    string AESKey = "your_aes_key_here"; // Ensure this key is 16 bytes long

    // Create a unique pointer to a Client instance
    auto client = make_unique<Client>(io_context, address, port, RSAPublicKey, RSAPrivateKey, AESKey);

    // Define the path to the file you want to send
    std::filesystem::path filePath = "test.txt";

    // Attempt to send the file
    try {
        client->sendFile(filePath);
        cout << "File sent successfully." << endl;
    }
    catch (const std::exception& e) {
        cerr << "Error while sending file: " << e.what() << endl;
    }

    return 0;
}
