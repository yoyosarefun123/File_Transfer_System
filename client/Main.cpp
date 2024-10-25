#include <iostream>
#include <boost/asio.hpp>
#include <filesystem>
#include <memory>
#include "Client.h" // Include your Client class header file

int main() {
    // Initialize Boost ASIO context
    try {
        boost::asio::io_context io_context;

        // Create a unique pointer to a Client instance
        auto client = std::make_unique<Client>(io_context);
        client->loadTransferInfo();
        client->connect();

        if (!std::filesystem::exists(std::filesystem::current_path() / "me.info")) {
            try {
                client->registrate();
            }
            catch (const std::exception& e) {
                std::cerr << "Error in registration: " << e.what() << std::endl;
                exit(0);
            }
            try {
                client->sendRSAreceiveAES();
            }
            catch (const std::exception& e) {
                std::cerr << "Error in sending RSA key or receiving AES key: " << e.what() << std::endl;
                exit(0);
            }
        }
        else {
            std::cout << "Attempting to load info from me.info:" << std::endl;
            client->loadMeInfo();
            std::cout << "Attempting to load key from prev.key:" << std::endl;
            client->loadPrivateKey();
            try {
                client->login();
            }
            catch (const std::exception& e) {
                std::cerr << "Error in login: " << e.what() << std::endl;
                exit(0);
            }
        }

        try {
            client->sendFile();
        }
        catch (const std::exception& e) {
            std::cerr << "Error in sending file process: " << e.what() << std::endl;
            exit(0);
        }
        try {
            client->saveClientInfo();
        }
        catch (const std::exception& e) {
            std::cerr << "Error in saving client info: " << e.what() << std::endl;
            exit(0);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception raised: " << e.what() << std::endl;
    }
    return 0;
}
    