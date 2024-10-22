#pragma once

#include <boost/asio.hpp>
#include <string>
#include "RequestManager.h"
#include <filesystem>

using boost::asio::ip::tcp, std::string;

class Client {
private:
	tcp::socket socket;
	tcp::resolver resolver;
	string address;
	string port;
	string RSAPublicKey;
	string RSAPrivateKey;
	string AESKey;
	string clientID;
	string name;
	std::filesystem::path path;

public:
	Client(boost::asio::io_context& io_context);
	
	void setName(const string& name);

	void sendFile();
	void connect();
	void sendPacket(unique_ptr<Packet> packet);
	void registrate();
	void login();
	void sendRSAreceiveAES();
	void handleCRCSuccess();
	void handleCRCFailure();
	void handleCRCShutdown();
	void closeConnection();
	void loadTransferInfo();
	void loadMeInfo();
	void saveClientInfo();
	void savePrivateKey();
	void loadPrivateKey();
};