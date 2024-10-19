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

public:
	Client(boost::asio::io_context &io_context, const string& address, const string& port, const string &RSAPublicKey, const string &RSAPrivateKey, const string &AESKey);
	
	void sendFile(std::filesystem::path path);
	void sendPacket(unique_ptr<Packet> packet);

};