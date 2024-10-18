#pragma once

#include <boost/asio.hpp>
#include <string>
#include "RequestManager.h"

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

public:
	Client(boost::asio::io_context &io_context, const string& address, const string& port, const string &RSAPublicKey, const string &RSAPrivateKey, const string &AESKey);
	void sendFile();
	void sendPacket(Packet packet, uint16_t code);
	void sendFilePacket(Packet packet);
	void sendKeyPacket(Packet packet);
	void sendLoginPacket(Packet packet);
	void sendRegisterPacket(Packet packet);
	void sendChecksumCorrectPacket(Packet packet);
	void sendChecksumFailedPacket(Packet packet);
	void sendChecksumShutDownPacket(Packet packet);

};