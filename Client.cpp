#include "Client.h"
#include <boost/asio.hpp>
#include <stdexcept>

Client::Client(boost::asio::io_context &io_context, const string& address, const string& port, const string &RSAPublicKey, const string &RSAPrivateKey, const string &AESKey)
	: socket(io_context), resolver(io_context), address(address), port(port), RSAPublicKey(RSAPublicKey), RSAPrivateKey(RSAPrivateKey), AESKey(AESKey) 
{
	boost::asio::connect(socket, resolver.resolve(address, port));
}