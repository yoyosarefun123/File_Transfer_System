import struct
import enum
from abc import ABC, abstractmethod

# Define ResponseCode enum
class ResponseCode(enum.Enum):
    REGISTER_OK = 1600
    REGISTER_FAIL = 1601
    AES_SEND_KEY = 1602
    FILE_OK = 1603
    MESSAGE_OK = 1604
    LOGIN_OK_SEND_AES = 1605
    LOGIN_FAIL = 1606
    GENERAL_ERROR = 1607

# Header class for packing the common header part
class ResponseHeader:
    def __init__(self, version: int, response_code: ResponseCode, payload_size: int):
        self.version = version
        self.response_code = response_code
        self.payload_size = payload_size

    def serialize(self):
        # Pack version (1 byte), response_code (2 bytes), payload_size (4 bytes) using big-endian format
        return struct.pack('>BHI', self.version, self.response_code.value, self.payload_size)

# Abstract Payload class
class ResponsePayload(ABC):
    @abstractmethod
    def serialize(self):
        pass

# Register OK Payload: client ID (16 bytes)
class RegisterOkPayload(ResponsePayload):
    def __init__(self, client_id: bytes):
        if len(client_id) != 16:
            raise ValueError("client_id must be 16 bytes")
        self.client_id = client_id

    def serialize(self):
        return self.client_id  # Client ID is already bytes (16 bytes)

# Register Fail Payload: empty payload
class RegisterFailPayload(ResponsePayload):
    def serialize(self):
        return b''  # Empty payload

# AES Send Key Payload: client ID (16 bytes), AES key (dynamic size)
class AESSendKeyPayload(ResponsePayload):
    def __init__(self, client_id: bytes, aes_key: bytes):
        if len(client_id) != 16:
            raise ValueError("client_id must be 16 bytes")
        self.client_id = client_id
        self.aes_key = aes_key

    def serialize(self):
        return self.client_id + self.aes_key

# File OK Payload: client ID (16 bytes), content size (4 bytes), file name (255 bytes), checksum (4 bytes)
class FileOkPayload(ResponsePayload):
    def __init__(self, client_id: bytes, content_size: int, file_name: str, checksum: int):
        if len(client_id) != 16:
            raise ValueError("client_id must be 16 bytes")
        if len(file_name) > 255:
            raise ValueError("file_name must not exceed 255 bytes")
        self.client_id = client_id
        self.content_size = content_size
        self.file_name = file_name.ljust(255, '\x00')  # Pad to 255 bytes
        self.checksum = checksum

    def serialize(self):
        return (
            self.client_id +
            struct.pack('>I', self.content_size) +  # 4 bytes content size
            self.file_name.encode('utf-8') +  # 255 bytes file name
            struct.pack('>I', self.checksum)  # 4 bytes checksum
        )

# Message OK Payload: client ID (16 bytes)
class MessageOkPayload(ResponsePayload):
    def __init__(self, client_id: bytes):
        if len(client_id) != 16:
            raise ValueError("client_id must be 16 bytes")
        self.client_id = client_id

    def serialize(self):
        return self.client_id

# Login OK Send AES Payload: client ID (16 bytes), aes key (dynamic size)
class LoginOkSendAesPayload(ResponsePayload):
    def __init__(self, client_id: bytes, aes_key: bytes):
        if len(client_id) != 16:
            raise ValueError("client_id must be 16 bytes")
        self.client_id = client_id
        self.aes_key = aes_key

    def serialize(self):
        return self.client_id + self.aes_key

# Login Fail Payload: client ID (16 bytes)
class LoginFailPayload(ResponsePayload):
    def __init__(self, client_id: bytes):
        if len(client_id) != 16:
            raise ValueError("client_id must be 16 bytes")
        self.client_id = client_id

    def serialize(self):
        return self.client_id

# General Error Payload: empty payload
class GeneralErrorPayload(ResponsePayload):
    def serialize(self):
        return b''  # Empty payload

# Packet class to combine header and payload
class Packet:
    def __init__(self, header: ResponseHeader, payload: ResponsePayload):
        self.header = header
        self.payload = payload

    def serialize(self):
        serialized_header = self.header.serialize()
        serialized_payload = self.payload.serialize()
        return serialized_header + serialized_payload

# Factory function to create packets
def create_packet(response_code: ResponseCode, version: int, payload: ResponsePayload):
    payload_size = len(payload.serialize())
    header = ResponseHeader(version, response_code, payload_size)
    return Packet(header, payload)

# Example Usage
if __name__ == "__main__":
    # Example: Register OK packet
    client_id = b'1234567890123456'  # 16 bytes client ID
    response_packet = create_packet(ResponseCode.REGISTER_OK, 1, RegisterOkPayload(client_id))
    serialized_packet = response_packet.serialize()
    print(serialized_packet)
