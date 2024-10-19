import enum
import struct
from abc import ABC, abstractmethod


CLIENT_ID_SIZE = 255
NAME_SIZE = 255
FILE_NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160


class RequestCode(enum.Enum):
    REGISTER = 825
    SEND_RSA_PUBLIC_KEY = 826
    LOGIN = 827
    SEND_FILE = 828

    CRC_OK = 900
    CRC_FAIL_TRY_AGAIN = 901
    CRC_FAIL_SHUT_DOWN = 902


import struct

class RequestPacket(ABC):
    HEADER_FORMAT = "16sBHL"  # Client ID (16 bytes), client version (1 byte), request code (2 bytes), payload size (4 bytes)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, client_id, client_version, request_code, payload_size):
        self.client_id = client_id
        self.client_version = client_version
        self.request_code = request_code
        self.payload_size = payload_size

    @abstractmethod
    def unpack_payload(self, data):
        """Derived classes must implement this to unpack their specific payload."""
        pass


    def unpack_header(self, data):
        """Unpacks the common header."""
        self.client_id, self.client_version, self.request_code, self.payload_size = struct.unpack(self.HEADER_FORMAT, data[:self.HEADER_SIZE])
        self.client_id = self.client_id.rstrip(b'\x00').decode('utf-8')  # Remove null terminators and decode


    def unpack(self, data):
        """Unpacks the full packet (header + payload)."""
        self.unpack_header(data)
        self.unpack_payload(data[self.HEADER_SIZE:])


# Registration Request (825), Login Request (827), Checksum OK (900), Checksum Retry (901), Checksum Shut Down (902)
class NameBasedRequest(RequestPacket):
    def __init__(self, client_id, client_version, request_code, name):
        self.name = name.ljust(255, '\x00')  # Pad name to 255 bytes
        payload_size = 255
        super().__init__(client_id, client_version, request_code, payload_size)

    def unpack_payload(self, data):
        self.name = data[:255].decode('utf-8').rstrip('\x00')  # Unpack the name, remove null terminators


class SendRSAKeyRequest(RequestPacket):
    def __init__(self, client_id, client_version, name, rsa_key):
        self.name = name.ljust(255, '\x00')  # Pad name to 255 bytes
        self.rsa_key = rsa_key  # Assume rsa_key is already 160 bytes
        if len(rsa_key) != 160:
            raise ValueError("RSA key must be 160 bytes")
        payload_size = 255 + 160
        super().__init__(client_id, client_version, request_code=826, payload_size=payload_size)

    def unpack_payload(self, data):
        self.name = data[:255].decode('utf-8').rstrip('\x00')
        self.rsa_key = data[255:415]  # RSA key is 160 bytes


class SendFileRequest(RequestPacket):
    FILE_NAME_SIZE = 255

    def __init__(self, client_id, client_version, content_size, original_file_size, packet_number, total_packets, file_name, message_content):
        self.content_size = content_size
        self.original_file_size = original_file_size
        self.packet_number = packet_number
        self.total_packets = total_packets
        self.file_name = file_name.ljust(self.FILE_NAME_SIZE, '\x00')  # Pad file name
        self.message_content = message_content
        payload_size = 8 + 4 + 2 + 2 + len(self.file_name.encode('utf-8')) + len(self.message_content)
        super().__init__(client_id, client_version, request_code=828, payload_size=payload_size)

    def unpack_payload(self, data):
        payload_format = f'LLHH{self.FILE_NAME_SIZE}s'
        self.content_size, self.original_file_size, self.packet_number, self.total_packets, file_name_bytes = struct.unpack(payload_format, data)
        self.file_name = file_name_bytes.decode('utf-8').rstrip('\x00')
        self.message_content = data[struct.calcsize(payload_format):].decode('utf-8')


class RequestPacketFactory:
    @staticmethod
    def create_packet(data):
        """Creates a packet based on the request code."""
        # Extract request code from the header
        client_id, client_version, request_code, payload_size = struct.unpack(RequestPacket.HEADER_FORMAT, data[:RequestPacket.HEADER_SIZE])

        client_id = client_id.rstrip(b'\x00').decode('utf-8')  # Convert client ID to string

        # Determine which class to instantiate based on request code
        if request_code == 825:
            return NameBasedRequest(client_id, client_version, request_code, "")
        elif request_code == 826:
            return SendRSAKeyRequest(client_id, client_version, "", b"")
        elif request_code == 827:
            return NameBasedRequest(client_id, client_version, request_code, "")
        elif request_code == 828:
            return SendFileRequest(client_id, client_version, 0, 0, 0, 0, "", "")
        elif request_code in {900, 901, 902}:
            return NameBasedRequest(client_id, client_version, request_code, "")
        else:
            raise ValueError(f"Unknown request code: {request_code}")

# def unpack_header(header):
#     # Assuming clientID is a fixed size of 255 bytes 
#     clientID_size = CLIENT_ID_SIZE
#     header_format = f'{clientID_size}sBHL'  # string of 255 bytes, uint8 (version), uint16 (code), uint32 (payloadSize)
    
#     clientID, version, code, payload_size = struct.unpack(header_format, header[:struct.calcsize(header_format)])
    
#     # Decode clientID from bytes to string, stripping null bytes
#     clientID = clientID.decode('utf-8').rstrip('\x00')
    
#     return {
#         'clientID': clientID,
#         'version': version,
#         'code': code,
#         'payload_size': payload_size
#     }


# def unpack_register_payload(payload):
#     # Assuming the name is a fixed-size string of 255 bytes
#     name_size = NAME_SIZE
#     payload_format = f'{name_size}s'

#     name, = struct.unpack(payload_format, payload[:struct.calcsize(payload_format)])

#     # Decode name and trim null terminators
#     name = name.decode('utf-8').rstrip('\x00')

#     return {
#         'name': name
#     }


# def unpack_send_key_payload(payload):
#     # Assuming name and publicKey are fixed-size strings: name (255 bytes) and publicKey (160 bytes)
#     name_size = NAME_SIZE
#     public_key_size = PUBLIC_KEY_SIZE
#     payload_format = f'{name_size}s{public_key_size}s'

#     name, public_key = struct.unpack(payload_format, payload[:struct.calcsize(payload_format)])

#     # Decode name and publicKey, and trim null terminators
#     name = name.decode('utf-8').rstrip('\x00')
#     public_key = public_key.decode('utf-8').rstrip('\x00')

#     return {
#         'name': name,
#         'public_key': public_key
#     }


# def unpack_login_payload(payload):
#     # Assuming the name is a fixed-size string of 255 bytes
#     name_size = NAME_SIZE
#     payload_format = f'{name_size}s'

#     name, = struct.unpack(payload_format, payload[:struct.calcsize(payload_format)])

#     # Decode name and trim null terminators
#     name = name.decode('utf-8').rstrip('\x00')

#     return {
#         'name': name
#     }


# def unpack_send_file_payload(payload):
#     # Define the format for SendFilePayload: contentSize (uint32_t), originalFileSize (uint32_t),
#     # packetNumber (uint16_t), totalPackets (uint16_t), fileName (255-byte string), messageContent (remaining bytes)
    
#     # Assuming fileName is fixed at 255 bytes
#     fileName_size = FILE_NAME_SIZE
#     payload_format = f'LLHH{fileName_size}s'
    
#     contentSize, originalFileSize, packetNumber, totalPackets, fileName = struct.unpack(payload_format, payload[:struct.calcsize(payload_format)])
    
#     # Decode fileName and trim null terminators
#     fileName = fileName.decode('utf-8').rstrip('\x00')
    
#     # The remaining part of the data is the message content
#     messageContent = payload[struct.calcsize(payload_format):]
    
#     return {
#         'contentSize': contentSize,
#         'originalFileSize': originalFileSize,
#         'packetNumber': packetNumber,
#         'totalPackets': totalPackets,
#         'fileName': fileName,
#         'messageContent': messageContent
#     }



# def unpack_checksum_correct_payload(payload):
#     # Assuming the name is a fixed-size string of 255 bytes
#     name_size = NAME_SIZE
#     payload_format = f'{name_size}s'

#     name, = struct.unpack(payload_format, payload[:struct.calcsize(payload_format)])

#     # Decode name and trim null terminators
#     name = name.decode('utf-8').rstrip('\x00')

#     return {
#         'name': name
#     }


# def unpack_checksum_failed_payload(payload):
#     # Assuming the name is a fixed-size string of 255 bytes
#     name_size = NAME_SIZE
#     payload_format = f'{name_size}s'

#     name, = struct.unpack(payload_format, payload[:struct.calcsize(payload_format)])

#     # Decode name and trim null terminators
#     name = name.decode('utf-8').rstrip('\x00')

#     return {
#         'name': name
#     }


# def unpack_checksum_shutdown_payload(payload):
#     # Assuming the name is a fixed-size string of 255 bytes
#     name_size = NAME_SIZE
#     payload_format = f'{name_size}s'

#     name, = struct.unpack(payload_format, payload[:struct.calcsize(payload_format)])

#     # Decode name and trim null terminators
#     name = name.decode('utf-8').rstrip('\x00')

#     return {
#         'name': name
#     }


# def unpack_packet(packet):
#     # First, unpack the header
#     header = unpack_header(packet)
    
#     # The payload starts right after the header, calculate the offset
#     header_size = struct.calcsize(f'{255}sBHL')
#     payload_data = packet[header_size:]  # Extract the payload data based on header size
    
#     # Determine the packet type using the code from the header
#     if header['code'] == RequestCode.REGISTER.value:
#         payload = unpack_register_payload(payload_data)
#     elif header['code'] == RequestCode.SEND_RSA_PUBLIC_KEY.value:
#         payload = unpack_send_key_payload(payload_data)
#     elif header['code'] == RequestCode.LOGIN.value:
#         payload = unpack_login_payload(payload_data)
#     elif header['code'] == RequestCode.SEND_FILE.value:
#         payload = unpack_send_file_payload(payload_data)
#     elif header['code'] == RequestCode.CRC_OK.value:
#         payload = unpack_checksum_correct_payload(payload_data)
#     elif header['code'] == RequestCode.CRC_FAIL_TRY_AGAIN.value:
#         payload = unpack_checksum_failed_payload(payload_data)
#     elif header['code'] == RequestCode.CRC_FAIL_SHUT_DOWN.value:
#         payload = unpack_checksum_shutdown_payload(payload_data)
#     else:
#         raise ValueError(f"Unknown request code: {header['code']}")
    
#     return {
#         'header': header,
#         'payload': payload
#     }

