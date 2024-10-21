import enum
import struct
from abc import ABC, abstractmethod


CLIENT_ID_SIZE = 16
NAME_SIZE = 255
KEY_SIZE = 160


class RequestCode(enum.Enum):
    REGISTER = 825
    SEND_RSA_PUBLIC_KEY = 826
    LOGIN = 827
    SEND_FILE = 828

    CRC_OK = 900
    CRC_FAIL_TRY_AGAIN = 901
    CRC_FAIL_SHUT_DOWN = 902


class RequestHeader:
    def __init__(self, client_id, code, payload_size, version):
        self._client_id = client_id
        self._code = code
        self._payload_size = payload_size
        self._version = version

    @staticmethod
    def deserialize_header(data: bytes):
        client_id = data[:CLIENT_ID_SIZE].decode('utf-8').strip('\x00')
        version, = struct.unpack('<B', data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + 1])
        code, = struct.unpack('<H', data[CLIENT_ID_SIZE + 1:CLIENT_ID_SIZE + 3])
        payload_size, = struct.unpack('<I', data[CLIENT_ID_SIZE + 3:CLIENT_ID_SIZE + 7])

        return RequestHeader(client_id, code, payload_size, version)


# class Packet:
#     def __init__(self, header, payload):
#         self._header = header
#         self._payload = payload

#     @staticmethod
#     def deserialize(data: bytes):
#         # Deserialize header (NAME_SIZE + 7 bytes)
#         header = Header.deserialize_header(data[:NAME_SIZE + 7])
        
#         # Deserialize payload based on code
#         payload_data = data[NAME_SIZE + 7:]
#         payload = PayloadFactory.deserialize_payload(header.code, payload_data)

#         return Packet(header, payload)


class RequestPayload(ABC):
    @abstractmethod
    def deserialize_payload(data: bytes):
        pass


class RegisterPayload(RequestPayload):
    def __init__(self, name):
        self._name = name

    @staticmethod
    def deserialize_payload(data: bytes):
        name = data[:NAME_SIZE].decode('utf-8').strip('\x00')
        return RegisterPayload(name)


class SendKeyPayload(RequestPayload):
    def __init__(self, name, public_key):
        self._name = name
        self._public_key = public_key

    @staticmethod
    def deserialize_payload(data: bytes):
        name = data[:NAME_SIZE].decode('utf-8').strip('\x00')
        public_key = data[NAME_SIZE:NAME_SIZE + KEY_SIZE].decode('utf-8').strip('\x00')
        return SendKeyPayload(name, public_key)


class LoginPayload(RequestPayload):
    def __init__(self, name):
        self._name = name

    @staticmethod
    def deserialize_payload(data: bytes):
        name = data[:NAME_SIZE].decode('utf-8').strip('\x00')
        return LoginPayload(name)


class SendFilePayload(RequestPayload):
    def __init__(self, content_size, original_file_size, packet_number, total_packets, file_name, message_content):
        self._content_size = content_size
        self._original_file_size = original_file_size
        self._packet_number = packet_number
        self._total_packets = total_packets
        self._file_name = file_name
        self._message_content = message_content

    @staticmethod
    def deserialize_payload(data: bytes):
        content_size, = struct.unpack('>I', data[:4])
        original_file_size, = struct.unpack('>I', data[4:8])
        packet_number, = struct.unpack('>H', data[8:10])
        total_packets, = struct.unpack('>H', data[10:12])
        file_name = data[12:12 + NAME_SIZE].decode('utf-8').strip('\x00')
        message_content = data[12 + NAME_SIZE:].decode('utf-8').strip('\x00')
        return SendFilePayload(content_size, original_file_size, packet_number, total_packets, file_name, message_content)


class ChecksumCorrectPayload(RequestPayload):
    def __init__(self, name):
        self._name = name

    @staticmethod
    def deserialize_payload(data: bytes):
        name = data[:NAME_SIZE].decode('utf-8').strip('\x00')
        return ChecksumCorrectPayload(name)


class ChecksumFailedPayload(RequestPayload):
    def __init__(self, name):
        self.name = name

    @staticmethod
    def deserialize_payload(data: bytes):
        name = data[:NAME_SIZE].decode('utf-8').strip('\x00')
        return ChecksumFailedPayload(name)


class ChecksumShutDownPayload(RequestPayload):
    def __init__(self, name):
        self.name = name

    @staticmethod
    def deserialize_payload(data: bytes):
        name = data[:NAME_SIZE].decode('utf-8').strip('\x00')
        return ChecksumShutDownPayload(name)


class RequestPayloadFactory:
    @staticmethod
    def deserialize_payload(code, data):
        if code == RequestCode.REGISTER.value:  # Registration packet code
            return RegisterPayload.deserialize_payload(data)
        elif code == RequestCode.SEND_RSA_PUBLIC_KEY.value:  # Send key packet code
            return SendKeyPayload.deserialize_payload(data)
        elif code == RequestCode.LOGIN.value:  # Login packet code
            return LoginPayload.deserialize_payload(data)
        elif code == RequestCode.SEND_FILE.value:  # Send file packet code
            return SendFilePayload.deserialize_payload(data)
        elif code == RequestCode.CRC_OK.value:  # Checksum correct packet code
            return ChecksumCorrectPayload.deserialize_payload(data)
        elif code == RequestCode.CRC_FAIL_TRY_AGAIN.value:  # Checksum failed packet code
            return ChecksumFailedPayload.deserialize_payload(data)
        elif code == RequestCode.CRC_FAIL_SHUT_DOWN.value:  # Checksum shutdown packet code
            return ChecksumShutDownPayload.deserialize_payload(data)
        else:
            raise ValueError(f"Unknown payload type code: {code}")

