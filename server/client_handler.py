import socket 
from database_management import ClientDBManager, CLIENT_DB, FileDBManager, FILE_DB
import threading 
import uuid
import crypto.rsa
import crypto.aes
import crypto.checksum

from protocol.requests import RequestCode, RequestHeader, RequestPayload, RegisterPayload, SendKeyPayload, LoginPayload, \
    SendFilePayload, ChecksumCorrectPayload, ChecksumFailedPayload, ChecksumShutDownPayload, RequestPayloadFactory

from protocol.responses import ResponseCode, ResponseHeader, ResponsePayload, RegisterOkPayload, RegisterFailPayload, \
    AESSendKeyPayload, FileOkPayload, MessageOkPayload, LoginOkSendAesPayload, LoginFailPayload, \
    GeneralErrorPayload, Packet


CLIENT_HEADER_SIZE = 23
CLIENT_ID_SIZE = 16
CLIENT_VERSION = 3
SERVER_VERSION = 3


class ClientHandler:
    def __init__(self, client_socket : socket.socket, client_db_manager : ClientDBManager, file_db_manager : FileDBManager, files_path) -> None:
        self._client_socket = client_socket
        self._client_db_manager = client_db_manager
        self._file_db_manager = file_db_manager
        self._files_path = files_path

        self._db_lock = threading.Lock()
        self._client_name = ""
        self._client_id = b""
        self._public_key = b""
        self._aes_key = b""

    def handle(self) -> None:
        header_data = self._client_socket.recv(CLIENT_HEADER_SIZE)
        header = RequestHeader.deserialize_header(header_data)
        payload_data = self._client_socket.recv(header._payload_size)
        payload = RequestPayloadFactory.deserialize_payload(header._code, payload_data)

        if header._code == RequestCode.REGISTER.value:  # Registration packet code
            self.handle_registration(header, payload)
        elif header._code == RequestCode.SEND_RSA_PUBLIC_KEY.value:  # Send key packet code
            self.handle_key_send(header, payload)
        elif header._code == RequestCode.LOGIN.value:  # Login packet code
            self.handle_login(header, payload)
        elif header._code == RequestCode.SEND_FILE.value:  # Send file packet code
            self.handle_file_send(header, payload)
        elif header._code == RequestCode.CRC_OK.value:  # Checksum correct packet code
            self.handle_checksum_ok(header, payload)
        elif header._code == RequestCode.CRC_FAIL_TRY_AGAIN.value:  # Checksum failed packet code
            self.handle_checksum_fail(header, payload)
        elif header._code == RequestCode.CRC_FAIL_SHUT_DOWN.value:  # Checksum shutdown packet code
            self.handle_checksum_shutdown(header, payload)
        else:
            raise ValueError(f"Unknown payload type code: {header._code}")
        
    def handle_registration(self, request_header : RequestHeader, request_payload : RegisterPayload):
        with self._db_lock:
            client_exists = self._client_db_manager.client_exists_by_name(request_payload._name) 
        
        if (client_exists):
            try:
                response_payload = RegisterFailPayload()
                response_header = ResponseHeader(version=SERVER_VERSION, response_code=ResponseCode.REGISTER_FAIL.value, payload_size=0)
                response_packet = Packet(response_header, response_payload)
                self._client_socket.send(response_packet.serialize())        

            except Exception as e:
                print(f"Exception raised in sending failed registration attempt: {e}")
                self.send_general_error()

        else:
            self._client_name = request_payload._name
            self._client_id = uuid.uuid4().bytes
            with self._db_lock:
                try:
                    self._client_db_manager.create_client_table()
                    self._client_db_manager.add_or_update_client(self._client_id, self._client_name, self._public_key, self._aes_key)
                except Exception as e:
                    print(f"Exception raised in handle registration db update: {e}")
                    self.send_general_error()
            
            try:
                response_payload = RegisterOkPayload(self._client_id)
                response_header = ResponseHeader(SERVER_VERSION, ResponseCode.REGISTER_OK.value, CLIENT_ID_SIZE)
                response_packet = Packet(response_header, response_payload)
                self._client_socket.send(response_packet.serialize())
            except Exception as e:
                print(f"Exception raised in creation/sending response packet: {e}")
                self.send_general_error()


    def handle_key_send(self, request_header : RequestHeader, request_payload : SendKeyPayload):
        self._public_key = request_payload._public_key
        self._aes_key = crypto.aes.generate_key()
        with self._db_lock:
            try: 
                self._client_db_manager.update_client_aes_key()
                self._client_db_manager.update_client_public_key(self._public_key)
            except Exception as e:
                print(f"Exception raised in handle_key_send database update: {e}")

        try:
            encrypted_aes = crypto.rsa.encrypt(self._aes_key, self._public_key)
            response_payload = AESSendKeyPayload(self._client_id, encrypted_aes)
            response_header = ResponseHeader(SERVER_VERSION, ResponseCode.AES_SEND_KEY.value, CLIENT_ID_SIZE + len(encrypted_aes))
            response_packet = Packet(response_header, response_payload)
            self._client_socket.send(response_packet.serialize())
        except Exception as e:
            print(f"Exception raised in creating and encrypting aes key: {e}")
            self.send_general_error()


    def handle_login(self, request_header : RequestHeader, request_payload : LoginPayload):
        with self._db_lock:
            client_exists = self._client_db_manager.client_exists_by_name(request_payload._name) 
        
        if (client_exists):
            with self._db_lock:
                self._aes_key = crypto.aes.generate_key()
                self._client_db_manager.update_client_aes_key(self._aes_key)
            
            try:
                encrypted_aes = crypto.rsa.encrypt(self._aes_key, self._public_key)
                response_payload = LoginOkSendAesPayload(self._client_id, encrypted_aes)
                response_header = ResponseHeader(SERVER_VERSION, ResponseCode.LOGIN_OK_SEND_AES.value, CLIENT_ID_SIZE + len(encrypted_aes))
                response_packet = Packet(response_header, response_payload)
                self._client_socket.send(response_packet.serialize())
            except Exception as e:
                print(f"Login failed: {e}")
                self.send_login_failed()

        else:
            print(f"Login failed: {e}")
            self.send_login_failed()
    

    def send_login_failed(self):
        response_payload = LoginFailPayload(self._client_id)
        response_header = ResponseHeader(SERVER_VERSION, ResponseCode.LOGIN_FAIL.value, CLIENT_ID_SIZE)
        response_packet = Packet(response_header, response_payload)
        self._client_socket.send(response_packet.serialize())                


    def handle_file_send(self, header : RequestHeader, payload : RequestPayload):
        pass


    def handle_checksum_ok(self, header : RequestHeader, payload : RequestPayload):
        pass


    def handle_checksum_fail(self, header : RequestHeader, payload : RequestPayload):
        pass


    def handle_checksum_shutdown(self, header : RequestHeader, payload : RequestPayload):
        pass


    def send_general_error(self):
        response_payload = GeneralErrorPayload()
        response_header = ResponseHeader(SERVER_VERSION, ResponseCode.GENERAL_ERROR.value, 0)
        response_packet = Packet(response_header, response_payload)
        self._client_socket.send(response_packet.serialize()) 