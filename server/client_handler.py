import socket 
from database_management import ClientDBManager, CLIENT_DB, FileDBManager, FILE_DB
import threading 
import uuid
import crypto.rsa
import crypto.aes
import crypto.checksum
import os

from protocol.requests import RequestCode, RequestHeader, RequestPayload, RegisterPayload, SendKeyPayload, LoginPayload, \
    SendFilePayload, ChecksumCorrectPayload, ChecksumFailedPayload, ChecksumShutDownPayload, RequestPayloadFactory

from protocol.responses import ResponseCode, ResponseHeader, ResponsePayload, RegisterOkPayload, RegisterFailPayload, \
    AESSendKeyPayload, FileOkPayload, MessageOkPayload, LoginOkSendAesPayload, LoginFailPayload, \
    GeneralErrorPayload, Packet


CLIENT_HEADER_SIZE = 23
CLIENT_ID_SIZE = 16
CLIENT_VERSION = 3
SERVER_VERSION = 3
NAME_SIZE = 255

class ClientHandler:
    def __init__(self, client_socket : socket.socket, client_db_manager : ClientDBManager, file_db_manager : FileDBManager, files_path) -> None:
        self._client_socket = client_socket
        self._client_db_manager = client_db_manager
        self._file_db_manager = file_db_manager
        self._files_path = files_path

        self._db_lock = threading.Lock()
        self._client_name = ""
        self._file_name = ""
        self._client_id = b""
        self._public_key = b""
        self._aes_key = b""

    def handle(self) -> str:
        try:
            header_data = self._client_socket.recv(CLIENT_HEADER_SIZE)
            if not header_data:
                return "disconnect"
            
            header = RequestHeader.deserialize_header(header_data)
            print(f"Received header code: {header._code}, payload size: {header._payload_size}")
            payload_data = self._client_socket.recv(header._payload_size)
            
            payload = RequestPayloadFactory.deserialize_payload(header._code, payload_data)
            if not payload_data and header._payload_size > 0:
                return "disconnect"

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
            return "continue"
        
        except Exception as e:
            print(f"Error in client handler: {e}")
            return "error"
    
    def handle_registration(self, request_header : RequestHeader, request_payload : RegisterPayload):
        print(f"Attempting to register {request_payload._name}:")
        with self._db_lock:
            client_exists = self._client_db_manager.client_exists_by_name(request_payload._name) 
        
        if (client_exists):
            print(f"Client {request_payload._name} already exists. Registration failed.")
            try:
                response_payload = RegisterFailPayload()
                response_header = ResponseHeader(version=SERVER_VERSION, response_code=ResponseCode.REGISTER_FAIL, payload_size=0)
                response_packet = Packet(response_header, response_payload)
                self._client_socket.send(response_packet.serialize())        

            except Exception as e:
                print(f"Exception raised in sending failed registration attempt: {e}")
                self.send_general_error()

        else:
            self._client_name = request_payload._name
            self._client_id = uuid.uuid4().bytes
            print(f"Generated client ID (printed in hex) to send to client: {self._client_id.hex()}")
            with self._db_lock:
                try:
                    self._client_db_manager.create_client_table()
                    self._client_db_manager.add_or_update_client(self._client_id, self._client_name, self._public_key, self._aes_key)
                except Exception as e:
                    print(f"Exception raised trying to add client to database: {e}")
                    self.send_general_error()
                    return
            
            try:
                print("Registration OK. Client updated.")
                response_payload = RegisterOkPayload(self._client_id)
                response_header = ResponseHeader(SERVER_VERSION, ResponseCode.REGISTER_OK, CLIENT_ID_SIZE)
                response_packet = Packet(response_header, response_payload)
                self._client_socket.send(response_packet.serialize())
                return
            except Exception as e:
                print(f"Exception raised in creation/sending response packet: {e}")
                self.send_general_error()


    def handle_key_send(self, request_header : RequestHeader, request_payload : SendKeyPayload):
        print("Setting public key from client payload.")
        self._public_key = request_payload._public_key
        print("Generating AES key.")
        self._aes_key = crypto.aes.generate_key()
        with self._db_lock:
            try: 
                print("Updating database with keys")
                self._client_db_manager.update_client_aes_key(self._client_id, self._public_key)
                self._client_db_manager.update_client_public_key(self._client_id, self._public_key)
            except Exception as e:
                print(f"Exception raised in handle_key_send database update: {e}")
                self.send_general_error()
                return

        try:
            print("Sending AES key to user.")
            encrypted_aes = crypto.rsa.encrypt(self._aes_key, self._public_key)
            response_payload = AESSendKeyPayload(self._client_id, encrypted_aes)
            response_header = ResponseHeader(SERVER_VERSION, ResponseCode.AES_SEND_KEY, CLIENT_ID_SIZE + len(encrypted_aes))
            response_packet = Packet(response_header, response_payload)
            self._client_socket.send(response_packet.serialize())
        except Exception as e:
            print(f"Exception raised in creating and encrypting aes key: {e}")
            self.send_general_error()


    def handle_login(self, request_header : RequestHeader, request_payload : LoginPayload):
        print(f"Logging in. \nChecking that client by name {request_payload._name} exists:")
        self._client_id = request_header._client_id
        with self._db_lock:
            client_exists = self._client_db_manager.client_exists_by_name(request_payload._name) 

        if (client_exists):
            print("Client does exists. Attempting to retreive information from database:")
            with self._db_lock:
                client_data = self._client_db_manager.get_client(self._client_id)
                try: 
                    self._client_id, self._client_name, self._public_key, last_seen, self._aes_key = client_data
                    print(f"Data received from database.")
                
                except Exception as e:
                    print(f"Data could not be loaded from database: {e}")
                    self.send_general_error()
                    return
            
                self._aes_key = crypto.aes.generate_key()
                self._client_db_manager.update_client_aes_key(self._client_id, self._aes_key)
            
            try:
                encrypted_aes = crypto.rsa.encrypt(self._aes_key, self._public_key)
                response_payload = LoginOkSendAesPayload(self._client_id, encrypted_aes)
                response_header = ResponseHeader(SERVER_VERSION, ResponseCode.LOGIN_OK_SEND_AES, CLIENT_ID_SIZE + len(encrypted_aes))
                response_packet = Packet(response_header, response_payload)
                self._client_socket.send(response_packet.serialize())
            except Exception as e:
                print(f"Login failed: {e}")
                self.send_login_failed()

        else:
            print(f"Login failed: client does not exist in database.")
            self.send_login_failed()
    

    def send_login_failed(self):
        response_payload = LoginFailPayload(self._client_id)
        response_header = ResponseHeader(SERVER_VERSION, ResponseCode.LOGIN_FAIL.value, CLIENT_ID_SIZE)
        response_packet = Packet(response_header, response_payload)
        self._client_socket.send(response_packet.serialize())                


    def handle_file_send(self, header: RequestHeader, payload: SendFilePayload):
        try:
            # Step 1: Create/Open the directory for the client
            client_dir = os.path.join(self._files_path, self._client_id.hex())
            os.makedirs(client_dir, exist_ok=True)  # Create the directory if it doesn't exist

            # make sure that the file name is only the actual name of the file, not a path
            sanitized_file_name = os.path.basename(payload._file_name)
            self._file_name = sanitized_file_name
            file_path = os.path.join(client_dir, self._file_name)
            while True:
                with self._db_lock:
                    print(f"Client ID: {self._client_id.hex()}, file name: {self._file_name}")
                    print(f"Check if file {self._file_name} already exists: ")
                    if self._file_db_manager.file_exists(self._client_id, self._file_name):
                        print("File does exist. Overwriting it.")
                        # If it exists, delete the old entry and file
                        
                        self._file_db_manager.delete_file(self._client_id, self._file_name)
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            print(f"Deleted previous file with same name.")
                    else:
                        print(f"{self._file_name} does not exist. Adding it:")

                # Step 3: Open the file for writing (append mode if it already exists)
                with open(file_path, 'ab') as file:  # 'ab' mode to append binary data
                    # Step 4: Write the message content to the file
                    file.write(payload._message_content)  # Write the current packet content

                # Step 5: Check if this is the last packet
                if payload._packet_number == payload._total_packets:
                    print(f"Received all packets for file: {self._file_name}")
                    break 
                    # Step 6: Update the file metadata in the database
                else:
                    print(f"Received packet {payload._packet_number} of {payload._total_packets} for file {self._file_name}.")
                    
            with self._db_lock:
                self._file_db_manager.add_file(self._client_id, payload._file_name, file_path, verified=False)
            print(f"File {payload._file_name} has been successfully saved and added to the database.")
                
            # Step 7: Decrypt the entire file
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            print(f"Decrypting data for: {self._file_name}")
            decrypted_data = crypto.aes.decrypt(encrypted_data, self._aes_key)

            # Step 8: Write the decrypted data back to the file or another file as needed
            print("Writing decrypted data back to file.")
            with open(file_path, 'wb') as file:  # Overwrite the file with decrypted data
                file.write(decrypted_data)

            # Step 9: Calculate checksum
            print("Calculating checksum.")
            checksum_info = crypto.checksum.readfile(file_path)
            checksum_str, content_size_str, filename = checksum_info.split('\t')

            # Convert the values from string to integers
            checksum = int(checksum_str)  # Convert checksum to int
            content_size = len(encrypted_data)  # Convert content size to int
            
            response_payload = FileOkPayload(self._client_id, content_size, self._file_name.ljust(NAME_SIZE, '\0'), checksum)
            response_header = ResponseHeader(SERVER_VERSION, ResponseCode.FILE_OK, CLIENT_ID_SIZE + NAME_SIZE + 4 + 4)
            response_packet = Packet(response_header, response_payload)
            self._client_socket.send(response_packet.serialize())

        except Exception as e:
            print(f"Exception occurred while handling file send: {e}")
            self.send_general_error()


    def handle_checksum_ok(self, header : RequestHeader, payload : ChecksumCorrectPayload):
        print("Checksum was correct - file validated.")
        response_payload = MessageOkPayload(self._client_id)
        response_header = ResponseHeader(SERVER_VERSION, ResponseCode.MESSAGE_OK, CLIENT_ID_SIZE)
        response_packet = Packet(response_header, response_payload)
        self._client_socket.send(response_packet.serialize())
        self._file_db_manager.update_file_verification(self._client_id, self._file_name, 1)
        


    def handle_checksum_fail(self, header : RequestHeader, payload : ChecksumFailedPayload):
        print("Checksum was incorrect - deleting and trying again.")
        client_dir = os.path.join(self._files_path, self._client_id.hex())
        file_path = os.path.join(client_dir, self._file_name)
        
        if self._file_db_manager.file_exists(self._client_id, self._file_name):
            self._file_db_manager.delete_file(self._client_id, self._file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file entry {self._file_name}.")


    def handle_checksum_shutdown(self, header : RequestHeader, payload : ChecksumShutDownPayload):
        print("Checksum was incorrect - deleting and shutting down.")
        client_dir = os.path.join(self._files_path, self._client_id.hex())
        file_path = os.path.join(client_dir, self._file_name)
        
        if self._file_db_manager.file_exists(self._client_id, self._file_name):            
            self._file_db_manager.delete_file(self._client_id, self._file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file entry {self._file_name}.")
        response_payload = MessageOkPayload(self._client_id)
        response_header = ResponseHeader(SERVER_VERSION, ResponseCode.MESSAGE_OK, CLIENT_ID_SIZE)
        response_packet = Packet(response_header, response_payload)
        self._client_socket.send(response_packet.serialize())


    def send_general_error(self):
            response_payload = GeneralErrorPayload()
            response_header = ResponseHeader(SERVER_VERSION, ResponseCode.GENERAL_ERROR.value, 0)
            response_packet = Packet(response_header, response_payload)
            self._client_socket.send(response_packet.serialize()) 