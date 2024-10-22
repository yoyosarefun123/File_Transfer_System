from client_handler import ClientHandler
import socket
import threading
from database_management import ClientDBManager, FileDBManager, CLIENT_DB, FILE_DB

SERVER_HOST = '127.0.0.1'  # Localhost
SERVER_PORT = 12345        # Arbitrary non-privileged port
MAX_CONNECTIONS = 5

class ThreadedServer:
    def __init__(self, host, port):
        self.server_host = host
        self.server_port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_db_manager = ClientDBManager(CLIENT_DB)  # Initialize the Client DB Manager
        self.file_db_manager = FileDBManager(FILE_DB)  # Initialize the File DB Manager
        self.files_path = './files/'  # Directory to store files

    def start_server(self):
        # Bind the server to the address and start listening for connections
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(MAX_CONNECTIONS)
        print(f"Server listening on {self.server_host}:{self.server_port}")

        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                print(f"Connection established with {client_address}")
                # Create a new thread for each client
                client_handler = ClientHandler(client_socket, self.client_db_manager, self.file_db_manager, self.files_path)
                client_thread = threading.Thread(target=self.handle_client, args=(client_handler,))
                client_thread.start()
            except KeyboardInterrupt:
                print("Server is shutting down...")
                self.server_socket.close()
                break

    def handle_client(self, client_handler):
        try:
            while True:
                # Call the handle method repeat'edly to process client packets
                result = client_handler.handle()
                print(f"client handling result: {result}")

                # Check if the client has closed the connection (e.g., by sending an empty message or a special signal)
                if result is None or result != "continue":  
                    print("Client disconnected")
                    break
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_handler._client_socket.close()  # Close the client's socket after handling
            print("Client connection closed")

if __name__ == '__main__':
    server = ThreadedServer(SERVER_HOST, SERVER_PORT)
    server.start_server()
