import sqlite3
from datetime import datetime

# Database filenames
CLIENT_DB = 'client_database.db'
FILE_DB = 'file_database.db'

class ClientDBManager:
    def __init__(self, db_path=CLIENT_DB):
        self.db_path = db_path
        self.create_client_table()

    def create_client_table(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY, 
                    client_name TEXT, 
                    public_key TEXT, 
                    last_seen TIMESTAMP, 
                    aes_key BLOB
                )
            ''')
            conn.commit()

    def client_exists_by_name(self, client_name):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM clients WHERE client_name = ?', (client_name,))
            result = cursor.fetchone()
            return result is not None

    def add_or_update_client(self, client_id, client_name, public_key, aes_key):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO clients (client_id, client_name, public_key, last_seen, aes_key)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(client_id) 
                DO UPDATE SET 
                    client_name=excluded.client_name, 
                    public_key=excluded.public_key, 
                    last_seen=excluded.last_seen, 
                    aes_key=excluded.aes_key;
            ''', (client_id, client_name, public_key, datetime.now(), aes_key))
            conn.commit()

    def update_client_last_seen(self, client_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE clients
                SET last_seen = ?
                WHERE client_id = ?;
            ''', (datetime.now(), client_id))
            conn.commit()

    def update_client_public_key(self, client_id, public_key):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE clients
                SET public_key = ?
                WHERE client_id = ?;
            ''', (public_key, client_id))
            conn.commit()

    def update_client_aes_key(self, client_id, aes_key):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE clients
                SET aes_key = ?
                WHERE client_id = ?;
            ''', (aes_key, client_id))
            conn.commit()

    def get_client(self, client_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM clients WHERE client_id = ?', (client_id,))
            return cursor.fetchone()


class FileDBManager:
    def __init__(self, db_path=FILE_DB):
        self.db_path = db_path
        self.create_file_table()

    def create_file_table(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    client_id TEXT, 
                    file_name TEXT, 
                    path_name TEXT, 
                    verified INTEGER, 
                    PRIMARY KEY (client_id, file_name)
                )
            ''')
            conn.commit()

    def add_file(self, client_id, file_name, path_name, verified=False):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO files (client_id, file_name, path_name, verified)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(client_id, file_name)
                DO UPDATE SET
                    path_name=excluded.path_name,
                    verified=excluded.verified;
            ''', (client_id, file_name, path_name, int(verified)))
            conn.commit()

    def update_file_verification(self, client_id, file_name, verified):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE files
                SET verified = ?
                WHERE client_id = ? AND file_name = ?;
            ''', (int(verified), client_id, file_name))
            conn.commit()

    def get_files_by_client(self, client_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files WHERE client_id = ?', (client_id,))
            return cursor.fetchall()


# Usage example (optional)
if __name__ == '__main__':
    client_manager = ClientDBManager()
    file_manager = FileDBManager()
    
    # Create tables (done in the constructor)
    # client_manager.create_client_table()
    # file_manager.create_file_table()

    # Add or update client
    client_manager.add_or_update_client('client123', 'John Doe', 'public_key_data', b'aes_key_data')

    # Add a file
    file_manager.add_file('client123', 'file1.txt', '/path/to/file', verified=True)

    # Get client and file info
    client = client_manager.get_client('client123')
    files = file_manager.get_files_by_client('client123')
    
    print("Client Info:", client)
    print("Files:", files)
