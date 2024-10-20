import sqlite3
from datetime import datetime

# Database filenames
CLIENT_DB = 'client_database.db'
FILE_DB = 'file_database.db'

### CLIENT DATABASE FUNCTIONS ###
def create_client_table():
    with sqlite3.connect(CLIENT_DB) as conn:
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

def add_or_update_client(client_id, client_name, public_key, aes_key):
    with sqlite3.connect(CLIENT_DB) as conn:
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

def update_client_last_seen(client_id):
    with sqlite3.connect(CLIENT_DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE clients
            SET last_seen = ?
            WHERE client_id = ?;
        ''', (datetime.now(), client_id))
        conn.commit()

def update_client_public_key(client_id, public_key):
    with sqlite3.connect(CLIENT_DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE clients
            SET public_key = ?
            WHERE client_id = ?;
        ''', (public_key, client_id))
        conn.commit()

def update_client_aes_key(client_id, aes_key):
    with sqlite3.connect(CLIENT_DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE clients
            SET aes_key = ?
            WHERE client_id = ?;
        ''', (aes_key, client_id))
        conn.commit()

### FILE DATABASE FUNCTIONS ###
def create_file_table():
    with sqlite3.connect(FILE_DB) as conn:
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

def add_file(client_id, file_name, path_name, verified=False):
    with sqlite3.connect(FILE_DB) as conn:
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

def update_file_verification(client_id, file_name, verified):
    with sqlite3.connect(FILE_DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE files
            SET verified = ?
            WHERE client_id = ? AND file_name = ?;
        ''', (int(verified), client_id, file_name))
        conn.commit()

### HELPER FUNCTIONS ###
def get_client(client_id):
    with sqlite3.connect(CLIENT_DB) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM clients WHERE client_id = ?', (client_id,))
        return cursor.fetchone()

def get_files_by_client(client_id):
    with sqlite3.connect(FILE_DB) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM files WHERE client_id = ?', (client_id,))
        return cursor.fetchall()

# Create the tables when this script is run
if __name__ == '__main__':
    create_client_table()
    create_file_table()
