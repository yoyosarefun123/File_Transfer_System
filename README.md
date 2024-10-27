# File Transfer System
This project essentially implements a simple file transfer protocol for educational purposes. 

The client for the project is built in cpp, and the server is built in python.

It supports sending a file from the client to the server in a (relatively) secure fashion. NEVER use this protocol for actually sending important files since it is purposefully weak, in an attempt to help students develop security research skills.

## Overview of the protocol
The general flow of the protocol is as such:
1. The user (manually) creates a file named `transfer.info` and then runs the client code. This file will be of the following format:
```
<ip>:<port>
<client username>
<path to the file client wants to send>
```
2. The file is loaded and a connection is created with the server.
3. The client now checks if there are existing me.info and priv.key files. These files are created after the first registration.
4. If those files do not exist, register the new client and exchange RSA keys - then create these files. Their format is:
```
me.info:
<client username>
<client ID in hex>
<client private RSA key in base64>

priv.key:
<client private RSA key in base64>
```
5. Otherwise, if they do exist, login using the information saved in them.
6. Calculate CRC and send the file to the server.
7. Server calculates CRC as well, they confirm it's correct and the client disconnects.

## A bit more in depth about the protocol itself
### Client side
General client request:
| Request | Field     | Size | Meaning |
| --------| ----------| -----| --------|
| Header  | Client ID |16 bytes | uuid for the client |
| | Version | 1 byte | Version number of client |
| | Code | 2 bytes | Request code|
| | Payload size | 4 bytes | Size of the payload |
| Content | payload | dynamic | Content of the request |

#### List of client request payloads
825 - Registration 
| Field | Size | Meaning |
| --- | --- | --- |
| Name | 255 bytes | null terminated username | 

826 - Sending RSA key
| Field | Size | Meaning |
| --- | --- | --- |
| Name | 255 bytes | null terminated username | 
| Public Key | 160 bytes | RSA public key (including metadata) |

827 - Login
| Field | Size | Meaning |
| --- | --- | --- |
| Name | 255 bytes | null terminated username | 

828 - Send file
| Field | Size | Meaning |
| --- | --- | --- |
| Content size | 4 bytes | size of the data chunk sent | 
| Orig file size | 4 bytes | size of the original file before encryption |
| Packet number, total packets | 4 bytes | 2 bytes for the current packet number, 2 for the total sent |
| File name | 255 bytes | null terminated name of the file sent |
| Message content | dynamic | file data chunk, encrypted with the AES key sent by the server | 

900 - CRC ok
| Field | Size | Meaning |
| --- | --- | --- |
| Name | 255 bytes | null terminated username | 

901 - CRC not ok, trying again
| Field | Size | Meaning |
| --- | --- | --- |
| Name | 255 bytes | null terminated username | 

902 - CRC not ok, shutting down
| Field | Size | Meaning |
| --- | --- | --- |
| Name | 255 bytes | null terminated username | 

### Server side
General server response:
| Response | Field     | Size | Meaning |
| --------| ----------| -----| --------|
| Header | Version | 1 byte | Version number of client |
| | Code | 2 bytes | Request code|
| | Payload size | 4 bytes | Size of the payload |
| Content | payload | dynamic | Content of the request |

#### List of server response payloads
1600 - Registration OK
| Field | Size | Meaning |
| --- | --- | --- |
| client ID | 16 bytes | uuid for the client |

1601 - Registration failed 

empty payload


1602 - RSA public key accepted, sending AES key
| Field | Size | Meaning |
| --- | --- | --- |
| client ID | 16 bytes | uuid for the client |
| AES key | dynamic | AES key encrypted with public RSA key received from client |

1603 - File accepted, sending CRC 
| Field | Size | Meaning |
| --- | --- | --- |
| client ID | 16 bytes | uuid for the client |
| content size | 4 bytes | size of the file after encryption (for some reason) |
| file name | 255 bytes | null terminated file name of the sent file |
| checksum | 4 bytes | CRC |

1604 - Message OK (used in response to requests 900, 902)
| Field | Size | Meaning |
| --- | --- | --- |
| client ID | 16 bytes | uuid for the client |

1605 - Login ok, sending AES key (same payload as 1602)
 Field | Size | Meaning |
| --- | --- | --- |
| client ID | 16 bytes | uuid for the client |
| AES key | dynamic | AES key encrypted with public RSA key received from client |

1606 - Login not ok
 Field | Size | Meaning |
| --- | --- | --- |
| client ID | 16 bytes | uuid for the client |

1607 - General server error 

empty payload 

