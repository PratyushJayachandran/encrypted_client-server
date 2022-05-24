# encrypted_client-server
An TCP client server program in python with assymmetric and symmetric encryption methodologies and database search

A networked client and server application coded in Python which allows a client program to query a simple database which is managed by a server program. A database of NFL games is used as an example in this project. The client program sends a message containing the query about a game to the server and the server program responds back with a message containing the requested information. Communications between the client and server is secured using a hybrid encryption scheme in which asymmetric encryption is used to transmit a session key at the start of a session, and symmetric encryption is used for the remainder of the session.

RSA is used for assymmetric encryption and AES in ECB mode is used for syymmetric encryption.
