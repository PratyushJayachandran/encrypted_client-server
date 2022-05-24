import socket
import csv
import argparse
from _thread import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST = "127.0.0.8"  # Default Host Name
PORT = 8654  # Default port to listen on
 
# Initializing the titles and rows list as global
fields = []
rows = []

global secret_key

def load_database(data_filename):
    global rows
    global fields
    # Reading csv file
    with open(data_filename, 'r') as csvfile:
        # creating a csv reader object
        csvreader = csv.reader(csvfile)
         
        # extracting field names through first row
        fields = next(csvreader)
     
        # extracting each data row one by one
        for row in csvreader:
            rows.append(row)

def find_value(query):
    # default return for corner cases   
    data_found = "unknown"

    # check if the split produced 2 parts
    qr = query.split(" ")
    if len(qr) != 2:
        return data_found

    for index, field in enumerate(fields):
        if field == qr[1]:
            index_found = index
            break

    for row in rows:
        if str(row[1]) == str(qr[0]):
            data_found = row[index_found]

    return data_found

def threaded_client(connection, address):
    while True:
        encrypted_msg = connection.recv(1024)
        in_data = decrypt_message(encrypted_msg, secret_key)
        data = [in_data[0], in_data[1:]]
        if data[1].decode().lower() == "quit":
            print('Connection to ' + address[0] + ':' + str(address[1]) + ' Terminated')
            connection.close()
            break
        else:
            print(data[1].decode())
            reply = find_value(data[1].decode())
            encrypted_reply = encrypt_message(str.encode(reply), secret_key)    # encrypt session messages
            connection.send(encrypted_reply)
            continue

def encrypt_message(private_msg, secret_key):
    # use the secret key to create a AES cipher
    cipher = AES.new(secret_key, AES.MODE_ECB)
    # pad private_msg
    padded_private_msg = pad(private_msg, 16, style='pkcs7')
    # use the cipher to encrypt the padded message
    encrypted_msg = cipher.encrypt(padded_private_msg)  
    # return encrypted message
    return encrypted_msg

def decrypt_message(encrypted_msg, secret_key):
    decipher = AES.new(secret_key, AES.MODE_ECB)
    # use the cipher to decrypt the encrypted message
    padded_decrypted_msg = decipher.decrypt(encrypted_msg)
    decrypted_msg = unpad(padded_decrypted_msg, 16, style='pkcs7')
    # return a decrypted original private message
    return decrypted_msg

if __name__ == "__main__":
    # Handle arguments
    parser = argparse.ArgumentParser(description = "server")
    parser.add_argument('port',type=int,help = "Port Number")
    parser.add_argument('data_file',type=str,help = "data_base.csv")
    parser.add_argument('private_key',type=argparse.FileType('r', encoding='UTF-8'),help = "private.txt")
    args = parser.parse_args()
    PORT = args.port
    data_filename = args.data_file

    # Load the database from csv file
    load_database(data_filename)

    # Load the private key
    pr_key = RSA.import_key(args.private_key.read())

    # Initialize the private key
    decrypt = PKCS1_OAEP.new(key=pr_key)
    
    # Start up the server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_ip = socket.gethostbyname(socket.gethostname())
    try:
        server.bind((local_ip, PORT))
        print(f"Server Started at {local_ip}")
    except socket.error as err:
        print(str(err))
    # Server listens for connections
    server.listen()

    # Receive connections infinitely
    while True:
        global secret_key
        conn, address = server.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        secret_key_encoded = conn.recv(1024)
        decrypted_secret_key = decrypt.decrypt(secret_key_encoded)  # decrypt session messages
        secret_key = decrypted_secret_key
        start_new_thread(threaded_client, (conn, address, ))
    server.close()