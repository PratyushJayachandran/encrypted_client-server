import socket
import argparse
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 8654  # The port used by the server

def generate_secret_key_for_AES_cipher(AES_key_length):
    # AES key length can be either 16, 24, or 32 bytes long
    secret_key = get_random_bytes(AES_key_length)
    return secret_key

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
    parser = argparse.ArgumentParser(description = "client")
    parser.add_argument('host',type=str,help = "Host Name in xxx.xxx.xxx.xxx format")
    parser.add_argument('port',type=int,help = "Port Number")
    parser.add_argument('public_key',type=argparse.FileType('r', encoding='UTF-8'),help = "public.txt")
    args = parser.parse_args()
    HOST = args.host
    PORT = args.port
    pu_key = RSA.import_key(args.public_key.read())

    # Generate Private Key for session
    secret_key = generate_secret_key_for_AES_cipher(32)
    cipher = PKCS1_OAEP.new(key=pu_key)
    #Encrypting the message with the PKCS1_OAEP object
    cipher_text = cipher.encrypt(secret_key)
    
    # Start up client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((HOST, PORT))
        client.send(cipher_text)   # Send the secret key
    except socket.error as err:
        print(str(err))

    # Send messages infinite loop
    while True:
        message_str = input('>')
        message = bytes(chr(len(message_str)), 'UTF-8')
        message += message_str.encode()
        encrypted_message = encrypt_message(message, secret_key)    # encrypt session messages
        client.send(encrypted_message)
        if message_str.lower() == "quit":
            break
        else:
            encrypted_response = client.recv(1024)
            decrypted_response = decrypt_message(encrypted_response, secret_key)    # decrypt session messages
            print(decrypted_response.decode('utf-8'))
            continue

    client.close()