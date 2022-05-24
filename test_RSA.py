from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
# from binascii import hexlify#The message to be encrypted

message = b'Public and Private keys encryption'

#Generating private key (RsaKey object) of key length of 1024 bits
private_key = RSA.generate(1024)
#Generating the public key (RsaKey object) from the private key
public_key = private_key.publickey()
# print(type(private_key), type(public_key))#Converting the RsaKey objects to string 
private_str = private_key.export_key().decode()
public_str = public_key.export_key().decode()
# print(type(private_str), type(public_str))#Writing down the private and public keys to 'pem' files
with open('private.txt', 'w') as pr:
    pr.write(private_str)
with open('public.txt', 'w') as pu:
    pu.write(public_str)
    
# #Importing keys from files, converting it into the RsaKey object   
# pr_key = RSA.import_key(open('private.txt', 'r').read())
# pu_key = RSA.import_key(open('public.txt', 'r').read())
# # print(type(pr_key), type(pu_key))#Instantiating PKCS1_OAEP object with the public key for encryption
# cipher = PKCS1_OAEP.new(key=pu_key)
# #Encrypting the message with the PKCS1_OAEP object
# cipher_text = cipher.encrypt(message)
# print(cipher_text)#Instantiating PKCS1_OAEP object with the private key for decryption
# decrypt = PKCS1_OAEP.new(key=pr_key)
# #Decrypting the message with the PKCS1_OAEP object
# decrypted_message = decrypt.decrypt(cipher_text)
# print(decrypted_message)
