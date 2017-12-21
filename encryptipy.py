# -*- coding: utf-8 -*-
"""
Encryption and Decryption methods
Created on Thu Oct 26 14:11:51 2017

@authors: Francisco Fierro and Daniel Wang
"""

import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.asymmetric import rsa

# check for matching tag, then decrypt and unpad message
def MydecryptMAC(ciphertext, tag, EncKey, HMACKey, iv):
	if len(EncKey) < 32:
		print("Encryption key is not 32 bytes")
		return -1

	if len(iv) < 16:
		print("IV is not 16 bytes")
		return -1

    # calculate tag of cipher
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(ciphertext)
	new_tag = h.finalize()

    # check integrity with tag matching
    # proceed with decryption if tags match
	if(tag == new_tag):
		print("tags match!")
		backend = default_backend()
        # prepare decryptor with AES key
		cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend)
		decryptor = cipher.decryptor()
		unpadder = padding.PKCS7(128).unpadder()

        # decrypt, then unpad message
		padded_message= decryptor.update(ciphertext) + decryptor.finalize()
		byte_message = unpadder.update(padded_message) + unpadder.finalize()

		return byte_message
	else:
		print("Tags do not match!!!")

# encrypts the message using AES in CBC mode and MAC it using SHA-256
# returns the ciphertext, the iv for CBC, and the tag from HMAC
def MyencryptMAC(message, EncKey, HMACKey):
	if len(EncKey) < 32:
		return -1

    #initialization vector for CBC block cipher
	iv = os.urandom(16)

	backend = default_backend()
    # prepare encryption
	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	padder = padding.PKCS7(128).padder()

	if(type(message) == str):
		encoded_message = message.encode("utf-8")
	else:
		encoded_message = message
        
    # add padding to message
	padded_message = padder.update(encoded_message) + padder.finalize()
    # encrypt message
	ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    # hash message
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(ciphertext)
    # calculat tag for hashed ciphertext
	tag = h.finalize()

	return ciphertext, iv, tag

# generates random strings from AES and HMAC keys
# returns the result of MyencryptMAC and key generation
def MyfileEncryptMAC(filepath):
    # generate random string using entropy from OS
    EncKey = os.urandom(32)
    HMACKey = os.urandom(128)
    
    # read file using appropriate method basedd on file extension
    filename, file_extension = os.path.splitext(filepath)
    if(file_extension == ".txt"):
        file = open(filepath, "r")
    else:
        file = open(filepath, "rb")
    message = file.read()
    
    # encrypt and hash message
    ciphertext, iv, tag = MyencryptMAC(message, EncKey, HMACKey)

    return ciphertext, iv, tag, EncKey, HMACKey, file_extension

# write the decrypted file data
def MyfileDecryptMAC(filepath, Enckey, HMACKey, ciphertext, iv, tag, file_extension):
    # decrypt file and reattach file extension
    file_data = MydecryptMAC(ciphertext, tag, Enckey, HMACKey, iv)
    filename = filepath + file_extension
    
    if(file_extension != ".txt"):
        file = open(filename, "wb")
    else:
        file = open(filename, "w")
        file_data = file_data.decode("utf-8")
    # write file
    file.write(file_data)

# using the generated RSA key, encrypt AES and HMAC keys
def MyRSAEncrypt(filepath, RSA_publickey_filepath):
	ciphertext, iv, tag, EncKey, HMACKey, file_extension = MyfileEncryptMAC(filepath)

	with open(RSA_publickey_filepath, "rb") as key_file:
		public_key = serialization.load_pem_public_key(
				key_file.read(),
				backend=default_backend())

    # concatenate both AES and HMAC keys
	keys = EncKey + HMACKey

    # encrypt both keys with OAEP padding
	RSACipher = public_key.encrypt(
		keys,
		apadding.OAEP(
			mgf=apadding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None	))

	return RSACipher, ciphertext, iv, tag, file_extension

# retrieve AES and HMAC keys using the RSA private key
# use the retrieved keys to decrypt the ciphertext
def MyRSADecrypt(filepath, RSACipher, ciphertext, iv, tag, file_extension, RSA_privatekey_filepath):

	# load the RSA private key
	with open(RSA_privatekey_filepath, "rb") as key_file:
		private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=None,
				backend=default_backend())
	# use the RSA private key to retrieve AES and HMAC keys
	keys = private_key.decrypt(
			RSACipher,
			apadding.OAEP(
					mgf=apadding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None	))
    # split the concatenated keys
	EncKey = keys[0:32]
	HMACKey = keys[32:]

	# decrypt and write the file with decrypted AES and HMAC keys
	MyfileDecryptMAC(filepath, EncKey, HMACKey, ciphertext, iv, tag, file_extension)

# writes RSA public key and associated RSA private key files
def genRSAkeys():
    # generate RSA private key using 65537 as 'e'
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()	)
    # serialize generated RSA private key
    pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

    file = open("RSA_PrivateKey", "wb")
    file.write(pem)

    #generate associated public key
    public_key = private_key.public_key()
    # serialize public key
    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,)

    file = open("RSA_PublicKey", "wb")
    file.write(pem)

# checks for a public and private key
# generates them if keys are not found
def checkRSAKeys():
    private_key_name = "RSA_PrivateKey"
    public_key_name = "RSA_PublicKey"
    # checks list of files in current directory
    files = os.listdir(os.curdir)
    keys_present = [False, False]

    for f in files:
        if(f == private_key_name):
            print("found RSA private key")
            keys_present[0] = True
        if(f == public_key_name):
            print("found RSA public key")
            keys_present[1] = True

    if(keys_present[0] and keys_present[1]):
        print("RSA keys are present. No need to generate")
        return True
    else:
        print("RSA key(s) missing. Generating keys...")
        return False
