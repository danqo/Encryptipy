# -*- coding: utf-8 -*-
"""
FileEncryptMAC script
Created on Tue Nov 21 21:20:55 2017

@author: Francisco Fierro and Daniel Wang
"""

import encryptipy as enpy
import os
import json
import base64

# generate keys if they don't exist
if(enpy.checkRSAKeys() == False):
    enpy.genRSAkeys()

RSA_public_key_path = "RSA_PublicKey"
RSA_private_key_path = "RSA_PrivateKey"

#retrieve current directory files
files = os.listdir(os.curdir)
print (files)

for f in files:
    # don't encrypt keys, encryption methods, decryptor script, encryptor script, or directories
    # name the executable FileEncryptMAC
    if (f != RSA_public_key_path and f!= RSA_private_key_path and f != "encryptipy.py" and f != "encrdir.py" and f != "decrdir.py" and os.path.isfile(f)):
        print (f)
        # encrypted filename with json extension
        filename = os.path.splitext(f)[0] + ".json"
        # encrypt file
        RSA_cipher, ciphertext, iv, tag, file_extension = enpy.MyRSAEncrypt(f, RSA_public_key_path)
        # put json data in a dictionary
        jsondata = {"RSA_cipher" : base64.b64encode(RSA_cipher).decode(),
                    "ciphertext" : base64.b64encode(ciphertext).decode(),
                    "iv" : base64.b64encode(iv).decode(),
                    "tag" : base64.b64encode(tag).decode(),
                    "file_extension" : file_extension}
        # write json file
        with open(filename, 'w') as jsonfile:
            json.dump(jsondata, jsonfile)
        # delete original file
        os.remove(f)
        print (filename)
        