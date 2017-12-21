# -*- coding: utf-8 -*-
"""
FileDecryptMAC script
Created on Wed Nov 22 00:58:54 2017

@author: Francisco Fierro and Daniel Wang
"""

import encryptipy as enpy
import os
import json
import base64

# retrieve current directory files
files = os.listdir(os.curdir)
# check for private key
if "RSA_PrivateKey" not in files:
    print("keys not found.")
else:
    RSA_private_key_path = "RSA_PrivateKey"
    print (files)
    
    for f in files:
        # keep track of filename and extension
        filename, ext = os.path.splitext(f)
        # encrypted files should be in json format
        if (ext == ".json"):
            print(f)
            with open(f, 'r') as json_file:
                #print (json.load(json_file))
                jsondata = json.load(json_file)
            # grab json data
            if type(jsondata) is dict:
                RSA_cipher = base64.b64decode(jsondata.get('RSA_cipher').encode())
                ciphertext = base64.b64decode(jsondata.get('ciphertext').encode())
                iv = base64.b64decode(jsondata.get('iv').encode())
                tag = base64.b64decode(jsondata.get('tag').encode())
                file_extension = jsondata.get('file_extension')
            # decrypt with json data if json data is complete
            if (RSA_cipher != None and ciphertext != None and iv != None and tag != None and file_extension != None):
                enpy.MyRSADecrypt(filename, RSA_cipher, ciphertext, iv, tag, file_extension, RSA_private_key_path)
                # delete json file
                os.remove(f)