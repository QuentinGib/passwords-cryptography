!pip install scrypt
!pip3 install bcrypt
!pip3 install tink

import hashlib
import os
import bcrypt
from tink import daead
from tink import cleartext_keyset_handle
from tink import _keyset_writer
import tink
import scrypt


# This part need to be run only once -------------------------------------------------

# generate secret key
daead.register()
keytemplate = daead.deterministic_aead_key_templates.AES256_SIV
secret_key = tink.new_keyset_handle(keytemplate)
# write the key in a file
keyset = open('keys.txt', 'wb')
cleartext_keyset_handle.write(_keyset_writer.BinaryKeysetWriter(keyset), secret_key)
keyset.close()

# add values to the database
user = "admin"
pwd = "goodpassword"
save_to_database(user, pwd)

#--------------------------------------------------------------------------------------


# main

def hash_password(password, salt):
    hashp = scrypt.hash(password, salt).hex()
    return hashp

def encryption_machine(msg):
    # Register all deterministic AEAD primitives
    daead.register()
    # Get the secret key from the file
    keyset = open('keys.txt', 'rb').read()
    reader = tink.BinaryKeysetReader(keyset)
    secret_key = tink.cleartext_keyset_handle.read(reader)
    associated_data = b'context'
    # Get the primitive
    daead_primitive = secret_key.primitive(daead.DeterministicAead)
    secret_key = daead_primitive
    # Use the primitive.
    cipherText = secret_key.encrypt_deterministically(msg.encode("utf-8"), associated_data)
    return cipherText


def save_to_database(user, password):
    salt = bcrypt.gensalt().hex()
    hashp = hash_password(password, salt)
    encryptMsg = encryption_machine(hashp)
    fichier = open('database.txt', 'a')
    fichier.write(user + ',' + str(encryptMsg.hex()) + ',' + salt + '\n')
    fichier.close()

def check_password(user, pwd):
    salt = ''
    hashpwd = ''
    fichier = open('database.txt', 'r')
    for line in fichier.readlines():
        splitLine = line.split(',')
        if user == splitLine[0]:
            salt = splitLine[2]
            hashpwd = splitLine[1]
    hashp = hash_password(pwd, salt[:-1])
    encryptMsg = encryption_machine(hashp).hex()
    if encryptMsg == hashpwd:
        return True
    return False


username = input("user : ")
passwordd = input("password : ")

while not check_password(username, passwordd):
    print("Wrong, try again")
    username = input("user : ")
    passwordd = input("password : ")

print("Connected !")
