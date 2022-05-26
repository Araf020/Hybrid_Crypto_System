# import AES from Encryption Module

import sys
import os
# sys.path.append(os.path.relpath("./Encryption"))
import AES
import RSA







# Bob is the rcvr
# Alice is the sender

# Alices public key, private key
k = 32
alice_public_key, alice_private_key = RSA.get_key_pair(k)

# Bobs public key, private key
bob_public_key, bob_private_key = RSA.get_key_pair(k)


def encrypt_msg(message, key):
    # encryption
    cipher = AES.AES_encryption(key, message)
    print("msg encryption done")
    
    return cipher


"""here Key is the key to encrypt the msg using  AES encryption"""
"""that is encrypted by Bobs public key using RSA"""
"""Bob is the receiver"""

def encrypt_key(key_for_msg_decryption):
    # encryption

    cipher = RSA.RSA_encrypt(key_for_msg_decryption, bob_public_key)
    
    print("key encryption done")

    print("ciphered key: ", cipher)
    # a list of integers
    return cipher

"""key to decrypt the msg using AES decryption"""
"""needed to be decrypted first"""

def decrypt_key(ciphered_key, n):
    # decryption
    key = RSA.RSA_decrypt(ciphered_key, bob_private_key,n)
    print("key decryption done")
    print("key: ", key)
    return key

"""msg is plain text and Key is plain text"""
"""done using AES encryption"""
"""key needs to be decrypted using Bobs private key"""
def decrypt_msg(cipher, key):
    
    # decryption
    print("\ndecrypting msg.......................\n")
    text = AES.AES_decryption(key, cipher)
    print("msg decryption done")
    return text


def demo():
    # take input from user
    # message = input("Enter the message: ")
    # key = input("Enter the key: ")
    message = "Two One Nine Two"
    key = "Thats my Kung Fu"

    

    

    # encryption
    cipher_msg = encrypt_msg(message, key)
    ciphered_key = encrypt_key(key)

    # decryption of the key
    d_key  = decrypt_key(ciphered_key, bob_public_key.get("n"))
    print(cipher_msg)

    d_msg = decrypt_msg(cipher_msg, d_key)

    print("d_msg: ", d_msg)

# show bobs key pair
print("Bob's public key: ", bob_public_key)
print("Bob's private key: ", bob_private_key)

demo()