# import AES from Encryption Module

import sys
import os
# sys.path.append(os.path.relpath("./Encryption"))
import AES
import RSA







# Bob is the rcvr
# Alice is the sender

# Alices public key, private key
def provide_key_pair(k,user_name):
    pubk, prk = RSA.get_key_pair(k)

    # make a directory for Alice
    
    try:
        os.mkdir(user_name)
    except OSError:
        print("%s Already exists!" % user_name)
    
    # write pubk to a txt file in the directory
    with open(str(user_name)+"/public_key.txt", "w") as f:
        f.write(str(pubk))
    
    # write prk to a txt file in the directory
    with open(str(user_name)+"/private_key.txt", "w") as f:
        f.write(str(prk))

def chunk_msg(msg):
    # chunk the message
    msg_chunks = []
    for i in range(0, len(msg), 16):
        msg_chunks.append(msg[i:i+16])
    return msg_chunks

def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

k = 32
alice_public_key, alice_private_key = RSA.get_key_pair(k)

# Bobs public key, private key
bob_public_key, bob_private_key = RSA.get_key_pair(k)


def encrypt_msg(message, key):
    # encryption
    
    cipher = AES.AES_encryption(key, message)
    # print("msg encryption done")
    
    return cipher

def encrypt_msg_(message, key):
    # encryption

    ms = message.encode('utf-8')

    mpd = pad(ms)
    # print("after padding: ", mpd)
    chunks = chunk_msg(mpd)
    ciphers = []
    for chunk in chunks:
        ciphers.append(AES.AES_encryption(key, chunk.decode('utf-8')))
   
    # print("msg encryption done")
    
    return ciphers


"""here Key is the key to encrypt the msg using  AES encryption"""
"""that is encrypted by Bobs public key using RSA"""
"""Bob is the receiver"""

def encrypt_key(key_for_msg_decryption):
    # encryption

    cipher = RSA.RSA_encrypt(key_for_msg_decryption, bob_public_key)
    
    # print("key encryption done")

    # print("ciphered key: ", cipher)
    # a list of integers
    return cipher

def encrypt_key_(key_for_msg_decryption, pubk):
    # encryption
    
    key_for_msg_decryption = key_for_msg_decryption[:16]


    cipher = RSA.RSA_encrypt(key_for_msg_decryption, pubk)
    
    # print("key encryption done")

    # print("ciphered key: ", cipher)
    # a list of integers
    return cipher

"""key to decrypt the msg using AES decryption"""
"""needed to be decrypted first"""

def decrypt_key(ciphered_key, n):
    # decryption
    key = RSA.RSA_decrypt(ciphered_key, bob_private_key,n)
    # print("key decryption done")
    # print("key: ", key)
    return key

def decrypt_key_(ciphered_key,private_key,n):
    # decryption
    key = RSA.RSA_decrypt(ciphered_key, private_key,n)
    # print("key decryption done")
    # print("key: ", key)
    return key

"""msg is plain text and Key is plain text"""
"""done using AES encryption"""
"""key needs to be decrypted using Bobs private key"""

def decrypt_msg(cipher, key):
    
    # decryption
    print("\ndecrypting msg.......................\n")
    text = AES.AES_decryption(key, cipher)
    print("msg decryption done!")
    return text

def decrypt_msg_(ciphers, key):
    
    # decryption

    print("\ndecrypting msg.......................\n")
    text = []
    for cipher in ciphers:
        text += (AES.AES_decryption(key, cipher))
    # text = AES.AES_decryption(key, cipher)
    print("msg decryption done!")
    text = ''.join(text)
    text = unpad(text.encode('utf-8')).decode('utf-8')
    return text



def dem():

    # not multiple of 16 characters
    message = "Two One Nine Two. Two jkhask"
    

    

    key = "Thats my Kung Fu"

    # print(chunk_msg(message))

    ciphers = encrypt_msg_(message, key)
    ciphered_key = encrypt_key(key)


    

    # decryption of the key
    d_key  = decrypt_key(ciphered_key, bob_public_key.get("n"))
    print(d_key)

    msg = decrypt_msg_(ciphers, d_key)
    
    print(msg)


    
    

def demo():
    # take input from user
    # message = input("Enter the message: ")
    # key = input("Enter the key: ")
    message = "Two One Nine TwoTwo One Nine Two fkj sjf"
    message1 = "Two One Nine Two. Two One Nine Two. fkj sjf"
    ms = message1.encode('utf-8')
    mpd = pad(ms)
    print("after padding: ", mpd)

    umpd  = unpad(mpd)
    print("after unpadding: ", umpd)

    # print(mpd)
    
    chunks = chunk_msg(mpd)
    print("chunks: ", chunks)
    print("chunk[0]: ", chunks[2].decode('utf-8'), end="")
    



    key = "Thats my Kung Fu"

    # print(chunk_msg(message))

    # encryption
    cipher_msg = encrypt_msg(chunks[0].decode('utf-8'), key)
    cipher_msg2 = encrypt_msg(chunks[1].decode('utf-8'), key)
    cipher_msg3 = encrypt_msg(chunks[2].decode('utf-8'), key)
    ciphered_key = encrypt_key(key)

    

    # decryption of the key
    d_key  = decrypt_key(ciphered_key, bob_public_key.get("n"))
    print(cipher_msg)

    d_msg = decrypt_msg(cipher_msg, d_key)
    d_msg2 = decrypt_msg(cipher_msg2, d_key)
    d_msg3 = decrypt_msg(cipher_msg3, d_key)

    
    

    # print("d_msg: ", d_msg)
    print("d_msg3: ", d_msg3)
    print("d_msg: ", d_msg+d_msg2+d_msg3)

# show bobs key pair
# print("Bob's public key: ", bob_public_key)
# print("Bob's private key: ", bob_private_key)

# dem()