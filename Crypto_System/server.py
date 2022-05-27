import time, socket, sys
import hybrid_system
import pickle
import random
import string

def generate_key_pair(name):

    # k = input("Enter  #bits of prime numbers to be generated[16,32,64,128]: ")
    # k = int(k)
    k=16
    hybrid_system.provide_key_pair(k,name)

def generate_16bit_string():
    
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))

def encrypt_msg(message):
   
    # get the public key of the receiver
    """as we are sending to bob, we need to get his public key"""
    # read it from Bob/public_key.txt
    
    with open("Bob/public_key.txt", "r") as f:
        pubk = f.read()

    # convert it to dictionary
    pubk = eval(pubk)
    
    """"================================================"""
    # encryption_key = input("Enter the encryption key: ")

    encryption_key = generate_16bit_string()
    # encryption_key = "Thats my Kung Fu"
    # message = "Two One Nine Two"

    if(len(encryption_key) < 16):
        print("Encryption key is too short[ should be 16 characters]")
        encryption_key = input("Enter a encryption key: ")

    # if(len(message)>16):
    #     print("Message is too long[ should be 16 characters]")
    #     message = input("Enter a message: ")
    

    msg_ciphers = hybrid_system.encrypt_msg_(message, encryption_key)

    ciphered_key  = hybrid_system.encrypt_key_(encryption_key, pubk)

    # print("msg_cipher: ", msg_cipher)
    # print("ciphered_key: ", ciphered_key)

    return msg_ciphers, ciphered_key



def start_server():
    
    print("Initialising....\n")
    time.sleep(1)

    s = socket.socket()

    host = socket.gethostname()
    ip = socket.gethostbyname(host)
    port = 8085

    s.bind((host, port))
    print(host, "(", ip, ")\n")
    name = "Alice"


    # generate pubk prk
    generate_key_pair(name)

    print("Hey ",name,", ", end=" ")

    s.listen(1)
    print("\nWaiting for incoming connections...\n")
    conn, addr = s.accept()
    print("Received connection from ", addr[0], "(", addr[1], ")\n")

    s_name = conn.recv(1024)
    s_name = s_name.decode()
    print(s_name, "has connected to the chat room\nEnter [e] to exit chat room\n")
    conn.send(name.encode())
    HEADERSIZE=10
    while True:

        message = input(str("Me : "))
        
        msg, key = encrypt_msg(message)

    
        dic = {"msg": msg, "key": key}
        
        if message == "[e]":
            message = "Left chat room!"

            conn.send(message.encode())
            print("\n")
            break

        msg = pickle.dumps(dic)
        msg = bytes(f"{len(msg):<{HEADERSIZE}}", 'utf-8')+msg
        # print(msg)
        conn.send(msg)


        message = conn.recv(1024)
        message = message.decode()
        print(s_name, ":", message)


start_server()
