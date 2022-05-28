import time, socket, sys
import hybrid_system
import pickle

def generate_key_pair(name):

    # k = input("Enter  #bits of prime numbers to be generated[16,32,64,128]: ")
    # k = int(k)
    k=16
    hybrid_system.provide_key_pair(k,name)


def decrypt_encryption_key(cipherd_key ):

    # get my private key
    with open("Dont open this/Bob/private_key.txt", "r") as f:
        privk = f.read()
    # get my public key
    with open("Dont open this/Bob/public_key.txt", "r") as f:
        pubk = f.read()
    
    prk = eval(privk)
    pubk = eval(pubk)

    n = pubk.get("n")
    
    key = hybrid_system.decrypt_key_(cipherd_key, prk, n)
    print("\n*****key decryption done******")
    print("key: ", key, end="\n")
    return key

def decrypt_msg(cipher, enc_key):
    msg = hybrid_system.decrypt_msg_(cipher, enc_key)
    # print(s_name+": ", msg)
    # print()
    return msg

def write_to_file(msg):
    with open("Dont open this/Bob/msg.txt", "w") as f:
        f.write(msg)

def receive_message(s, header_size, s_name):
   
    rcvd_msg =None

    full_msg = b''
    new_msg = True
    while True:
        msg = s.recv(16)
        if new_msg:
            # print("new msg len:",msg[:HEADERSIZE])
            msglen = int(msg[:header_size])
            new_msg = False
        full_msg += msg

        if len(full_msg)-header_size == msglen:
           
            rcvd_msg = pickle.loads(full_msg[header_size:])
            new_msg = True
            full_msg = b""
            break
    
    if rcvd_msg:
        
        """decrypt msg"""
        cipherd_key = rcvd_msg.get("key")
        key = decrypt_encryption_key(cipherd_key)
        msg = decrypt_msg(rcvd_msg.get("msg"), key)

        print(s_name+": ", msg)
        print()
        write_to_file(msg)


def establish_conn(s_name, port):
    
    print("Initialising....\n")
    time.sleep(1)
    s = socket.socket()
    shost = socket.gethostname()
    ip = socket.gethostbyname(shost)
    print(shost, "(", ip, ")\n")
    # host = input(str("Enter server address: "))
    host = "127.0.1.1"
   
    # generate pubk prk
    generate_key_pair(s_name)
    
    print("\nTrying to connect to ", host, "(", port, ")\n")
    time.sleep(1)
    s.connect((host, port))
    print("Connected...\n")
    return s


def start_bob():
    
    name = "Bob"
    port = 8085
    s = establish_conn(name,port)
    
    s.send(name.encode())
    s_name = s.recv(1024)
    s_name = s_name.decode()
    print(s_name, "has joined the chat room\nEnter [e] to exit chat room\n")
    HEADERSIZE=10
    while True:
        
        receive_message(s, HEADERSIZE, s_name)
        
        # send  msg
        message = input(str("Me : "))
        if message == "[e]":
            message = "Left chat room!"
            s.send(message.encode())
            print("\n")
            break

        s.send(message.encode())

# start bob
start_bob()