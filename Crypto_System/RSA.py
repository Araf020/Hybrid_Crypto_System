# RSA encryption

import prime
import time
# from Crypto.Util import number

 


def phi(p,q):
    return (p-1)*(q-1)

def gcd(a,b):
    if (a < b):
        return gcd(b,a)
    if (a == 0):
        return b
    if (b==0):
        return a
    return gcd(b, a%b)

def find_e(phi_n):
    x=2
    while x<phi_n:
        if(gcd(phi_n, x)==1):
            return x
        else:
            x = x+1

def find_private_key(phi_n,e):
    i = 1
    while True:
        
        if (phi_n * i + 1)%e == 0:
            return (phi_n * i + 1)//e
        i = i+1


def generate_keys(p,q):

    n = p*q

    # calculate euler's totient
    phi_n = phi(p,q)

    # find e
    e = find_e(phi_n)

    
    # e*d = 1 mod phi_n
    # now find d
   
    d = find_private_key(phi_n,e)

    public_key = {"e":e, "n":n}
    private_key = {"e":e, "d":d}

    return public_key, private_key

def get_key_pair(k):
    
    p = prime.generate_nbit_prime(k//2)
    q = prime.generate_nbit_prime(k//2)
    # p = number.getPrime(k//2)
    # p = number.getPrime(k//2)

    public_key, private_key = generate_keys(p,q)

    # print(public_key)
    # print(private_key)

    return public_key, private_key

# RSA encryption method
def RSA_encrypt(m,public_key):
    # m is message
    # read the message character by character
    n =  public_key.get("n")
    e = public_key.get("e")
    cipher = []
    for i in range(len(m)):
        # convert each character to ASCII value
        # and encrypt
        # c = pow(ord(m[i]),e,n)
        cipher.append(pow(ord(m[i]),e,n))
        # cipher.append(hex(c))
    
    return cipher


# RSA decryption method
def RSA_decrypt(cipher, private_key,n):
    
    d = private_key.get("d")
    
    # cipher is cipher text
    # read the cipher character by character
    msg = []
    msg_1=[]
    for i in range(len(cipher)):
        # decrypt each character
        m = pow(cipher[i],d,n)
        msg.append(chr(m))
        msg_1.append(m)
    
    # print("msg1: ",msg_1)
    return ''.join(msg)


def make_report(report,k):
    with open("rsa_report.csv", "w") as f:
        # make it look like a table
        # make the rows
        # 
        # f.write("k,key generation time,encryption time,decryption time\n") 
        f.write("K,")
        for i in k:
            f.write(str(i) + ",")
        f.write("\n")
        
        # make the columns
        f.write("Key-Generation,")
        for i in k:
            f.write(str(report[i]['key_gen']) + ",")
        f.write("\n")
        f.write("Encryption,")
        for i in k:
            f.write(str(report[i]['encrypt']) + ",")
        f.write("\n")
        f.write("Decryption,")
        for i in k:
            f.write(str(report[i]['decrypt']) + ",")
        f.write("\n")
        f.write("\n")
        f.write("\n")
    
    



def demo():
    """INPUTS"""

    """Number of bits"""
    k =  [16,32,64,128]
    print("for k: ",k)


    """OUTPUTS"""


   
    message = input("Enter the message: ")

    report = {16:{'key_gen':0,'encrypt':0,'decrypt':0},32:{'key_gen':0,'encrypt':0,'decrypt':0},64:{'key_gen':0,'encrypt':0,'decrypt':0},128:{'key_gen':0,'encrypt':0,'decrypt':0}}

    """Let the encryption begin"""
    for bits in k:

    # measureing the time taken to generate the key pair
        print("For k: ", bits)

        start_time = time.time()
        public_key, private_key = get_key_pair(bits)
        key_gen_time = time.time() - start_time

        # convert it to microseconds
        report[bits]['key_gen'] = (key_gen_time * 1000000).__round__(4)

        # measureing the time taken to encrypt the message
        start_time = time.time()
        cipher = RSA_encrypt(message, public_key)
        encryption_time = time.time() - start_time
        # convert it to microseconds
        report[bits]['encrypt'] = (encryption_time * 1000000).__round__(4)
        


        print("Encrypted message: ", cipher)

        # decryption

        # measureing the time taken to decrypt the message
        start_time = time.time()
        text = RSA_decrypt(cipher, private_key,public_key.get("n"))
        decryption_time = time.time() - start_time

        # convert it to microseconds and round it to 4 decimal places

        report[bits]['decrypt'] = (decryption_time * 1000000).__round__(4)


        cipher = ''.join(hex(e) for e in cipher)

        print("Encrypted message in hex: ", cipher)
        print("original message: ", message)
        print("Decrypted message: ", text)
    
    print("Report: ",report)
    # write the report to a file 
    make_report(report,k)



# demo()


    




    
    

    



    



# get_key_pair("hi",k, iterations)



# print(generate_prime(bits=k/2,iterations=iterations))
# print(generate_prime(bits=k/2,iterations=iterations))
 



