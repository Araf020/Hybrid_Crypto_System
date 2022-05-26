# RSA encryption

from os import getrandom
import random
import prime


# python library to generate prime
# print hello




# generate a number of given bit size
# def generate_number(k):
#     return random.getrandbits(k)

# find modulus of exponent
# It returns (x^y) % p




# def miillerTest(d, n):
     
#     # Pick a random number in [2..n-2]
#     # Corner cases make sure that n > 4
#     a = 2 + random.randint(1, n - 4)
 
#     # Compute a^d % n
#     x = pow(a, d, n)
 
#     if (x == 1 or x == n - 1):
#         return True
 
#     # Keep squaring x while one
#     # of the following doesn't
#     # happen
#     # (i) d does not reach n-1
#     # (ii) (x^2) % n is not 1
#     # (iii) (x^2) % n is not n-1
#     while (d != n - 1):
#         x = (x * x) % n
#         d *= 2
 
#         if (x == 1):
#             return False
#         if (x == n - 1):
#             return True
 
#     # Return composite
#     return False

# def isPrime( n, k):
     
#     # Corner cases
#     if (n <= 1 or n == 4):
#         return False
#     if (n <= 3):
#         return True
 
#     # Find r such that n =
#     # 2^d * r + 1 for some r >= 1
#     d = n - 1
#     while (d % 2 == 0):
#         d //= 2
 
#     # Iterate given number of 'k' times
#     for i in range(k):
#         if (miillerTest(d, n) == False):
#             return False
 
#     return True

# def generate_prime(bits, iterations):
#     prime=None
#     while True:
#         num = generate_number(int(bits))
#         # print(num)
#         if (isPrime(num, iterations)):
#             return num
    


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
    
    print("msg1: ",msg_1)
    return ''.join(msg)



def demo():
    """INPUTS"""

    """Number of bits"""
    k =  128
    print("for k: ",k)


    """ iterations"""
    # iterations = 100
    message = input("Enter the message: ")

    # encryption
    public_key, private_key = get_key_pair(k)

    msg_ascii = []
    for i in range(len(message)):
        msg_ascii.append(ord(message[i]))

    print("msg_ascii: ",msg_ascii)

    cipher = RSA_encrypt(message, public_key)
    print("Encrypted message: ", cipher)

    # decryption
    text = RSA_decrypt(cipher, private_key,public_key.get("n"))


    cipher = ''.join(str(e) for e in cipher)

    print("Encrypted message: ", cipher)
    print("original message: ", message)
    print("Decrypted message: ", text)


# demo()


    




    
    

    



    



# get_key_pair("hi",k, iterations)



# print(generate_prime(bits=k/2,iterations=iterations))
# print(generate_prime(bits=k/2,iterations=iterations))
 



