# implemenatation of AES
import time
from unittest import result
from BitVector import *
import key_expansion

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]

InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

# for g_function
Rcon = (
        0x00, 0x01, 0x02,
		0x04, 0x08, 0x10, 
		0x20, 0x40, 0x80, 
		0x1b, 0x36
       )

report = {'scheduling':0, 'encrypt':0, 'decrypt':0}

def add_round_key(state, round_key):
     
     for i in range(4):
         for j in range(4):
             state[i][j] = state[i][j] ^ round_key[i][j]

    
def substitute_bytes(state):
    for i in range(4):
        for j in range(4):
            sb=Sbox[state[i][j].int_val()]
            # print("sub for ", state[i][j].get_bitvector_in_hex(), " is ", hex(sb))
            state[i][j] = BitVector(intVal=sb, size = 8)  


def inv_substitute_bytes(state):
    for i in range(4):
        for j in range(4):
            sb=InvSbox[state[i][j].int_val()]
            # print("sub for ", state[i][j].get_bitvector_in_hex(), " is ", hex(sb))
            state[i][j] = BitVector(intVal=sb, size = 8) 


def shift_single_row_left_1(row):
    
    row[0], row[1], row[2], row[3] = row[1], row[2], row[3], row[0]


def shift_single_row_left_2(row):
    
    shift_single_row_left_1(row)
    shift_single_row_left_1(row)

def shift_single_row_left_3(row):

    shift_single_row_left_2(row)
    shift_single_row_left_1(row)

def shift_single_row_right_1(row):
    
    row[0], row[1], row[2], row[3] = row[3], row[0], row[1], row[2]

def shift_single_row_right_2(row):
    
    shift_single_row_right_1(row)
    shift_single_row_right_1(row)

def shift_single_row_right_3(row):

    shift_single_row_right_2(row)
    shift_single_row_right_1(row)


def shift_rows(state):

    result=[]
   
    shift_single_row_left_1(state[1])
    shift_single_row_left_2(state[2])
    shift_single_row_left_3(state[3])

    result = [state[0], state[1], state[2], state[3]]

    return result


def inv_shift_rows(state):

    result=[]
   
    shift_single_row_right_1(state[1])
    shift_single_row_right_2(state[2])
    shift_single_row_right_3(state[3])

    result = [state[0], state[1], state[2], state[3]]

    return result




def mix_columns(state):

    AES_modulus = BitVector(bitstring='100011011')
    result_mat = [
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)]
    ]

    for i in range(4):
        for j in range(4):
            for k in range(4):
          
                mul = state[k][j].gf_multiply_modular(Mixer[i][k], AES_modulus, 8)
                result_mat[i][j] ^= mul
               
    return result_mat


   

def inv_mix_columns(state):
    AES_modulus = BitVector(bitstring='100011011')
    result_mat = [
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
        [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)]
    ]

    for i in range(4):
        for j in range(4):
            for k in range(4):
          
                mul = state[k][j].gf_multiply_modular(InvMixer[i][k], AES_modulus, 8)
                result_mat[i][j] ^= mul
               
    return result_mat

def print_list(lst):
    for i in range(len(lst)):
        print(lst[i].get_bitvector_in_hex(), end=" ")
        
    print()

def print_matrix(matrix):
    for i in range(4):
        for j in range(4):
            print(matrix[i][j].get_bitvector_in_hex(), end=" ")
        print()
        
    print()

def list_to_matrix(lst):
    result = [[0 for x in range(4)] for y in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = lst[i*4+j]
    
    # make column to row
    result = [list(i) for i in zip(*result)]
    return result

def list_to_bitvector_matrix(lst):
    result = [[0 for x in range(4)] for y in range(4)]
    for i in range(4):
        for j in range(4):
            result[i][j] = BitVector(hexstring=lst[i*4+j])
    
    # make column to row
    result = [list(i) for i in zip(*result)]
    return result

def matrix_to_bitvector_list(matrix):
    
    # make row to column
    matrix = [list(i) for i in zip(*matrix)]
    result = []
    for i in range(4):
        for j in range(4):
            result.append(matrix[i][j])
    
    return result

def bitvector_matrix_to_text(matrix):
    
    # make row to column
    matrix = [list(i) for i in zip(*matrix)]
    result = []
    for i in range(4):
        for j in range(4):
            # bitvector to text
            result.append(matrix[i][j].get_bitvector_in_ascii())
            # result.append(matrix[i][j])
    
    # make the result to text
    result = ''.join(result)
    return result



def matrix_to_list(matrix):
    
    # make row to column
    matrix = [list(i) for i in zip(*matrix)]
    result = []
    for i in range(4):
        for j in range(4):
            result.append(matrix[i][j].get_bitvector_in_hex())
    
    return result

def bitvector_list2matrix(lst):
    word_list = []
    for i in range(4):
        word_list.append(lst[i*4:i*4+4])
    
    return word_list

def demo(message, key):

    # read 16 bytes from the message
    message_in_bytes = message.encode('utf-8')
    message_in_bytes = message_in_bytes[:16]

    key_in_bytes = key.encode('utf-8')
    key_in_bytes = key_in_bytes[:16]
    key_in_bytes = list(key_in_bytes)

    # make every byte a bitvector
    key_in_bitvectors = [BitVector(intVal=byte, size=8) for byte in key_in_bytes]
    print_list(key_in_bitvectors)

    print("key in bytes: ", key_in_bytes)

    print("Message in bytes: ", message_in_bytes)
    # make it a array of bytes
    message_in_bytes = list(message_in_bytes)
    msg_in_bitvectors = [BitVector(intVal=byte, size=8) for byte in message_in_bytes]
    print("Message in bitvectors: ")
    print_list(msg_in_bitvectors)

    m_mat = bitvector_list2matrix(msg_in_bitvectors)
    print("Message in matrix: ")
    print_matrix(m_mat)

    # make row to column
    m_mat = [list(i) for i in zip(*m_mat)]

    print("Message in column matrix: ")
    print_matrix(m_mat)

    key_mat = bitvector_list2matrix(key_in_bitvectors)
    print("Key in matrix: ")
    print_matrix(key_mat)

    # make row to column
    key_mat = [list(i) for i in zip(*key_mat)]
    print("Key in column matrix: ")
    print_matrix(key_mat)


    # add round key
    add_round_key(m_mat, key_mat)

    # print m_mat
    print("After add round key: ")
    print_matrix(m_mat)

    # substitute bytes
    substitute_bytes(m_mat)

    # print m_mat
    print("After substitute bytes: ")
    print_matrix(m_mat)

    m_mat = shift_rows(m_mat)

    print("After shift rows: ")
    print_matrix(m_mat)


    m_mat=mix_columns(m_mat)

    print("After mix columns: ")
    print_matrix(m_mat)

    key_mat=key_expansion.get_the_round_key(key_mat,1)
    print("round key")
    print_matrix(key_mat)

    print("After add round key: ")
    add_round_key(m_mat, key_mat)
    print_matrix(m_mat)





def str_to_bitevector_matrix(text):
    text_in_bytes = text.encode('utf-8')
    text_in_bytes = text_in_bytes[:16]
    text_in_bytes = list(text_in_bytes)
    text_in_bitvectors = [BitVector(intVal=byte, size=8) for byte in text_in_bytes]
    text_in_matrix = bitvector_list2matrix(text_in_bitvectors)

    text_in_matrix = [list(i) for i in zip(*text_in_matrix)]
    
    
    return text_in_matrix



def get_list_of_roundKeys(key):
    
    # key_mat = str_to_bitevector_matrix(key)
    key_mat = str_to_bitevector_matrix(key)
    round_keys = []
    round_keys.append(key_mat)

    for round in range(1,11):
        key_mat = key_expansion.get_the_round_key(key_mat,round)
        round_keys.append(key_mat)
    return round_keys




def AES_encryption(key, message):

    # in column order 
    # key_mat = str_to_bitevector_matrix(key)
    m_mat = str_to_bitevector_matrix(message)

    # measure time for generating round keys
    start_time = time.time()
    round_keys = get_list_of_roundKeys(key)
    # convert time to microseconds
    key_time = (time.time() - start_time) * 1000
    report["scheduling"] = key_time.__round__(2)


    # print("Message in column matrix: ")
    # print_matrix(m_mat)

    # print("Key in column matrix: ")
    # print_matrix(key_mat)

    
    """measure encryption time"""
    start_time = time.time()



    '''============ First round ============='''

    # add round key
    add_round_key(m_mat, round_keys[0])

    # print m_mat
    # print("After add round key: ")
    # key_expansion.print_matrix(m_mat)

    """================9 More Rounds======================"""
    for round in range(1,10):

        # substitute bytes
        substitute_bytes(m_mat)

        # print m_mat
        # print("After substitute bytes: ")
        # print_matrix(m_mat)

        m_mat = shift_rows(m_mat)

        # print("After shift rows: ")
        # print_matrix(m_mat)


        m_mat=mix_columns(m_mat)

        # print("After mix columns: ")
        # print_matrix(m_mat)

        # key_mat=key_expansion.get_the_round_key(key_mat,round)
        
        # print("round key")
        # print_matrix(key_mat)

        # print("After add round key: ")
        # add_round_key(m_mat, key_mat)
        add_round_key(m_mat, round_keys[round])
        # print("AES output after Round : ", round)
        # print_matrix(m_mat)
        # print_matrix(m_mat)
    
    # final round
    substitute_bytes(m_mat)
    m_mat=shift_rows(m_mat)
    # key_mat=key_expansion.get_the_round_key(key_mat,10)
    
    # add_round_key(m_mat, key_mat)
    add_round_key(m_mat, round_keys[10])

    encrypt_time = (time.time() - start_time) * 1000 #miliseconds
    report["encrypt"] = encrypt_time.__round__(2)



    # print("AES output after Round : ", 10)
    # print_matrix(m_mat)

    return matrix_to_list(m_mat)



def AES_decryption(key, ciphertext):

    # print("AES decryption")
    # in column order
    cipher_mat = list_to_bitvector_matrix(ciphertext)
  

    round_keys = get_list_of_roundKeys(key)


    start_time = time.time()
   

    
    # print("Key in column matrix: ")
    # print_matrix(key_mat)
    # print("Cipher in column matrix: ")
    # print_matrix(cipher_mat)

    '''============ decryptionFirst round ============='''

    # add round key
    add_round_key(cipher_mat, round_keys[10])
    # print("After add round key: ")
    # print_matrix(cipher_mat)

    # inv shift rows
    cipher_mat = inv_shift_rows(cipher_mat)
    # print("After inv shift rows: ")
    # print_matrix(cipher_mat)

    # inv substitute bytes
    inv_substitute_bytes(cipher_mat)

    # print("After inv substitute bytes: ")
    # print_matrix(cipher_mat)

    for i in range(9,0,-1):
        # add round key
        # print("Round: ", i)
        # print("round key: ")
        # print_matrix(round_keys[i])

        add_round_key(cipher_mat, round_keys[i])
        # print("After add round key: ")
        # print_matrix(cipher_mat)

        """Inv mix columns"""
        cipher_mat = inv_mix_columns(cipher_mat)

        # inv shift rows
        cipher_mat = inv_shift_rows(cipher_mat)
        # print("After inv shift rows: ")
        # print_matrix(cipher_mat)

        # inv substitute bytes
        inv_substitute_bytes(cipher_mat)

        # print("After Round: ", i, "AES decryption: ")
        # print_matrix(cipher_mat)
        
        # return original message
    
    # final round
    add_round_key(cipher_mat, round_keys[0])

    decrypt_time = (time.time() - start_time) * 1000 #miliseconds
    report["decrypt"] = decrypt_time.__round__(2)

    # print("AES decryption: ")
    # print_matrix(cipher_mat)
    return bitvector_matrix_to_text(cipher_mat)


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

def chunk_msg(msg):
    
    msg_chunks = []
    for i in range(0, len(msg), 16):
        msg_chunks.append(msg[i:i+16])
    return msg_chunks


def encrypt_file(key, filename):
    # convert it to bytes
    # file could be in any encoding
    with open(filename, 'rb') as f:
        plaintext = f.read()
    # print("Original message: ", plaintext)
    # pad it to a multiple of 16 bytes
    plaintext = pad(plaintext)
    # print("Padded message: ", plaintext)
    # encrypt it
    ciphers = encrypt_msg_not_multiple_16bytes(plaintext, key)
    file = decrypt_msg_not_multiple_16bytes(ciphers, key)

    


    



def encrypt_msg_not_multiple_16bytes(msg,key):

    msg_p = pad(msg.encode('utf-8'))
    
    chunks = chunk_msg(msg_p)
    ciphers = []
    for chunk in chunks:
        ciphers.append(AES_encryption(key, chunk.decode('utf-8')))
    
    return ciphers


def decrypt_msg_not_multiple_16bytes(ciphers,dkey):
    print("\ndecrypting msg.......................\n")
    text = []
    for cipher in ciphers:
        text += (AES_decryption(dkey, cipher))
    # text = AES.AES_decryption(key, cipher)
    # print("msg decryption done!")
    text = ''.join(text)
    text = unpad(text.encode('utf-8')).decode('utf-8')
    return text

def convert_hex_to_ascii(list_hex):
    # convert hex string to integer
    # list_int = [int(i, 16) for i in list_hex]
    ascii_v = [chr(int(i,16)) for i in list_hex]
    ascii_v = ''.join(ascii_v)
    return ascii_v



def convert_ascii_to_hex(text):
    text = list(text)
    text = [hex(ord(i)) for i in text]
    text = [i[2:] for i in text]
    # text = [i.upper() for i in text]
    text = [i.zfill(2) for i in text]
    text = ''.join(text)
    return text


def encryptDemo(key, message):

    print("\n*******************************************************************")
    print("**************************** AES ENCRYPTION STARTED ***************************")
    print("*******************************************************************")

    print("Message: ", message)
    print("Message [hex]: ", convert_ascii_to_hex(message))
    print()
    
    if len(key) > 16:
        key = key[:16]
        print("key is too long. Truncated to 16 character long")
    elif len(key) < 16:
        print("key is too short! exiting..")
        print()
        
        exit()
        
        

    print("Key: ", key)
    print("Key [hex]: ", convert_ascii_to_hex(key))
    print()


    """""Encryption"""

    
    if len(message) == 16:
        cipher_text = AES_encryption(key, message)
        cipher_string = ''.join(map(lambda x: x, cipher_text))
        print("Cipher text[hex]: ", cipher_string)
        # print in ascii
        print("Cipher text[ascii]: ", convert_hex_to_ascii(cipher_text))
        print()

        print()
        # print("**********************************************\n*********************************************\n")

        # decrypt
        """Decryption"""
        msg = AES_decryption(key, cipher_text)
        print("Deciphered message [hex]: ", convert_ascii_to_hex(msg))
        print("Deciphered message [ascii]: ", msg)
    
    else:
        ciphers = encrypt_msg_not_multiple_16bytes(message, key)
        text = decrypt_msg_not_multiple_16bytes(ciphers,key)
        print("decryption done!")
        print("Deciphered message [ascii]: ", text)

    print()
    print("**********************************************\n*********************************************\n")

    print("Execution time: \nKey scheduling: ", report["scheduling"], " miliseconds")
    print("Encryption: ",report["encrypt"], " miliseconds")
    print("Decryption: ",report["decrypt"], " miliseconds")
    print()

    


# # take msg input
msg = input("Enter message: ")
# take key input
key = input("Enter key: ")

# encryptDemo("BUET CSE17 Batch", "CanTheyDotheirFest")
encryptDemo(key,msg)

# encrypt_file("BUET CSE17 Batch",'a.jpeg')


















