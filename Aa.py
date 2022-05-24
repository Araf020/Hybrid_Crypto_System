
# implement AES using bitvector
import BitVector

def convert_to_matrix(key):
    
    key_bytes = key.encode('utf-8')
    key_bytes = list(key_bytes)

    key_text = [chr(i) for i in key_bytes]
    # key_bitvector = BitVector.BitVector(textstring=key_bytes)

    # print it
    # for i in range(len(key_bitvector)):
    #     print(key_bitvector[i], end="")


    key_matrix_1 = [key_text[i:i+4] for i in range(0, len(key_text), 4)]
    print("Key in text: ", key_matrix_1)



    # convert it to a matrix representation in column major order
    key_matrix_2 = [list(i) for i in zip(*key_matrix_1)]
    print("Key matrix: ", key_matrix_2)

    # convert each element of key_matrix_2 to bitvector
    key_matrix_3 = []
    for i in range(4):
        row = []
        for j in range(4):
            row.append(BitVector.BitVector(textstring = (key_matrix_2[i][j])))
        key_matrix_3.append(row)

    return key_matrix_3


def print_matrix(matrix):
    for i in range(4):
        for j in range(4):
            print(matrix[i][j].get_bitvector_in_hex(), end=" ")
        print()
        
    print()

# v = BitVector.BitVector(textstring = "this is a test")
# v.get_bitvector_in_hex()
# take a 128 bit key from user
key = input("Enter a 16 character Key: ")
# handle if the key is not 128 bit
if len(key) > 128//8:
    print("Key is not 128 bit")

    # take the first 16 bytes = 128 bits of the key
    key = key[:16]
elif len(key) < 128//8:
    print("Key is less than 128 bit")
    # take the first 16 bytes = 128 bits of the key
    # exit the program
    exit()
msg = input("Enter a message: ")
# handle if the message is not 128 bit
if len(msg) > 128//8:
    print("Message is not 128 bit")
    # take the first 16 bytes = 128 bits of the message
    msg = msg[:16]

elif len(msg) < 128//8:
    print("Message is less than 128 bit")
    
    # exit the program
    exit()


        

# get a bit vector matrix representation of the key
key_matrix = convert_to_matrix(key)

# get a bit vector matrix representation of the message
msg_matrix  =  convert_to_matrix(msg)
print()

print_matrix(key_matrix)
print_matrix(msg_matrix)





    