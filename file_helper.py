from BitVector import *
import AES

convert_base_16_to_10 = lambda x: int(x, 16)



def int_chunk_to_bitvector_matrix(chunk):
    # make a matrix of 4x4 from chunk
    # def bitvector_list2matrix(key):

    # convert the chunk list to a bit vector list
    lst = []
    for i in range(len(chunk)):
        lst.append(BitVector(intVal = chunk[i], size = 8))

    mat = []
    for i in range(4):
        mat.append(lst[i*4:i*4+4])
    
    # make row to column
    print_matrix(mat)
    mat = [list(i) for i in zip(*mat)]
    return mat

def file_chunks_to_int_chunks(chunks):
    # convert this every chunk to a list of int
    chunks = [list(map(int, chunk)) for chunk in chunks]
    
    return chunks


def chunk_msg(msg):
    
    msg_chunks = []
    for i in range(0, len(msg), 16):
        msg_chunks.append(msg[i:i+16])
    

    return msg_chunks

def get_chunks_of_file(imgfile):
    # read byte by byte
    with open(imgfile, 'rb') as f:
        file_bytes = f.read()
    
    # chunk it
    # p_bytes = pad(file_bytes)

    chunks = chunk_msg(file_bytes)
    print("Number of chunks: ", len(chunks))
    return chunks

def print_matrix(matrix):
    for i in range(4):
        for j in range(4):
            print(matrix[i][j].get_bitvector_in_hex(), end=" ")
        print()
        
    print()

def encrypt_file(key, file):

    fchunks =  get_chunks_of_file(file)
    l = len(fchunks)
    print("last of chunks: ", fchunks[l-1])
    print("len of last of chunks: ", len(fchunks[l-1]))
    print("last element of chunks: ", hex(fchunks[l-1][-1]))

    # print(convert_base_16_to_10(hex(fchunks[l-1][-1])))

    fchunks = file_chunks_to_int_chunks(fchunks)
    print("fchunks last: ", fchunks[l-1])

    mat = int_chunk_to_bitvector_matrix(fchunks[l-1])

    # print(mat)
    print_matrix(mat)
    # ch = convert_hex_to_ascii(fchunks[l-1])
    
    # convert this list of chunk to a string
    # chunk1 = ''.join(fchunks[l-1])

    


    ciphers = []

    # for chunk in fchunks:
    #     ciphers.append(AES_encryption(key, chunk))


# convert explicit base 16 to base 10

# encrypt_file("0123456789abcdef", "a.jpeg")

st  = "hi babe"
lst = [1,24,5,5]
# check if a variable is list or string
if isinstance(st, str):
    print("is string")
