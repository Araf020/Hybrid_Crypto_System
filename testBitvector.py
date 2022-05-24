# Demo on Bitvector
 
from BitVector import *

# a dummy 4x4 matrix
mat = [[BitVector(intVal=2, size=8), BitVector(intVal=4, size=8), BitVector(intVal=7, size=8), BitVector(intVal=0, size=8)],
         [BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
            [BitVector(intVal=6, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)],
                [BitVector(intVal=0, size=8), BitVector(intVal=5, size=8), BitVector(intVal=0, size=8), BitVector(intVal=0, size=8)]]


# print the matrix
print("The matrix:")
for i in range(4):
    for j in range(4):
        print(mat[i][j], end=' ')
    print()



