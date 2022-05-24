k = input("enter the key: ")
arr=list(k)
print(arr)

# a=0
# # declare 2d array
rows, cols = (4,4)
 
# method 2a
key = [[0]*cols]*rows
# key = [[0]*4]*4
# key=[][]
i=0

# for j in range(4):
#     for k in range(4):
#         key[j][k] = arr[i]
#         print(j,", ",k,", ", arr[i]," ",key[j][k])
#         i = i + 1
#         # print(i)
# # # for j in range(4):
# # #     for k in range(4):
# # #         print(j,k)
# # #         print(key[k][j])
# print(key)

list_of_lists = []
i=0
for row in range(rows):
    inner_list = []
    for col in range(cols):
        inner_list.append(arr[i])
        i = i+1
    list_of_lists.append(inner_list)

print(list_of_lists)
for j in range(4):
    for k in range(4):
        key[k][j] = list_of_lists[j][k]
print(key)