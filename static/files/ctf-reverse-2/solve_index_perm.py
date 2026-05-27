flag = ""
encode = "REla{PSF!!fg}!Y_SN_1_0U"
table = [7, 8, 1, 2, 4, 5, 13, 16, 20, 21, 0, 3, 22, 19, 6, 12, 11, 18, 9,
 10, 15, 14, 17]

def enc(input):
    tmp = ""
    for i in range(len(input)):
        tmp += input[table[i]]

    return tmp


if __name__ == "__main__":
    print("Please input your flag:")
    flag = input()
    if len(flag) != 23:
        print("Length Wrong!!")
    else:
        final = enc(flag)
        if final == encode:
            print("Wow,you get the right flag!!")
        else:
            print("Sorry,Your input is Wrong")