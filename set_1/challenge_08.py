import binascii
from utils import MyAES


def main():

    ciphertexts = []
    with open("data/8.txt", "r") as file:
        for index, line in enumerate(file.readlines()):
            ciphertexts.append((index, line.strip("\n")))
            
    for i in range(len(ciphertexts)):
        line = binascii.unhexlify(ciphertexts[i][1])
        for k in range((len(line) // MyAES.block_size) - 1):
            block = line[(k * MyAES.block_size):((k + 1) * MyAES.block_size)]
            for j in range(i, len(ciphertexts)):
                new_line = binascii.unhexlify(ciphertexts[j][1])
                for z in range(k, (len(new_line) // MyAES.block_size) - 2):
                    new_block = new_line[((z + 1) * MyAES.block_size):((z + 2) * MyAES.block_size)]
                    if block == new_block:
                        print("Line: " + str(i) + "- Block: " + str(k) + ":")
                        print(block)
                        print("Line: " + str(j) + "- Block: " + str(z + 1) + ":")
                        print(new_block)

if __name__ == '__main__':
    main()