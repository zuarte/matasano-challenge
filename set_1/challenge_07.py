import base64
from utils import MyAES

def main():
    oneline = ""
    with open("data/7.txt", "r") as file:
        for line in file.readlines():
            oneline += line.strip("\n")
    ciphertext = base64.b64decode(oneline)
    key = b"YELLOW SUBMARINE"

    plaintext = MyAES.new(key, MyAES.MODE_ECB, None).raw_decrypt(ciphertext)
    print(plaintext.decode("utf-8"))

if __name__ == '__main__':
    main()