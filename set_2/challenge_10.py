import base64
from utils import MyAES


def main():
    key = b"YELLOW SUBMARINE"
    b64_encoded = ""

    with open("data/10.txt", "r") as file:
        for line in file.readlines():
            b64_encoded += line.strip("\n")

    ciphertext = base64.b64decode(b64_encoded)
    plaintext = MyAES.new(key, MyAES.MODE_CBC, bytes(MyAES.block_size)).raw_decrypt(ciphertext)
    print(plaintext.decode("utf-8"))


if __name__ == '__main__':
    main()