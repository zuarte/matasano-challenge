import random, string
from utils import MyAES


def randomword(length):
    return ''.join(random.choice(string.printable) for i in range(length))


def is_aes_mode_ecb(ciphertext_bytes):
    found = False
    for i in range(len(ciphertext_bytes) // MyAES.block_size - 1):
        for j in range(i, len(ciphertext_bytes) // MyAES.block_size - 2):
            if ciphertext_bytes[(i * MyAES.block_size):((i + 1) * MyAES.block_size)] == ciphertext_bytes[((j + 1) * MyAES.block_size):((j + 2) * MyAES.block_size)]:
                found = True
                break
        if found:
            break
    if found:
        print("Oracle: ECB detected")
    else:
        print("Oracle: CBC detected")
    return found


def random_aes_mode_encryption(plaintext_bytes):
    key = random.getrandbits(MyAES.block_size * 8).to_bytes(MyAES.block_size, byteorder="big")
    saltedtext_bytes = randomword(random.randint(5, 10)).encode("utf-8") + plaintext_bytes + randomword(random.randint(5, 10)).encode("utf-8")
    coin = random.randint(0, 1)
    if coin == 0:
        # encrypt with ECB
        print("Real: ECB encrypted")
        return MyAES.new(key, MyAES.MODE_ECB, None).raw_encrypt(MyAES.pkcs7_pad(saltedtext_bytes))
    else:
        # encrypt with CBC
        print("Real: CBC encrypted")
        iv = random.getrandbits(MyAES.block_size * 8).to_bytes(MyAES.block_size, byteorder="big")
        return MyAES.new(key, MyAES.MODE_CBC, iv).raw_encrypt(MyAES.pkcs7_pad(saltedtext_bytes))


if __name__ == '__main__':
    plaintext_bytes = bytes("A" * 128, encoding="utf-8")
    for i in range(100):
        is_aes_mode_ecb(random_aes_mode_encryption(plaintext_bytes))
        print()
