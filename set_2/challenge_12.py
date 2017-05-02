from utils import MyAES
from set_2.challenge_11 import is_aes_mode_ecb
import base64

key = bytes("Y3LL0W SuBM4R1N3", encoding="utf-8")
secret = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"


def aes_ecb_with_appended_secret(plaintext_bytes):
    temp = bytearray(plaintext_bytes)
    temp.extend(base64.b64decode(secret))
    cipher = MyAES.new(key, MyAES.MODE_ECB, None)
    return cipher.raw_encrypt(MyAES.pkcs7_pad(temp))


def detect_block_size():
    count = 1
    empty = len(aes_ecb_with_appended_secret(b""))
    while(True):
        string = bytes("A" * count, encoding="utf-8")
        ciph_len = len(aes_ecb_with_appended_secret(string))
        if (ciph_len != empty):
            return (ciph_len - empty, empty)
        count += 1


def find_next_char(input_bytes, secret_bytes, block_size, latest_block):
    plaintext_bytes = input_bytes[1:]
    block_to_find = aes_ecb_with_appended_secret(plaintext_bytes)[(latest_block - 1) * block_size:(latest_block * block_size)]
    for char in range(255):
        temp = bytearray()
        temp.extend(plaintext_bytes)
        temp.extend(secret_bytes)
        temp.append(char)
        guessed_block = aes_ecb_with_appended_secret(temp)[(latest_block - 1) * block_size:(latest_block * block_size)]
        if guessed_block == block_to_find:
            return char
    return None


def main():
    # find block info
    block_info = detect_block_size()
    block_size = block_info[0]
    dummy_blocks = block_info[1] // block_size
    print("block size is: " + str(block_size))
    print(str(dummy_blocks) + " dummy input blocks needed")
    assert is_aes_mode_ecb(aes_ecb_with_appended_secret(bytes("A" * (block_size * 2), encoding="utf-8"))) == True, "Not ECB mode!"
    # create dummy input
    dummy_input = "A" * dummy_blocks * block_size
    secret_bytes = bytearray()
    for i in range(len(dummy_input)):
        next_input = dummy_input[:len(dummy_input) - i]
        next_char = find_next_char(bytes(next_input, encoding="utf-8"), secret_bytes, block_size, dummy_blocks)
        # 0x1 beginning of padding
        if next_char == None or next_char == 0x1:
            break
        secret_bytes.append(next_char)
    print("\nSecret message:\n" + secret_bytes.decode("utf-8"))

if __name__ == '__main__':
    main()