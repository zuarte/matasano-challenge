from set_2.challenge_12 import key, secret, detect_block_size
from utils import MyAES
import random, base64, string

# max and min length of the random prefix
max_random_length = 12
min_random_length = 4

# bytearray of discovered bytes
discovered_bytes = bytearray()


def random_bytes(length):
    tmp = bytearray(length)
    for i in range(length):
        tmp[i] = random.randint(0, 255)
    return bytes(tmp)


def aes_ecb_random_prefix_appended_secret(plaintext_bytes):
    # create a random prefix
    random_length = random.randint(min_random_length, max_random_length)
    tmp = bytearray()
    tmp.extend(random_bytes(random_length))
    # add plaintext
    tmp.extend(plaintext_bytes)
    # append secret
    tmp.extend(base64.b64decode(secret))
    cipher = MyAES.new(key, MyAES.MODE_ECB, None)
    return cipher.raw_encrypt(MyAES.pkcs7_pad(tmp))

'''
    AAAAAAAA 4
    BBBBBBBB 3 <- returns 3 as index
    BBBBBBBB 2
    BBBBBBBB 1
    ABCDEFAB 0
'''

def same_block(ciphertext_bytes):
    for i in range((len(ciphertext_bytes) // MyAES.block_size - 1), 0, -1):
        if ciphertext_bytes[MyAES.block_size * i:MyAES.block_size * (i + 1)] == ciphertext_bytes[MyAES.block_size * (i - 1):MyAES.block_size * i]:
            return i + 1


wrong_padding_block = None
full_A_block = None


def find_encrypted_blocks():
    global wrong_padding_block, full_A_block
    # find \x10 * 16 padding block
    ciphertext = aes_ecb_random_prefix_appended_secret(bytes("\x01" * MyAES.block_size * max_random_length, encoding="utf-8"))
    index = same_block(ciphertext)
    wrong_padding_block = ciphertext[(index - 1) * MyAES.block_size:index * MyAES.block_size]
    # find "A" * 16 full block
    ciphertext = aes_ecb_random_prefix_appended_secret(bytes("A" * MyAES.block_size * max_random_length, encoding="utf-8"))
    index = same_block(ciphertext)
    full_A_block = ciphertext[(index - 1) * MyAES.block_size:index * MyAES.block_size]


def find_next_char(plaintext_bytes, num_block):
    # discover encrypted blocks
    find_encrypted_blocks()
    fixed_input_bytes = b"\x01" * MyAES.block_size + plaintext_bytes[:len(plaintext_bytes) - 1]
    block_to_find = None
    while(True):
        random_input_bytes = random.randint(0, MyAES.block_size) * b"\x00"
        input_bytes = random_input_bytes + fixed_input_bytes
        ciphertext = aes_ecb_random_prefix_appended_secret(input_bytes)
        r_index = ciphertext.rfind(full_A_block)
        l_index = ciphertext.find(wrong_padding_block)
        if r_index != -1 and l_index != -1:
            block_to_find = ciphertext[r_index + MyAES.block_size * (num_block + 1):r_index + MyAES.block_size * (num_block + 2)]
            break
    for char in string.printable:
        guessed_block = None
        ext_fixed_input_bytes = fixed_input_bytes + bytes(discovered_bytes) + bytes(char, encoding="utf-8")
        while(True):
            random_input_bytes = random.randint(0, MyAES.block_size) * b"\x00"
            ext_input_bytes = random_input_bytes + ext_fixed_input_bytes
            ciphertext = aes_ecb_random_prefix_appended_secret(ext_input_bytes)
            r_index = ciphertext.rfind(full_A_block)
            l_index = ciphertext.find(wrong_padding_block)
            if r_index != -1 and l_index != -1:
                guessed_block = ciphertext[r_index + MyAES.block_size * (num_block + 1):r_index + MyAES.block_size * (num_block + 2)]
                break
        if guessed_block == block_to_find:
            return ord(char)


def main():
    # find block info (but we already know that is AES)
    block_info = detect_block_size()
    block_size = block_info[0]
    assert block_size == MyAES.block_size, "Something is horribly wrong."
    dummy_blocks = (block_info[1] // MyAES.block_size) + 1
    # create dummy input
    dummy_input = "A" * dummy_blocks * MyAES.block_size
    for i in range(len(dummy_input)):
        next_input = dummy_input[:len(dummy_input) - i]
        next_char = find_next_char(bytes(next_input, encoding="utf-8"), i // MyAES.block_size)
        if next_char is None:
            break
        discovered_bytes.append(next_char)
    print("Discovered:\n" + discovered_bytes.decode("utf-8"))


if __name__ == '__main__':
    main()


