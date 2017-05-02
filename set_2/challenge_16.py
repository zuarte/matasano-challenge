from set_2.challenge_15 import valid_pkcs7_padding
from set_2.challenge_14 import key as key_bytes
from utils import MyAES
import binascii


def convert_offending_chars(input_string):
    offending_chars = [(";", "%3B"), ("=", "%3D")]
    input_type = type(input_string)
    assert input_type is str, "[convert_offending_char]: expecting input as str, found " + input_type.__name__
    temp_string = input_string
    for tuple in offending_chars:
        temp_string = temp_string.replace(tuple[0], tuple[1])
    return temp_string


def aes_cbc_fixed_prefix_fixed_suffix(input_bytes):
    input_type = type(input_bytes)
    assert input_type is bytes, "[convert_offending_char]: expecting input as bytes, found " + input_type.__name__
    plaintext_bytes = bytearray()
    prefix_bytes = "comment1=cooking%20MCs;userdata=".encode("utf-8")
    suffix_bytes = ";comment2=%20like%20a%20pound%20of%20bacon".encode("utf-8")
    plaintext_bytes.extend(prefix_bytes)
    plaintext_bytes.extend(input_bytes)
    plaintext_bytes.extend(suffix_bytes)
    plaintext_bytes = MyAES.pkcs7_pad(plaintext_bytes)
    print(plaintext_bytes)
    # IV all zeroes
    cipher = MyAES.new(key_bytes, MyAES.MODE_CBC, bytes(MyAES.block_size))
    return cipher.raw_encrypt(plaintext_bytes)


def is_token_admin(input_bytes):
    cipher = MyAES.new(key_bytes, MyAES.MODE_CBC, bytes(MyAES.block_size))
    plaintext_bytes = valid_pkcs7_padding(cipher.raw_decrypt(input_bytes), strip=True)
    print(plaintext_bytes)
    plaintext = plaintext_bytes.decode("utf-8", errors="ignore")
    parameter_list = plaintext.split(";")
    for parameter in parameter_list:
        values_list = parameter.split("=")
        if len(values_list) == 2:
            name = values_list[0]
            value = values_list[1]
            if name == "admin" and value == "true":
                return True
        else:
            continue
    return False

def index_diff_block(f_ciph_bytes, s_ciph_bytes):
    assert len(f_ciph_bytes) == len(s_ciph_bytes), "[index_diff_block]: len(f_ciph_bytes) != len(s_ciph_bytes)"
    for i in range(len(s_ciph_bytes) // MyAES.block_size - 2):
        if f_ciph_bytes[i * MyAES.block_size:(i + 1) * MyAES.block_size] != s_ciph_bytes[i * MyAES.block_size:(i + 1) * MyAES.block_size]:
            print(binascii.hexlify(f_ciph_bytes[i * MyAES.block_size:(i + 1) * MyAES.block_size]))
            print(binascii.hexlify(s_ciph_bytes[i * MyAES.block_size:(i + 1) * MyAES.block_size]))
            print(i)
            return i


def bitflipping(ciphertext, index, xor_list):
    assert index >= 1, "[bitflip]: something is horribly wrong"


def main():

    last_input_block = ":admin?true:a?AA"
    # tuples of "bad" chars in last_input_block, we want ";admin=true;a=AA
    positions = [(0, ";"), (6, "="), (11, ";"), (13, "=")]

    # craft a suitable input for a bitflipping attack
    block_number = len(aes_cbc_fixed_prefix_fixed_suffix(b"")) // MyAES.block_size

    padding_input_string = ""
    while True:
        new_block_number = len(aes_cbc_fixed_prefix_fixed_suffix(bytes(padding_input_string, encoding="utf-8"))) // MyAES.block_size
        if new_block_number > block_number:
            break
        padding_input_string += "A"

    probe_ciphertext = aes_cbc_fixed_prefix_fixed_suffix(bytes(padding_input_string + "A" * MyAES.block_size, encoding="utf-8"))
    probing_input = padding_input_string + "A" * MyAES.block_size

    first = 0
    index = 0
    left_pad = 0
    for i in range(len(probing_input) - 1, -1, -1):
        probing_input = probing_input[:i] + "B" * (len(probing_input) - i)
        if i == (len(probing_input) - 1):
            first = index_diff_block(probe_ciphertext, aes_cbc_fixed_prefix_fixed_suffix(bytes(probing_input, encoding="utf-8")))
        else:
            index = index_diff_block(probe_ciphertext, aes_cbc_fixed_prefix_fixed_suffix(bytes(probing_input, encoding="utf-8")))
            if first != index:
                left_pad = i + 1
                break

    f_input_string = "A" * left_pad + last_input_block + padding_input_string
    s_input_string = "A" * left_pad + last_input_block[:-1] + "B" + padding_input_string

    first_ciphertext = aes_cbc_fixed_prefix_fixed_suffix(bytes(f_input_string, encoding="utf-8"))
    second_ciphertext = aes_cbc_fixed_prefix_fixed_suffix(bytes(s_input_string, encoding="utf-8"))

    print(binascii.hexlify(first_ciphertext))
    print(binascii.hexlify(second_ciphertext))

    index_of_last_input_block = index_diff_block(first_ciphertext, second_ciphertext)

    xor_list = [0] * len(positions)
    for i in range(len(positions)):
        xor_list[i] = ord(last_input_block[positions[i][0]]) ^ ord(positions[i][1])

    first_bytearray = bytearray(first_ciphertext)

    for i in range(len(positions)):
        first_bytearray[MyAES.block_size * (index_of_last_input_block - 1) + positions[i][0]] ^= xor_list[i]

    print(binascii.hexlify(first_bytearray))
    # decrypt
    print(is_token_admin(bytes(first_bytearray)))

if __name__ == '__main__':
    main()
