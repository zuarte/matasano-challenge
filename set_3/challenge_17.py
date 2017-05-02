from set_2.challenge_15 import valid_pkcs7_padding, InvalidPKCS7PaddingException
from utils import MyAES
from utils.XOR import fixed_xor
import base64, random


b64_strings = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]


key_bytes = random.getrandbits(MyAES.block_size * 8).to_bytes(MyAES.block_size, byteorder="big")


def select_and_encrypt():
    choice = random.randint(0, len(b64_strings) - 1)
    b64_string = b64_strings[choice]
    string_bytes = base64.b64decode(b64_string)
    iv_bytes = random.getrandbits(MyAES.block_size * 8).to_bytes(MyAES.block_size, byteorder="big")
    cipher = MyAES.new(key_bytes, MyAES.MODE_CBC, iv_bytes)
    ciphertext = cipher.raw_encrypt(MyAES.pkcs7_pad(string_bytes))
    return (iv_bytes, ciphertext)


def decrypt(iv_bytes, ciphertext_bytes):
    cipher = MyAES.new(key_bytes, MyAES.MODE_CBC, iv_bytes)
    plaintext_bytes = cipher.raw_decrypt(ciphertext_bytes)
    return valid_pkcs7_padding(plaintext_bytes, strip=False)


def brute_second_block(first_block, second_block):
    prexored = []
    for j in range(MyAES.block_size - 1, -1, -1):
        fb_bytearray = bytearray(first_block)
        for i in range(MyAES.block_size):
            fb_bytearray[i] = 0
        for i in range(len(prexored)):
            fb_bytearray[j + i + 1] = prexored[i] ^ (MyAES.block_size - j)
        found = False
        for byte in range(256):
            fb_bytearray[j] = byte
            #print(str(byte) + " - " + binascii.hexlify(fb_bytearray).decode("utf-8"))
            try:
                if decrypt(bytes(fb_bytearray), second_block) is True:
                    prexored.insert(0, byte ^ (MyAES.block_size - j))
                    found = True
                    #print("found " + str(j) + " - " + str(byte ^ (aes_block_size - j)))
                    break
            except InvalidPKCS7PaddingException:
                pass
        if found is False:
            raise Exception("Ouch")
        #print(prexored)
    return fixed_xor(first_block, prexored)


def cbc_padding_oracle_attack(iv_bytes, ciphertext_bytes):
    blocks = len(ciphertext_bytes) // MyAES.block_size
    #print(blocks)
    #print(brute_second_block(iv_bytes, ciphertext_bytes[:aes_block_size]))
    #print(brute_second_block(ciphertext_bytes[:aes_block_size], ciphertext_bytes[aes_block_size:2*aes_block_size]))
    #print(brute_second_block(ciphertext_bytes[aes_block_size:2*aes_block_size], ciphertext_bytes[2*aes_block_size:3*aes_block_size]))
    plaintext_bytes = brute_second_block(iv_bytes, ciphertext_bytes[:MyAES.block_size])
    for i in range(2, blocks + 1):
        plaintext_bytes += brute_second_block(ciphertext_bytes[(i - 2) * MyAES.block_size:(i - 1) * MyAES.block_size], ciphertext_bytes[(i - 1) * MyAES.block_size:i * MyAES.block_size])
    print(valid_pkcs7_padding(plaintext_bytes, strip=True).decode("utf-8"))


def main():
    iv_bytes, ciphertext_bytes = select_and_encrypt()
    print(iv_bytes)
    print(ciphertext_bytes)
    decrypt(iv_bytes, ciphertext_bytes)
    cbc_padding_oracle_attack(iv_bytes, ciphertext_bytes)


if __name__ == '__main__':
    main()