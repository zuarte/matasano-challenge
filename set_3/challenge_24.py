from set_3.challenge_21 import MT19937
from utils.XOR import fixed_xor
import math, binascii


SIZE_OF_CHUNK = 4

class MT19937StreamCipher:

    def __init__(self, seed):
        self.seed = seed

    def raw_encrypt(self, plaintext):
        prng = MT19937(self.seed)
        chunks = len(plaintext) // SIZE_OF_CHUNK
        ciphertext_chunks = []
        for i in range(chunks):
            random = prng.get_random().to_bytes(SIZE_OF_CHUNK, byteorder="big")
            ciphertext_chunks.append(fixed_xor(random, plaintext[i * SIZE_OF_CHUNK:(i + 1) * SIZE_OF_CHUNK]))
        random = prng.get_random().to_bytes(SIZE_OF_CHUNK, byteorder="big")
        remainder = len(plaintext) % SIZE_OF_CHUNK
        if remainder != 0:
            ciphertext_chunks.append(fixed_xor(random[:remainder], plaintext[-remainder:]))
        ciphertext = bytearray()
        for chunk in ciphertext_chunks:
            ciphertext.extend(chunk)
        return ciphertext


    def raw_decrypt(self, ciphertext):
        prng = MT19937(self.seed)
        num_chunks = len(ciphertext) // SIZE_OF_CHUNK
        plaintext_chunks = []
        for i in range(num_chunks):
            random = prng.get_random().to_bytes(SIZE_OF_CHUNK, byteorder="big")
            plaintext_chunks.append(fixed_xor(random, ciphertext[i * SIZE_OF_CHUNK:(i + 1) * SIZE_OF_CHUNK]))
        random = prng.get_random().to_bytes(SIZE_OF_CHUNK, byteorder="big")
        remainder = len(ciphertext) % SIZE_OF_CHUNK
        if remainder != 0:
            plaintext_chunks.append(fixed_xor(random[:remainder], ciphertext[-remainder:]))
        plaintext = bytearray()
        for chunk in plaintext_chunks:
            plaintext.extend(chunk)
        return plaintext


def salted_encrypt(plaintext):
    ciph = MT19937StreamCipher(2912)
    garbage = b""
    ciphertext = ciph.raw_encrypt(garbage + plaintext)
    print(ciphertext)
    return ciphertext[len(garbage):]


def crack_seed(values):
    for i in range(int(math.pow(2, 16))):
        #print(i)
        prng = MT19937(i)
        checks = []
        for j in range(20):
            checks.append(prng.get_random())
        print(checks)
        set_one = set(checks)
        set_two = set(values)
        intersection = set_one.intersection(set_two)
        if len(intersection) != 0:
            print("Found seed! " + str(i))
            break


if __name__ == '__main__':
    '''
    cipher = MT19937StreamCipher(14391)
    ciph = cipher.raw_encrypt(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    print(ciph)
    deciph = cipher.raw_decrypt(ciph)
    print(deciph)
    value_bytes = fixed_xor_bytes(ciph[:SIZE_OF_CHUNK], b"A" * SIZE_OF_CHUNK)
    value = int.from_bytes(value_bytes, byteorder="big")
    crack_seed(value)
    '''

    plaintext = b"BBBBBBBB"
    ciph = fixed_xor(salted_encrypt(plaintext), plaintext)
    values = []
    print(binascii.hexlify(ciph))
    for i in range(SIZE_OF_CHUNK):
        values.append(int.from_bytes(ciph[i:SIZE_OF_CHUNK + i], byteorder="big"))
    print(values)
    crack_seed(values)
























