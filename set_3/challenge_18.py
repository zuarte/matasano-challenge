from utils import MyAES
import base64, struct

def main():
    ciphertext_string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    ciphertext = base64.b64decode(ciphertext_string)
    counter = struct.pack("<QQ", 0, 0)
    plaintext = MyAES.new(b"YELLOW SUBMARINE", MyAES.MODE_CTR, counter).raw_decrypt(ciphertext)
    print(plaintext)

    ciphertext = MyAES.new(b"YELLOW SUBMARINE", MyAES.MODE_CTR, counter).raw_encrypt(b"Another test, foo bar.")
    plaintext = MyAES.new(b"YELLOW SUBMARINE", MyAES.MODE_CTR, counter).raw_decrypt(ciphertext)
    print(plaintext)

if __name__ == '__main__':
    main()


