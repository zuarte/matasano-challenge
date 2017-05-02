from utils import MyAES
import binascii

key_bytes = b"\x829\x01\x04\xff12a\xf7\x0aA}\x3e/\xc1\x00"


def parsing_routine(input_string):
    parameters = input_string.split("&")
    for i in range(len(parameters)):
        tokens = parameters[i].split("=")
        print(tokens[0] + ": " + tokens[1])


def profile_for(email_string):
    sanitized_string = email_string.replace("&", "", len(email_string)).replace("=", "", len(email_string))
    return "email=" + sanitized_string + "&uid=10&role=user"


def encrypt_profile(email_string):
    plaintext_bytes = MyAES.pkcs7_pad(bytes(email_string, encoding="utf-8"))
    cipher = MyAES.new(key_bytes, MyAES.MODE_ECB, None)
    return binascii.hexlify(cipher.raw_encrypt(plaintext_bytes))


def decrypt_token(token_bytes):
    ciphertext_bytes = binascii.unhexlify(token_bytes)
    cipher = MyAES.new(key_bytes, MyAES.MODE_ECB, None)
    plaintext = cipher.raw_decrypt(ciphertext_bytes).decode("utf-8", errors="ignore")
    parsing_routine(plaintext)


def main():
    input_string = "foo@aol.com"
    new_token = encrypt_profile(profile_for(input_string))
    print(new_token.decode("utf-8"))

    input_string = "foooooooo@admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b.com"
    new_token = encrypt_profile(profile_for(input_string))
    last_chunk = new_token[32:64]
    print(new_token.decode("utf-8"))

    new_token = encrypt_profile(profile_for("foooo@aol.com"))
    print(new_token.decode("utf-8"))

    hacked_token = new_token[:64] + last_chunk
    print(hacked_token.decode("utf-8"))
    decrypt_token(hacked_token)

if __name__ == '__main__':
    main()