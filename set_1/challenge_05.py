from utils.XOR import fixed_xor, extend_key_for_xor
import binascii


def main():
    string = bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", encoding="utf-8")
    key = b"ICE"
    new_key_bytes = extend_key_for_xor(key, len(string))
    print(binascii.hexlify(fixed_xor(string, new_key_bytes)).decode("utf-8"))

if __name__ == '__main__':
    main()