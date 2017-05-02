from utils.XOR import fixed_xor
import binascii


def fixed_xor_hex(f_hex_str, s_hex_str):
    f_str = binascii.unhexlify(f_hex_str)
    s_str = binascii.unhexlify(s_hex_str)
    raw_res = fixed_xor(f_str, s_str)
    return binascii.hexlify(raw_res).decode("utf-8")


def main():
    f_hex_str = "1c0111001f010100061a024b53535009181c"
    s_hex_str = "686974207468652062756c6c277320657965"
    print(fixed_xor_hex(f_hex_str, s_hex_str))


if __name__ == '__main__':
    main()