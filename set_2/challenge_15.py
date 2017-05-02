from utils.MyAES import block_size


class InvalidPKCS7PaddingException(Exception):
    pass


def last_block(input_bytes):
    index = len(input_bytes) // block_size
    return input_bytes[(index - 1) * block_size:index * block_size]


def valid_pkcs7_padding(input_bytes, strip):
    assert len(input_bytes) % block_size == 0 and len(input_bytes) != 0, "[valid_pkcs7_padding]: invalid input size (" + str(len(input_bytes)) + ")"
    padding_block = last_block(input_bytes)
    value = padding_block[-1]
    if value not in range(1, block_size + 1):
        raise InvalidPKCS7PaddingException("Value not in range: " + str(value))
    for i in range(value):
        found = padding_block[len(padding_block) - value + i]
        if found != value:
            # raise InvalidPKCS7PaddingException("Found: " + str(found) + " Expected: " + str(value))
            raise InvalidPKCS7PaddingException("Invalid PKCS#7 padding")
    if strip is True:
        return input_bytes[:len(input_bytes) - value]
    else:
        return True


def main():
    plaintext = valid_pkcs7_padding(bytes("ICE ICE BABY\x01\x02\x02\x02\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", encoding="utf-8"), True)
    print(plaintext)


if __name__ == '__main__':
    main()