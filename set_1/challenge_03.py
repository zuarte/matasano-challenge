import binascii, string, struct
from utils.XOR import fixed_xor
from utils.Vector import cosine_similarity, build_frequency_vector_from_text
from utils.String import text_check_only_allowed_chars, text_contains_char

# string of printable characters
allowed_chars_string = string.ascii_letters + string.digits + ".,:;-_'()[]&%$\"!?/\\^" + string.whitespace

# reference list of char frequency in English text
char_frequency_reference = {
    'A': 8.12,
    'B': 1.49,
    'C': 2.71,
    'D': 4.32,
    'E': 12.02,
    'F': 2.30,
    'G': 2.03,
    'H': 5.92,
    'I': 7.31,
    'J': 0.10,
    'K': 0.69,
    'L': 3.98,
    'M': 2.61,
    'N': 6.95,
    'O': 7.68,
    'P': 1.82,
    'Q': 0.11,
    'R': 6.02,
    'S': 6.28,
    'T': 9.10,
    'U': 2.88,
    'V': 1.11,
    'W': 2.09,
    'X': 0.17,
    'Y': 2.11,
    'Z': 0.07
}
vector_frequency_reference = list(map(lambda tup: tup[1], list(char_frequency_reference.items())))


def main():
    result_list = []
    hexstr = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    bytes_str = binascii.unhexlify(hexstr)

    # single char xor
    for i in range(256):
        try:
            plaintext = fixed_xor(bytes_str, (struct.pack("B", i) * len(bytes_str))).decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text_check_only_allowed_chars(plaintext, allowed_chars_string) and text_contains_char(plaintext, " "):
            vector_a = build_frequency_vector_from_text(plaintext, list(char_frequency_reference.keys()), uppercase=True)
            result_list.append((cosine_similarity(vector_a, vector_frequency_reference), chr(i)))

    key = sorted(result_list, reverse=True)[0][1]
    plaintext = fixed_xor(bytes_str, bytes(key * len(bytes_str), encoding="utf-8")).decode("utf-8")
    print(key + ":" + " " + plaintext)


if __name__ == '__main__':
    main()