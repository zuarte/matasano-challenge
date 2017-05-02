from set_1.challenge_03 import char_frequency_reference, vector_frequency_reference, allowed_chars_string
from utils.String import text_contains_char, text_check_only_allowed_chars
from utils.Vector import build_frequency_vector_from_text, cosine_similarity
from utils.XOR import fixed_xor
import binascii, struct


def main():
    result_list = []
    with open("data/4.txt", "r") as file:
        for index, line in enumerate(file.readlines()):
            line = line.strip("\n")
            bytes_str = binascii.unhexlify(line)
            # single byte xor
            for i in range(256):
                try:
                    plaintext = fixed_xor(bytes_str, (struct.pack("B", i) * len(bytes_str))).decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if text_check_only_allowed_chars(plaintext, allowed_chars_string) and text_contains_char(plaintext, " "):
                    vector_a = build_frequency_vector_from_text(plaintext, list(char_frequency_reference.keys()), uppercase=True)
                    result_list.append((cosine_similarity(vector_a, vector_frequency_reference), chr(i), index, plaintext))

    best_match = sorted(result_list, reverse=True)[0]
    key = best_match[1]
    line = best_match[2]
    plaintext = best_match[3]
    print("line: " + str(line) + " - key: " + key + " - plaintext: " + plaintext)

if __name__ == '__main__':
    main()