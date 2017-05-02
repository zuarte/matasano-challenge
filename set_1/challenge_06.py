import base64, struct
from set_1.challenge_03 import allowed_chars_string, char_frequency_reference, vector_frequency_reference
from utils.String import hamming_distance, text_check_only_allowed_chars
from utils.Vector import is_null_vector, build_frequency_vector_from_text, cosine_similarity
from utils.XOR import fixed_xor, extend_key_for_xor


def find_key(blocks):

    key = bytearray()
    for i in range(len(blocks)):
        single_block_result_list = []
        for j in range(256):
            plaintext = fixed_xor(blocks[i], struct.pack("B", j) * len(blocks[i]))
            try:
                plaintext = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if text_check_only_allowed_chars(plaintext, allowed_chars_string):
                vector_a = build_frequency_vector_from_text(plaintext, list(char_frequency_reference.keys()), uppercase=True)
                if is_null_vector(vector_a) is True:
                    continue
                single_block_result_list.append((cosine_similarity(vector_a, vector_frequency_reference), j, plaintext))

        print(sorted(single_block_result_list, reverse=True))
        try:
            best_block_key = sorted(single_block_result_list, reverse=True)[0][1]
            print("The best key for this block is char \"" + chr(best_block_key) + "\", press Enter or specify another int")
            key_char = int(input() or best_block_key)
            key.extend(struct.pack("B", key_char))
        except IndexError:
            return None

    return bytes(key)


def crack_repeating_xor(ciphertext):

    keylength_list = []

    max_keysize = len(ciphertext) // 3
    if max_keysize > 50:
        max_keysize = 50

    for keysize in range(2, max_keysize):
        first_chunk = ciphertext[:keysize]
        second_chunk = ciphertext[keysize:(keysize * 2)]
        third_chunk = ciphertext[(keysize * 2):(keysize * 3)]
        fourth_chunk = ciphertext[(keysize * 2):(keysize * 3)]
        first_distance = hamming_distance(first_chunk, second_chunk) / keysize
        second_distance = hamming_distance(first_chunk, third_chunk) / keysize
        third_distance = hamming_distance(first_chunk, fourth_chunk) / keysize
        fourth_distance = hamming_distance(second_chunk, third_chunk) / keysize
        fifth_distance = hamming_distance(second_chunk, fourth_chunk) / keysize
        sixth_distance = hamming_distance(third_chunk, fourth_chunk) / keysize
        normalized_distance = (first_distance + second_distance + third_distance + fourth_distance + fifth_distance
                              + sixth_distance) / 6
        keylength_list.append((normalized_distance, keysize))

    print("Suggested keylength (enter for first)")
    print(sorted(keylength_list))
    keylength = int(input()) or sorted(keylength_list)[0][1]
    print("Will try to decrypt the xored text with a key of length " + str(keylength))
    blocks = list(zip(*[iter(ciphertext)]*keylength))
    # transpose the blocks
    blocks = list(zip(*blocks))
    print()
    block_key = find_key(blocks)
    return block_key


def main():

    oneline = ""
    with open("data/6.txt", "r") as file:
        for line in file.readlines():
            oneline += line.strip("\n")
    ciphertext = base64.b64decode(oneline)

    key = crack_repeating_xor(ciphertext)
    print("\nKey is: \"" + key.decode("utf-8") + "\n")
    plaintext = fixed_xor(ciphertext, extend_key_for_xor(key, len(ciphertext)))
    print(plaintext.decode("utf-8") + "\n")


if __name__ == '__main__':
    main()

