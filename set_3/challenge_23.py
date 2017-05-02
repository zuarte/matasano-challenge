from set_3.challenge_21 import MT19937


def invert_mt_xorshift_right(y, k):
    assert k == MT19937.L or k == MT19937.U, "[invert_mt_xorshift_right]: unknown k parameter for MT19937"
    if k == MT19937.L:
        # k == 18
        k_hex = 0xFFFFC000
        first_k_bits = y & k_hex
        keystream = first_k_bits >> k
        keystream_hex = 0x3FFF
        last_k_bits = (y ^ keystream) & keystream_hex
        return first_k_bits | last_k_bits
    else:
        # k == 11
        k_hex = 0xFFE00000
        first_k_bits = y & k_hex
        f_keystream = first_k_bits >> k
        f_keystream_hex = 0x1FFC00
        second_k_bits = (y ^ f_keystream) & f_keystream_hex
        s_keystream = second_k_bits >> k
        s_keystream_hex = 0x3FF
        last_k_bits = (y ^ s_keystream) & s_keystream_hex
        return first_k_bits | second_k_bits | last_k_bits


def invert_mt_xorshift_left(y, k):
    assert k == MT19937.S or k == MT19937.T, "[invert_mt_xorshift_left]: unknown k parameter for MT19937"
    if k == MT19937.S:
        # k = 7
        mask = 0x7F
        chunk_0_7b = y & mask
        keystream_0 = (chunk_0_7b << k) & MT19937.B
        mask <<= k
        chunk_1_7b = (y ^ keystream_0) & mask
        keystream_1 = (chunk_1_7b << k) & MT19937.B
        mask <<= k
        chunk_2_7b = (y ^ keystream_1) & mask
        keystream_2 = (chunk_2_7b << k) & MT19937.B
        mask <<= k
        chunk_3_7b = (y ^ keystream_2) & mask
        keystream_3 = (chunk_3_7b << k) & MT19937.B
        chunk_4_4b = (y ^ keystream_3) & 0xF0000000
        return chunk_4_4b | chunk_3_7b | chunk_2_7b | chunk_1_7b | chunk_0_7b
    else:
        #k = 15
        mask = 0x1FFFF
        chunk_0_15b = y & mask
        keystream_0 = (chunk_0_15b << k) & MT19937.C
        mask <<= k
        chunk_1_15b = (y ^ keystream_0) & mask
        keystream_1 = (chunk_1_15b << k) & MT19937.C
        mask <<=k
        chunk_2_2b = (y ^ keystream_1) & 0xC0000000
        return chunk_2_2b | chunk_1_15b | chunk_0_15b


def invert_mt_output(value):
    y = invert_mt_xorshift_right(value, MT19937.L)
    y = invert_mt_xorshift_left(y, MT19937.T)
    y = invert_mt_xorshift_left(y, MT19937.S)
    y = invert_mt_xorshift_right(y, MT19937.U)
    return y


def mt19937_cloner(prng):
    # dummy seed
    cloned_prng = MT19937(0)
    for i in range(MT19937.ITERATIONS):
        cloned_prng.mt[i] = invert_mt_output(prng.get_random())
        cloned_prng.index = (cloned_prng.index + 1) % MT19937.ITERATIONS
    return cloned_prng


if __name__ == '__main__':

    expected = 2629073562
    result = invert_mt_xorshift_right(2628250645, 11)
    assert expected == result, "Test case for 11 fails."
    expected = 1791094421
    result = invert_mt_xorshift_right(1791095845, 18)
    assert expected == result, "Test case for 18 fails."
    expected = 2374233749
    result = invert_mt_xorshift_left(1791094421, 15)
    assert expected == result, "Test case for 15 fails."
    expected = 2628250645
    result = invert_mt_xorshift_left(2374233749, 7)
    assert expected == result, "Test case for 7 fails."
    expected = 2982652730
    result = invert_mt_xorshift_left(818134842, 7)
    assert expected == result, "Test case for 7 fails."

    prng = MT19937(123398)
    cloned_prng = mt19937_cloner(prng)
    # from now on the prng should be perfectly cloned
    for i in range(5000):
        #assert cloned_prng.get_random() == prng.get_random(), "Something went wrong."
        print(cloned_prng.get_random())
        print(prng.get_random())
        print()