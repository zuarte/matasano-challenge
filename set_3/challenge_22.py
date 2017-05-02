from set_3.challenge_21 import MT19937

import time, random


if __name__ == '__main__':

    # get a random number
    seconds_to_sleep = random.randint(40, 100)
    time.sleep(seconds_to_sleep)
    prng = MT19937(int(time.time()))
    seconds_to_sleep = random.randint(40, 100)
    random_number = prng.get_random()
    print(random_number)

    # get current system time
    unix_timestamp = int(time.time())
    for guessed_seed in range(unix_timestamp - 250, unix_timestamp + 1):
        guessed_random = MT19937(guessed_seed).get_random()
        if guessed_random == random_number:
            print("Random number " + str(random_number) + " found with seed " + str(guessed_seed) + "\n")

