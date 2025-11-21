import itertools
import string
import time
import re

CHARSET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:'\",.<>?/\\|`~"

def analyze_password_strength(password):
    length = len(password)
    has_lower = re.search(r'[a-z]', password) is not None
    has_upper = re.search(r'[A-Z]', password) is not None
    has_digit = re.search(r'\d', password) is not None
    has_special = re.search(r'[^a-zA-Z0-9]', password) is not None

    score = sum([has_lower, has_upper, has_digit, has_special])

    if length < 6 or score < 2:
        strength = "Weak"
    elif length >= 6 and score == 3:
        strength = "Moderate"
    elif length >= 8 and score == 4:
        strength = "Strong"
    else:
        strength = "Moderate"

    print("\nPassword Strength Analysis:")
    print(f" - Length: {length}")
    print(f" - Contains lowercase: {'Yes' if has_lower else 'No'}")
    print(f" - Contains uppercase: {'Yes' if has_upper else 'No'}")
    print(f" - Contains digit: {'Yes' if has_digit else 'No'}")
    print(f" - Contains special character: {'Yes' if has_special else 'No'}")
    print(f" - Strength: {strength}\n")

def brute_force_attack(real_password):
    max_length = len(real_password)
    attempts = 0
    start_time = time.time()

    print(f"Starting brute-force attack (max length = {max_length})...")

    for length in range(1, max_length + 1):
        for guess_tuple in itertools.product(CHARSET, repeat=length):
            guess = ''.join(guess_tuple)
            attempts += 1

            print(f"Trying: {guess}", end='\r')

            if guess == real_password:
                elapsed = time.time() - start_time
                print(f"\nPassword found: '{guess}'")
                print(f"Attempts: {attempts}")
                print(f"Time taken: {elapsed:.2f} seconds")
                return

    print("\nPassword not found within the given maximum length.")

if __name__ == "__main__":
    real_password = input("Enter the password to test: ")

    analyze_password_strength(real_password)
    brute_force_attack(real_password)
