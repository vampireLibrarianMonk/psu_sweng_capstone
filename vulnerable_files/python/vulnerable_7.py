# Python (Insecure Randomness Vulnerability)
import random

def generate_password(length):
    # Generate a random password of specified length
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

if __name__ == "__main__":
    length = int(input("Enter the desired password length: "))
    print(f"Generated password: {generate_password(length)}")
