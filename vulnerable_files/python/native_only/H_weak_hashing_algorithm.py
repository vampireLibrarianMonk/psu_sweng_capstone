import hashlib

def store_password(password):
    """
    Stores the user's password.

    WARNING: This function uses a weak hashing algorithm (MD5) without a salt,
    making it vulnerable to attacks such as rainbow table attacks.

    :param password: The password to store.
    :return: The hashed password.
    """
    # Vulnerable hashing method
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    return hashed_password

if __name__ == "__main__":
    user_password = input("Enter your password: ")
    stored_password = store_password(user_password)
    print(f"Stored password hash: {stored_password}")
