import os

def list_directory_contents(directory):
    """
    Lists the contents of the specified directory.

    WARNING: This function is vulnerable to command injection attacks because
    it directly incorporates user input into a system command without sanitization.

    :param directory: The directory path to list contents of.
    """
    # Vulnerable system command
    os.system(f"ls {directory}")

if __name__ == "__main__":
    user_input = input("Enter directory path: ")
    list_directory_contents(user_input)
