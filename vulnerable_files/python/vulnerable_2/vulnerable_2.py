# Python (Command Injection)
import os


def list_files_in_directory(directory):
    """
    Unsafely executes a command to list files in the specified directory.
    This is vulnerable to command injection because the user input is directly
    interpolated into the shell command without validation or sanitization.

    Example of a malicious injection:
    If the user inputs "; rm -rf /", the command executed will be:
    `ls ; rm -rf /`
    This would result in deleting all files on the system (if permissions allow).
    """
    os.system(f"ls {directory}")


if __name__ == "__main__":
    user_directory = input("Enter the directory to list files: ")
    list_files_in_directory(user_directory)
