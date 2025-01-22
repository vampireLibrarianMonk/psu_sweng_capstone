def read_file(filename):
    """
    Reads the content of a specified file.

    WARNING: This function is vulnerable to path traversal attacks as it does
    not validate or sanitize the filename provided by the user.

    :param filename: The name of the file to read.
    :return: The content of the file.
    """
    with open(filename, 'r') as file:
        return file.read()

if __name__ == "__main__":
    user_input = input("Enter the filename to read: ")
    try:
        content = read_file(user_input)
        print(f"File Content:\n{content}")
    except FileNotFoundError:
        print("File not found.")
