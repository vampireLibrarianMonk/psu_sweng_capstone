# Python (Path Traversal Vulnerability)
import os


def read_file(filename):
    # Construct the full file path
    base_directory = '/var/www/data/'
    file_path = os.path.join(base_directory, filename)

    # Check if the file exists
    if os.path.exists(file_path):
        # Open and read the file
        with open(file_path, 'r') as file:
            return file.read()
    else:
        return "File not found."


if __name__ == "__main__":
    user_input = input("Enter the filename to read: ")
    file_content = read_file(user_input)
    print(file_content)
