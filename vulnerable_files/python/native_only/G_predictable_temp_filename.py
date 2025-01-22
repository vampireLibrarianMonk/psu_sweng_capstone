import os
import tempfile

def create_temp_file():
    """
    Creates a temporary file with a predictable name.

    WARNING: This function is vulnerable to attacks as it uses a predictable
    filename for the temporary file, which can be exploited by an attacker.

    :return: The path to the temporary file.
    """
    temp_dir = tempfile.gettempdir()
    temp_file = os.path.join(temp_dir, 'tempfile.txt')
    with open(temp_file, 'w') as file:
        file.write("This is a temporary file.")
    return temp_file

if __name__ == "__main__":
    temp_file_path = create_temp_file()
    print(f"Temporary file created at: {temp_file_path}")
