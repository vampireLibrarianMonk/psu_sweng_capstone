import os
import time
import threading

def check_and_delete(file_path):
    """
    Checks if a file exists and deletes it.

    WARNING: This function is vulnerable to a race condition (TOCTOU) because
    there is a time gap between checking for the file's existence and deleting it.
    An attacker could exploit this gap to manipulate the file.

    :param file_path: The path to the file to check and delete.
    """
    if os.path.exists(file_path):
        # Simulate time gap
        time.sleep(1)
        os.remove(file_path)
        print(f"{file_path} has been deleted.")
    else:
        print(f"{file_path} does not exist.")

if __name__ == "__main__":
    temp_file = "temp.txt"
    # Create a temporary file
    with open(temp_file, 'w') as f:
        f.write("Temporary file content.")

    # Start a thread to check and delete the file
    thread = threading.Thread(target=check_and_delete, args=(temp_file,))
    thread.start()

    # Simulate an attacker replacing the file during the time gap
    time.sleep(0.5)
    with open(temp_file, 'w') as f:
        f.write("Malicious content.")

    thread.join()
