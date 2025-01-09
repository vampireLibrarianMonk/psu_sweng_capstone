# Python (Timing Attack Vulnerability)
import time

def insecure_compare(user_input, expected_value):
    if len(user_input) != len(expected_value):
        return False
    for x, y in zip(user_input, expected_value):
        if x != y:
            return False
        time.sleep(0.01)  # Artificial delay
    return True

if __name__ == "__main__":
    expected_token = "securetoken123"
    user_token = input("Enter your authentication token: ")
    if insecure_compare(user_token, expected_token):
        print("Access granted.")
    else:
        print("Access denied.")
