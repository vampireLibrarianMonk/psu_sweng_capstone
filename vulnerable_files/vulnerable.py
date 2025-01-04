# Python (Insecure Deserialization)
import pickle

def load_user_data(serialized_data):
    user_data = pickle.loads(serialized_data) # Untrusted input deserialization
    print(f"User data: {user_data}")

if __name__ == "__main__":
    malicious_input = input("Enter serialized data: ")
    load_user_data(malicious_input)
