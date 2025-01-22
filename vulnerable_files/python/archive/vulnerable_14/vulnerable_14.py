import requests

def send_sensitive_data():
    # Hardcoded sensitive information
    api_key = "12345-ABCDE"
    url = "https://example.com/api/data"
    data = {
        "username": "admin",
        "password": "password123"  # Hardcoded credentials
    }
    response = requests.post(url, json=data, headers={"Authorization": f"Bearer {api_key}"})
    return response.json()

if __name__ == "__main__":
    result = send_sensitive_data()
    print(result)
