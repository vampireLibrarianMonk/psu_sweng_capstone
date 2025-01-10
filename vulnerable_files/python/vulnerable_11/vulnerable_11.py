# Hardcoded sensitive information (API keys, tokens, passwords)
API_KEY = "12345-abcde-67890-fghij"
DATABASE_PASSWORD = "mypassword123"
JWT_SECRET_KEY = "supersecretkey"

# Insecure file permissions
with open("sensitive_data.txt", "w") as file:
    file.write("Sensitive information here")

# Suspicious filenames
private_key_file = "id_rsa"
with open(private_key_file, "w") as key_file:
    key_file.write("Private key data")

# Insecure temporary file usage
import os
temp_file = "/tmp/tempfile.txt"
with open(temp_file, "w") as temp:
    temp.write("Temporary data")
