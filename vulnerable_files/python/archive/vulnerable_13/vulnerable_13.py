# This file contains examples of insecure file paths that Dodgy should flag.

# Writing sensitive data to an insecure temporary directory
tmp_file_path = "/tmp/sensitive_data.txt"
with open(tmp_file_path, "w") as temp_file:
    temp_file.write("Sensitive data written to an insecure temporary file.")

# Creating another insecure temporary file
tmp_file_path_2 = "/tmp/temp_key.pem"
with open(tmp_file_path_2, "w") as temp_key_file:
    temp_key_file.write("Temporary sensitive key data.")

print("Sensitive files created in insecure temporary paths.")
