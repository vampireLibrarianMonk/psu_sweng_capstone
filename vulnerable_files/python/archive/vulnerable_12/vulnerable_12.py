# This file contains examples of suspicious filenames that Dodgy should flag.

# Writing sensitive data to a suspicious file (e.g., private key file)
with open("id_rsa", "w") as private_key:
    private_key.write("This is a simulated private key.")

# Another example with a suspicious filename
with open("server.pem", "w") as certificate_file:
    certificate_file.write("This is a simulated server certificate.")

print("Sensitive files created with suspicious filenames.")
