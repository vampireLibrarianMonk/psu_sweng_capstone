# Intentionally Vulnerable Python Application

This rewritten [repository](https://github.com/mukxl/Intentionally-Vulnerable-Python-Application) contains a deliberately vulnerable Python web application designed for testing purposes. It includes several security flaws that can be detected by security tools such as:

- **Software Composition Analysis (SCA)**
- **Static Application Security Testing (SAST)**
- **Dynamic Application Security Testing (DAST)**

---

## Key Vulnerabilities

1. **Insecure Use of Subprocess (Command Injection):**
   - *Original Code:*
     - Utilizes `subprocess.check_output` to execute system commands, which can be exploited for command injection if user input is not properly sanitized.
   - *Mitigated Code:*
     - Replaces `subprocess` with the `ping3` library for ICMP operations, eliminating the risk associated with executing system commands directly.

2. **Hardcoded Credentials:**
   - *Original Code:*
     - Stores plaintext credentials (`USERNAME` and `PASSWORD`) within the code, posing a security risk if the codebase is exposed.
   - *Mitigated Code:*
     - Removes hardcoded credentials and utilizes `check_password_hash` from `werkzeug.security` to securely verify passwords, enhancing security by preventing exposure of plaintext credentials.

3. **Insecure Deserialization:**
   - *Original Code:*
     - Uses the `pickle` module to deserialize data, which is unsafe when handling untrusted input and can lead to arbitrary code execution.
   - *Mitigated Code:*
     - Eliminates the use of `pickle` and replaces it with `json.loads` for deserialization, ensuring that only valid JSON data is processed, thereby mitigating the risk of code injection.

4. **Use of Outdated Library with Known Vulnerabilities:**
   - *Original Code:*
     - Makes HTTP requests without specifying a timeout, which can lead to the application hanging indefinitely if the remote server does not respond.
   - *Mitigated Code:*
     - Adds a timeout parameter to HTTP requests using the `requests` library, preventing indefinite hangs and improving the application's resilience to unresponsive servers.

5. **SQL Injection:**
   - *Original Code:*
     - Constructs SQL queries by directly concatenating user input, making the application vulnerable to SQL injection attacks.
   - *Mitigated Code:*
     - Introduces parameterized queries in the `run_query` function, ensuring that user input is properly sanitized before being included in SQL statements, thereby preventing SQL injection attacks.

6. **Flask Debug Mode Enabled in Production:**
   - *Original Code:*
     - Runs the Flask application with `debug=True`, which should not be used in production as it can lead to security vulnerabilities.
   - *Mitigated Code:*
     - Sets `debug=False` when running the Flask application, ensuring that debug mode is not enabled in a production environment, thereby enhancing security.


TBD: Dependency scanning starting with

The application relies on an outdated version of the requests library, which may have known vulnerabilities.

---

## Purpose

This repository is intended for:

- **Security training**
- **Vulnerability scanning**
- **Testing tools like DefectDojo**

It provides a safe environment to understand how different security vulnerabilities can be identified and exploited.
