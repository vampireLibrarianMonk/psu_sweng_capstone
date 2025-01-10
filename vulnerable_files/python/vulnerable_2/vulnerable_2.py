# Python (Command Injection)
import os

def execute_user_command(command):
    # Unsafely executes user-provided command
    os.system(command)

if __name__ == "__main__":
    user_command = input("Enter a shell command to execute: ")
    execute_user_command(user_command)
