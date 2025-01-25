import sqlite3

def get_user_info(username):
    """
    Fetches user information from the database based on the provided username.

    WARNING: This function is vulnerable to SQL injection attacks due to the
    direct inclusion of user input in the SQL query without proper sanitization.

    :param username: The username to search for in the database.
    :return: User information if found, else None.
    """
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    # Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result

if __name__ == "__main__":
    user_input = input("Enter username: ")
    user_info = get_user_info(user_input)
    if user_info:
        print(f"User Info: {user_info}")
    else:
        print("User not found.")
