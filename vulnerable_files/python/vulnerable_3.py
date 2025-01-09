# Python (SQL Injection Vulnerability)
import sqlite3


def get_user_info(username):
    # Establish a connection to the database
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()

    # Construct the SQL query unsafely
    query = f"SELECT * FROM users WHERE username = '{username}'"

    # Execute the query
    cursor.execute(query)
    result = cursor.fetchall()

    # Close the connection
    conn.close()

    return result


if __name__ == "__main__":
    user_input = input("Enter your username: ")
    user_info = get_user_info(user_input)
    print(user_info)