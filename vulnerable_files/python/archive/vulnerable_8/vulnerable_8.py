# Python (Insecure Use of eval() Vulnerability)
def calculate(expression):
    try:
        # Evaluate the arithmetic expression provided by the user
        result = eval(expression)
        return result
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    user_input = input("Enter an arithmetic expression to evaluate: ")
    print(f"Result: {calculate(user_input)}")
