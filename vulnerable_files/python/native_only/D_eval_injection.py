def calculate_area_of_circle(radius):
    """
    Calculates the area of a circle given its radius.

    WARNING: This function is vulnerable to eval injection attacks as it uses
    the eval() function to evaluate a mathematical expression that includes
    user-provided input without proper sanitization.

    :param radius: The radius of the circle.
    :return: The area of the circle.
    """
    # Vulnerable use of eval()
    area = eval("3.14159 * (radius ** 2)")
    return area

if __name__ == "__main__":
    user_input = input("Enter the radius of the circle: ")
    try:
        # Convert user input to a float
        radius = float(user_input)
        result = calculate_area_of_circle(radius)
        print(f"Area of the circle: {result}")
    except ValueError:
        print("Invalid input. Please enter a numeric value.")
    except Exception as e:
        print(f"An error occurred: {e}")
