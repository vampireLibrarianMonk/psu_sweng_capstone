import os
from utilities_llm import organize_imports_and_globals


if __name__ == "__main__":
    # Specify the file path
    file_path = "/home/flaniganp/repositories/psu_sweng_capstone/mitigated_files/VulnerablePythonScript_mitigated_final.py"  # Replace with your file path

    # Ensure the file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        exit()

    # Run the organize_imports_and_globals method
    print(f"Processing file: {file_path}")
    organize_imports_and_globals(file_path)

    # Display the result file path
    new_file_path = os.path.splitext(file_path)[0] + "_organized.py"
    if os.path.exists(new_file_path):
        print(f"Organized file created: {new_file_path}")
    else:
        print("Error: Failed to create the organized file.")
