# # Prepare the system prompt for the AI assistant
# unit_test_system_prompt = (
#     "You are an AI assistant skilled in generating Python unit tests. Your task is to create a unit test that executes "
#     "both the original and mitigated functions, providing the same input to each, capturing their outputs, and comparing "
#     "them to ensure they produce identical results. If they do not, the test should identify the discrepancies. "
#     "Additionally, the test should include example inputs and their expected outputs. "
#     "Please ensure that all explanations and instructions are embedded within the code as docstrings or inline comments, "
#     "adhering to Python's best practices for documentation."
# )
#
# # Prepare the user prompt with the code to be reviewed
# unit_test_user_prompt = (
#     "Below are two Python functions:\n\n"
#     "Original Function:\n"
#     "```\n"
#     f"\"\"{original_code}\"\"\"\n"
#     "```\n\n"
#     "Mitigated Function:\n"
#     "```\n"
#     f"\"\"{mitigated_code}\"\"\"\n"
#     "```\n\n"
#     "Please generate a Python unit test that:\n"
#     "1. Defines both functions within the test script.\n"
#     "2. Provides example inputs and their expected outputs.\n"
#     "3. Executes both functions with the same inputs.\n"
#     "4. Captures and compares their outputs.\n"
#     "5. Asserts that the outputs are identical.\n"
#     "6. Reports any discrepancies if the outputs differ.\n"
#     "If creating such a unit test is not feasible due to differences in the functions or other limitations, please provide a detailed explanation. "
#     "Ensure that all explanations and instructions are included as docstrings or inline comments within the code, following Python's best practices for documentation."
# )

# Combine system and user prompts into a message list

# Turn the final file path into a from import statement for each of its methods