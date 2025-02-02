from llama_cpp import Llama
import argparse

from utilities_llm import get_block_count_keys, get_optimal_gpu_layers, setup_logger

# Initialize the LLaMA model
model_path = "models/CodeLlama-13b-Python-hf-Q5_K_M.gguf"

# Initialize the logger
logger = setup_logger(f"vulnerability_rectifier", 'A', 'direct_prompt')

# Get the total layers from the input model
total_layers = get_block_count_keys(model_path, logger)

# Determine the optimal number of GPU layers to offload
n_gpu_layers = get_optimal_gpu_layers(model_path, total_layers)

# Initialize the Llama model with appropriate settings
llama = Llama(
    model_path=model_path,
    seed=42,  # Fixed seed for reproducibility
    n_ctx=4096, #Set the desired context size here
    use_mmap=True,  # Memory mapping for efficiency
    use_mlock=True,  # Prevent swapping to disk for consistent performance
    n_gpu_layers=n_gpu_layers
)


def generate_unit_tests(python_code: str) -> str:
    """
    Generates unit tests for the given Python code.
    """
    prompt = f"""
    You are a Python expert specializing in writing unit tests.
    
    Below is a Python function that needs a unit test. Write exactly one **Positive Test** to verify normal behavior:
    - Include necessary imports for testing (e.g., unittest, json).
    - Use the unittest framework.
    - Output only **one** valid Python code block.
    - **Do not include comments**, repeated code, additional text, or explanations.
    - Do not duplicate the function definition.
    - Ensure the output is correctly formatted ```python``` code without unnecessary elements.
    
    Function to test:
    def load_user_data(serialized_data: bytes) -> dict:
        if not serialized_data:
            raise ValueError('Serialized data is empty')
    
        try:
            user_data = json.loads(serialized_data.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError('Malformed JSON data') from e
        if not isinstance(user_data, dict):
            raise ValueError('Invalid user data format')
    
        user_id = user_data.get('user_id')
        if not user_id:
            raise ValueError('Missing user ID in user data')
    
        return user_data
    """

    # Generate response
    response = llama(prompt, max_tokens=2048, temperature=0.0, top_p=1, top_k=0, stop=["<|endoftext|>"])
    return response["choices"][0]["text"]


def read_file(file_path: str) -> str:
    """
    Reads and returns the contents of a Python file.
    """
    with open(file_path, "r") as file:
        return file.read()


def main():
    parser = argparse.ArgumentParser(description="Generate unit tests for Python code.")
    parser.add_argument("-f", "--file", type=str, help="Path to the Python file.")
    parser.add_argument("-c", "--code", type=str, help="Python code as a string.")

    args = parser.parse_args()

    # Read input code
    if args.file:
        python_code = read_file(args.file)
    elif args.code:
        python_code = args.code
    else:
        print("Please provide a Python file or code input using -f or -c.")
        return

    # Generate unit tests
    unit_tests = generate_unit_tests(python_code)
    print("\nGenerated Unit Tests:\n")
    print(unit_tests)


if __name__ == "__main__":
    main()
