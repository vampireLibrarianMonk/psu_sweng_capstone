# import sys
# import os
# from huggingface_hub import login
# from llama_cpp import Llama
#
# from utilities_llm import setup_logger, get_block_count_keys, get_optimal_gpu_layers
#
#
# def main():
#     if len(sys.argv) != 3:
#         print("Usage: python script.py <huggingface_token> <input_python_file>")
#         sys.exit(1)
#
#     hf_token = sys.argv[1]
#     input_file_path = sys.argv[2]
#
#     # Get and separate file name into its base name and extension
#     base_name = os.path.basename(input_file_path)
#     name, ext = os.path.splitext(base_name)
#
#     # Log in to Hugging Face
#     login(token=hf_token)
#     print("Successfully logged into Hugging Face.")
#
#     # Initialize the logger
#     logger = setup_logger(f"vulnerability_rectifier_{name}")
#
#     # Load the input Python code
#     with open(input_file_path, 'r') as file:
#         input_code = file.read()
#
#     # Specify the path to the GGUF model file
#     model_path = "models/CodeLlama-7b-Python-hf-Q5_K_M.gguf"
#
#     # Retrieve the total number of layers in the model
#     total_layers = get_block_count_keys(model_path, logger)
#
#     # Determine the optimal number of layers to offload to the GPU
#     n_gpu_layers = get_optimal_gpu_layers(model_path, total_layers)
#
#     llm = Llama(
#         model_path=model_path,
#         model_type="llama",
#         n_ctx=4096,         # Context window size
#         n_gpu_layers=n_gpu_layers,    # Number of layers to offload to GPU
#         temperature=0.0,    # Controls randomness of outputs
#         top_k=0,           # Limits next token selection to top_k tokens
#         top_p=1           # Nucleus sampling: considers tokens with top_p probability mass
#     )
#
#     # Prepare the prompt for code review
#     prompt = f"Please review and correct the following Python code:\n\n```python\n{input_code}\n```"
#
#     # Generate the refined code
#     response = llm(prompt, max_tokens=512, stop=["<|endoftext|>"])
#
#     # Extract the generated code from the response
#     refined_code = response['choices'][0]['text'].strip()
#
#     # Output the refined code
#     print("Refined Code:\n")
#     print(refined_code)
#
# if __name__ == "__main__":
#     main()


import sys
from ctransformers import AutoModelForCausalLM

from utilities_llm import get_block_count_keys, get_optimal_gpu_layers, setup_logger


def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <prompt>")
        sys.exit(1)

    prompt = sys.argv[1]

    # Initialize the logger
    logger = setup_logger(f"test_python_llama")

    # Load the CodeLlama model
    # Specify the path to the GGUF model file
    model_path = "models/CodeLlama-34b-Python-hf-Q5_K_S.gguf"

    # Retrieve the total number of layers in the model
    total_layers = get_block_count_keys(model_path, logger)

    # Determine the optimal number of layers to offload to the GPU
    n_gpu_layers = get_optimal_gpu_layers(model_path, total_layers)

    # Initialize the model with desired parameters
    llm = AutoModelForCausalLM.from_pretrained(
        model_path,
        model_type="llama",
        gpu_layers=n_gpu_layers,  # Adjust based on your GPU capabilities
        context_length=4096,  # Set context length; applicable for LLaMA models
        max_new_tokens=4096,
        temperature=0.0,  # Controls randomness of outputs
        top_k=0,  # Limits next token selection to top_k tokens
        top_p=1  # Nucleus sampling: considers tokens with top_p probability mass
    )

    # Generate text based on the prompt
    response = llm(prompt)
    print(response)

if __name__ == "__main__":
    main()
