# Function to log resource usage
import os.path
import time
import psutil
from llama_cpp import Llama
from pyrsmi import rocml

from utilities_llm import get_block_count_keys, get_optimal_gpu_layers, setup_logger, process_streamed_output


def log_resource_usage():
    # CPU usage
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    print(f"CPU Usage: {cpu_usage}%")
    print(f"RAM Usage: {memory_info.percent}%")

    # GPU usage
    device_count = rocml.smi_get_device_count()
    for device_id in range(device_count):
        memory_used = rocml.smi_get_device_memory_used(device_id)
        memory_total = rocml.smi_get_device_memory_total(device_id)
        memory_usage_percentage = (memory_used / memory_total) * 100
        print(f"GPU {device_id} Memory Usage: {memory_usage_percentage:.2f}%")


if __name__ == "__main__":
    # Initialize ROCm SMI
    rocml.smi_initialize()

    # Set the model path
    model_path = 'models/llama-3.2-3b-instruct-q8_0.gguf'

    # Initialize the logger
    logger = setup_logger(f"test_llm_{os.path.basename(model_path)}")

    # Get the total layers from the input model
    total_layers = get_block_count_keys(model_path, logger)

    # Determine the optimal number of GPU layers to offload
    n_gpu_layers = get_optimal_gpu_layers(model_path, total_layers)

    # Initialize the Llama model with appropriate settings
    llm = Llama(
        model_path='models/llama-3.2-3b-instruct-q8_0.gguf',
        seed=42,  # Fixed seed for reproducibility
        n_ctx=4096,  # Set the desired context size here
        use_mmap=True,  # Memory mapping for efficiency
        use_mlock=True,  # Prevent swapping to disk for consistent performance
        n_gpu_layers=n_gpu_layers
    )

    # Log initial resource usage
    print("Initial Resource Usage:")
    log_resource_usage()

    # Define the system and user prompts
    system_prompt = (
        "You are an AI research assistant specializing in producing clear, concise and accurate technical "
        "documentation. Your role is to explain concepts, provide code implementations, analyze complexities and offer "
        "insights tailored to the user's requirements."
    )

    user_prompt = (
        "Write a concise implementation paper for the Floyd-Warshall algorithm, focusing on its application to "
        "undirected graphs. The paper should include a brief introduction, a Python implementation, complexity analysis"
        " and a discussion of limitations and potential optimizations specifically relevant to undirected graphs. "
        "Ensure the content is clear and accessible for readers with a basic understanding of graph algorithms."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    # Measure inference time
    start_time = time.perf_counter()
    chat_request = llm.create_chat_completion(
        messages=messages,  # system and user prompt
        temperature=0.0,
        top_p=1,
        top_k=0,
        stream=True,  # Enable streaming
        stop=["<|endoftext|>"]  # Stop generation at the end-of-text token
    )

    # Process the streamed response
    output = process_streamed_output(chat_request, logger)
    end_time = time.perf_counter()
    inference_time = end_time - start_time
    print(f"Inference Time: {inference_time:.4f} seconds")

    # Output the result
    print("Model Output:")
    print(output)  # Access the generated text from the response

    # Log resource usage after inference
    print("Resource Usage After Inference:")
    log_resource_usage()

    # Shutdown ROCm SMI
    rocml.smi_shutdown()
