import json
import logging
import os
import re
import struct
from datetime import datetime

import argparse
import pyrsmi.rocml as rocml
from bandit.core.config import BanditConfig
from bandit.core.manager import BanditManager
from bandit.formatters.text import get_metrics
from gguf_parser import GGUFParser
from llama_cpp import Llama

bandit_output_dir = "bandit_reports"


def setup_logger(log_suffix="log"):
    """
    Set up a logger that writes logs to a file with a timestamped filename.

    Args:
        log_suffix (str): A custom suffix for the log file name to differentiate logs.

    Returns:
        logging.Logger: Configured logger instance.
    """
    # Create the 'logs' folder if it doesn't exist
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)

    # Generate a filename with a datetime group and custom suffix
    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    log_filename = os.path.join(log_folder, f"{timestamp}_{log_suffix}.log")

    # Create and configure the logger
    logger = logging.getLogger(f"CustomLogger_{log_suffix}")
    logger.setLevel(logging.DEBUG)  # Set the logging level

    # Create file handler to write logs to the file
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)

    # Create console handler to output logs to the console (optional)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Define the log format
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_optimal_gpu_layers(input_model_path, input_total_layers, safety_margin_gb=4.0):
    """
    Determines the optimal number of transformer layers to offload to the GPU
    based on available VRAM and model characteristics.

    Args:
        input_model_path (str): Path to the model file.
        input_total_layers (int): Total number of layers found in model.
        safety_margin_gb (float): VRAM to reserve for system processes.

    Returns:
        int: Optimal number of layers to offload.
    """
    # Initialize ROCm SMI
    rocml.smi_initialize()

    # Get available VRAM for the first GPU (index 0)
    device_id = 0
    vram_total = rocml.smi_get_device_memory_total(device_id)
    vram_used = rocml.smi_get_device_memory_used(device_id)
    free_vram_gb = (vram_total - vram_used) / (1024 ** 3)

    # Calculate usable VRAM
    usable_vram_gb = max(0, free_vram_gb - safety_margin_gb)

    # Determine the model size in gigabytes
    model_size_bytes = os.path.getsize(input_model_path)
    model_size_gb = model_size_bytes / (1024 ** 3)

    # Estimate VRAM usage per layer
    vram_per_layer_gb = model_size_gb / input_total_layers

    # Determine the number of layers that fit into usable VRAM
    optimal_layers = int(usable_vram_gb / vram_per_layer_gb)

    # Shutdown ROCm SMI
    rocml.smi_shutdown()

    return max(0, min(optimal_layers, input_total_layers))


def get_rocm_smi_methods():
    # Initialize ROCm SMI
    rocml.smi_initialize()

    # List all attributes and methods in the rocml module
    attributes = dir(rocml)
    for attribute in attributes:
        print(attribute)

    # Shutdown ROCm SMI
    rocml.smi_shutdown()


def analyze_file_with_bandit(file_path, logger):
    # Get and separate file name into its base name and extension
    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)

    # Run Bandit analysis
    try:
        # Initialize Bandit configuration and manager
        config = BanditConfig()
        manager = BanditManager(config, 'file', 'json')
        manager.discover_files([file_path], True)
        manager.run_tests()
        issues = manager.get_issue_list()

        # Generate a timestamped filename for the Bandit report
        bandit_output_file = os.path.join(bandit_output_dir, f"bandit_single_file_{name}.json")

        # Write Bandit report to JSON file
        with open(bandit_output_file, 'w') as report_file:
            report_data = {
                'results': [issue.as_dict() for issue in issues],
                'metrics': get_metrics(manager),
            }
            json.dump(report_data, report_file, indent=4)

        logger.info(f"Bandit report saved to: {bandit_output_file}")
        return bandit_output_file
    except Exception as e:
        logger.error(f"Bandit analysis failed for {file_path}: {e}")

def get_block_count_keys(input_model_path, input_logger):
    """
    Extracts metadata keys containing 'block_count' from a GGUF model file.
    If only one such key is found, returns that key; otherwise, returns None.

    Args:
        input_model_path (str): Path to the GGUF model file.
        input_logger (Logger): Logging object.

    Returns:
        str or None: The matching key if exactly one is found; otherwise, None.
    """
    # Initialize the GGUF parser
    parser = GGUFParser(input_model_path)

    # Parse the GGUF file
    parser.parse()

    # Access the metadata
    metadata = parser.metadata

    # Filter keys containing 'block_count'
    matching_keys = [key for key in metadata if 'block_count' in key]

    # Print matching keys
    input_logger.info(f"Metadata keys containing 'block_count' in {input_model_path}:")
    for key in matching_keys:
        input_logger.info(f"{key}: {metadata[key]}")

    # Return the key if exactly one match is found
    if len(matching_keys) == 1:
        key_found = matching_keys[0]
        block_count = metadata[key_found]
        input_logger.info(f"Returning the block count {block_count} (aka total_layers) found for {key_found}")
        return int(block_count)
    else:
        raise Exception(f"Returning the keys found: {matching_keys}.")

def validate_bandit_allowance(value):
    """
    Validates that the provided bandit_allowance is a positive integer.

    Args:
        value (str): The input value to validate.

    Returns:
        int: The validated positive integer.

    Raises:
        argparse.ArgumentTypeError: If the input is not a positive integer.
    """
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid value '{value}'. bandit_allowance must be a positive integer.")
    return ivalue

def extract_module_names(text):
    """
    Extracts module names from a given text based on the pattern '<module_name> module'.

    Args:
        text (str): The input text containing module references.

    Returns:
        list: A list of extracted module names. If no module names are found, returns ['vulnerable module'].
    """
    # Regular expression to match '<module_name> module'
    pattern = r'\b(\w+)\s+module\b'
    # Find all matches in the text
    matches = re.findall(pattern, text)
    # Return matches if found; otherwise, return a generic placeholder
    return matches

def extract_libraries(mitigated_code):
    # Regular expression to match import and from statements
    pattern = r'^\s*(?:import\s+([\w\.]+)|from\s+([\w\.]+)\s+import\s+)'

    # Find all matches in the code string
    matches = re.findall(pattern, mitigated_code, re.MULTILINE)

    # Extract and combine the matched groups
    libraries = [lib for match in matches for lib in match if lib]

    return libraries

# Example usage
if __name__ == "__main__":
    # Initialize the logger
    logger = setup_logger(f"utilities_test")

    # Path to your model
    model_path = "models/llama-3.2-3b-instruct-q8_0.gguf"

    total_layers = get_block_count_keys(model_path, logger)

    # Determine the optimal number of GPU layers to offload
    n_gpu_layers = get_optimal_gpu_layers(model_path, total_layers)

    # Initialize the Llama model with dynamic GPU layer offloading
    llm = Llama(
        model_path=model_path,
        n_gpu_layers=n_gpu_layers,
        n_ctx=4096,  # Set the desired context size here
        verbose=True  # Enable verbose output to see detailed logs
    )

    # Generate a completion
    prompt = "Write a sample python script in 50 words or less."
    output = llm(
        prompt,
        max_tokens=2048,  # Limit the number of tokens generated
        echo=True  # Include the prompt in the output
    )

    # Print the generated text
    logger.info(output["choices"][0]["text"])
