import json
import logging
import os
import struct
from datetime import datetime

import pyrsmi.rocml as rocml
from bandit.core.config import BanditConfig
from bandit.core.manager import BanditManager
from bandit.formatters.text import get_metrics
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


def get_model_layers_from_gguf(file_path):
    """
    Extract the total number of layers from a GGUF model file.

    Args:
        file_path (str): Path to the GGUF model file.

    Returns:
        int: Total number of layers in the model.
    """
    try:
        with open(file_path, "rb") as f:
            # Read the file to find metadata
            file_content = f.read()

            # Search for the "llama.block_count" metadata
            block_count_key = b"llama.block_count"
            key_position = file_content.find(block_count_key)

            if key_position == -1:
                raise ValueError(f"'llama.block_count' key not found in {file_path}")

            # Move to the value position (key + 1 byte for key type + 4 bytes for length)
            value_position = key_position + len(block_count_key) + 5

            # Read the 4-byte unsigned integer (u32) for block count
            block_count = struct.unpack("I", file_content[value_position:value_position + 4])[0]

            return block_count
    except Exception as e:
        print(f"Error reading model layers: {e}")
        return None


def get_optimal_gpu_layers(model_path, safety_margin_gb=1.0):
    """
    Determines the optimal number of transformer layers to offload to the GPU
    based on available VRAM and model characteristics.

    Args:
        model_path (str): Path to the model file.
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
    model_size_bytes = os.path.getsize(model_path)
    model_size_gb = model_size_bytes / (1024 ** 3)

    # Get number of layers from model
    total_layers = get_model_layers_from_gguf(model_path)

    # Estimate VRAM usage per layer
    vram_per_layer_gb = model_size_gb / total_layers

    # Determine the number of layers that fit into usable VRAM
    optimal_layers = int(usable_vram_gb / vram_per_layer_gb)

    # Shutdown ROCm SMI
    rocml.smi_shutdown()

    return max(0, min(optimal_layers, total_layers))


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
        bandit_output_file = os.path.join(bandit_output_dir, f"bandit_single_file{name}.json")

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


# Example usage
if __name__ == "__main__":
    # Path to your model
    model_path = "models/Llama-3-11.5B-Instruct-Coder-v2-Q4_K_S.gguf"

    # Determine the optimal number of GPU layers to offload
    n_gpu_layers = get_optimal_gpu_layers(model_path)

    # Initialize the Llama model with dynamic GPU layer offloading
    llm = Llama(
        model_path=model_path,
        n_gpu_layers=n_gpu_layers,
        verbose=True  # Enable verbose output to see detailed logs
    )

    # Generate a completion
    prompt = "Write a short essay on gravity."
    output = llm(
        prompt,
        max_tokens=2048,  # Limit the number of tokens generated
        echo=True  # Include the prompt in the output
    )

    # Print the generated text
    print(output["choices"][0]["text"])
