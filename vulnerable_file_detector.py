import json
import os
from bandit.core.manager import BanditManager
from bandit.core.config import BanditConfig
import torch
import numpy as np
from bandit.formatters.text import get_metrics
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from utilities import setup_logger

BANDIT_OUTPUT = "bandit"

"""
The model `mrm8488/codebert-base-finetuned-detect-insecure-code` is a fine-tuned version of CodeBERT, a pre-trained model designed for
understanding and analyzing programming languages. It is specifically trained to detect vulnerabilities in code by classifying snippets
as either secure or insecure based on learned patterns from labeled data. The model supports a variety of programming languages and
focuses on identifying potential security flaws, such as unsafe function calls, untrusted input handling, or insecure data processing.
It operates using a sequence classification approach, where the input code is tokenized and evaluated for potential risks. While this
model excels in detecting insecure patterns, it does not provide direct recommendations or fixes for the identified vulnerabilities.
It serves as a tool to flag areas of concern, complementing manual code reviews and other security practices. For more advanced workflows,
it can be integrated with generative models or static analysis tools to provide remediation suggestions.
"""

MODEL_NAME = "mrm8488/codebert-base-finetuned-detect-insecure-code"

def load_model_and_tokenizer():
    """
    Load the pre-trained model and tokenizer for detecting insecure code.

    Returns:
        tokenizer: The tokenizer for the model.
        model: The pre-trained model for insecure code detection.
    """
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    return tokenizer, model

def analyze_code(code_snippet, tokenizer, model):
    """
    Analyze a given code snippet for vulnerabilities using the pre-trained model.

    Args:
        code_snippet (str): The code snippet to analyze.
        tokenizer: The tokenizer instance.
        model: The pre-trained model instance.

    Returns:
        str: The analysis result indicating whether the code is secure or insecure.
    """
    # Tokenize the input code
    inputs = tokenizer(code_snippet, return_tensors="pt", truncation=True, padding='max_length', max_length=512)

    # Perform inference
    with torch.no_grad():
        outputs = model(**inputs)

    # Get the predicted label
    logits = outputs.logits
    predicted_label = np.argmax(logits.numpy())

    # Map the label to a human-readable result
    if predicted_label == 1:
        return "Insecure code detected. Please review and apply necessary security measures."
    else:
        return "No obvious vulnerabilities detected. However, further manual review is recommended."

def analyze_directory(folder, tokenizer, model):
    # Dictionary to map file paths to analysis results
    output_map = {}

    # Recursively walk through all directories and files
    for root, _, files in os.walk(folder):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Get and separate file name into its base name and extension
            base_name = os.path.basename(file_path)
            name, ext = os.path.splitext(base_name)

            # Check if the current item is a Python file
            if os.path.isfile(file_path) and file_path.endswith('.py'):
                logger.info(f"Analyzing file: {file_path}")

                # Read the file content
                try:
                    with open(file_path, "r") as file:
                        code_snippet = file.read()
                except Exception as e:
                    logger.error(f"Error reading file {file_path}: {e}")
                    continue

                # Analyze the code snippet
                result = analyze_code(code_snippet, tokenizer, model)

                # Map the result to YES or NO
                output_map[file_path] = "YES" if "Insecure code detected" in result else "NO"

                # Run Bandit analysis
                try:
                    # Initialize Bandit configuration and manager
                    config = BanditConfig()
                    manager = BanditManager(config, 'file', 'json')
                    manager.discover_files([file_path], True)
                    manager.run_tests()
                    issues = manager.get_issue_list()

                    # Generate a timestamped filename for the Bandit report
                    pre_folder = root.replace("/", "_")
                    bandit_output_file = os.path.join(bandit_output_dir, f"bandit_{pre_folder}_{name}.json")

                    # Write Bandit report to JSON file
                    with open(bandit_output_file, 'w') as report_file:
                        report_data = {
                            'results': [issue.as_dict() for issue in issues],
                            'metrics': get_metrics(manager),
                        }
                        json.dump(report_data, report_file, indent=4)

                    logger.info(f"Bandit report saved to: {bandit_output_file}")
                except Exception as e:
                    logger.error(f"Bandit analysis failed for {file_path}: {e}")

    return output_map

def analyze_file_with_bandit(file_path):
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


bandit_output_dir = "bandit_reports"
os.makedirs(bandit_output_dir, exist_ok=True)

# Define the path to the folder containing the files
vulnerable_files_folder = "mitigated_files"

# Initialize the logger
logger = setup_logger(f"vulnerability_detector")

# Load model and tokenizer
vulnerable_tokenizer, vulnerable_model = load_model_and_tokenizer()

# Print the map of results
logger.info("\nAnalysis Results:")
insecure_code_map = analyze_directory(vulnerable_files_folder, vulnerable_tokenizer, vulnerable_model)
for path, status in insecure_code_map.items():
    logger.info(f"\t{path}: {status}")