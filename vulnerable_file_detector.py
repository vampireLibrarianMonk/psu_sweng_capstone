import os
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification

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

# Define the path to the folder containing the files
vulnerable_files_folder = "vulnerable_files"

# Load model and tokenizer
vulnerable_tokenizer, vulnerable_model = load_model_and_tokenizer()

# Iterate through each file in the folder
def analyze_directory(folder, tokenizer, model):
    # Dictionary to map file paths to analysis results
    output_map = {}

    # Recursively walk through all directories and files
    for root, _, files in os.walk(folder):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Check if the current item is a file
            if os.path.isfile(file_path):
                print(f"Analyzing file: {file_path}")

                # Read the file content
                try:
                    with open(file_path, "r") as file:
                        code_snippet = file.read()
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
                    continue

                # Analyze the code snippet
                result = analyze_code(code_snippet, tokenizer, model)

                # Map the result to YES or NO
                output_map[file_path] = "YES" if "Insecure code detected" in result else "NO"

    return output_map

# Print the map of results
print("\nAnalysis Results:")
insecure_code_map = analyze_directory(vulnerable_files_folder, vulnerable_tokenizer, vulnerable_model)
for path, status in insecure_code_map.items():
    print(f"\t{path}: {status}")