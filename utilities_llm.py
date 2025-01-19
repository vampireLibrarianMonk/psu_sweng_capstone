import argparse
import ast
import json
import logging
import os
import re
import subprocess
from datetime import datetime

import autoimport
import pyrsmi.rocml as rocml
import stdlib_list
from bandit.core.config import BanditConfig
from bandit.core.manager import BanditManager
from bandit.formatters.text import get_metrics
from dodgy.checks import check_file_contents
from gguf_parser import GGUFParser
from llama_cpp import Llama

bandit_output_dir = "reports/bandit"
os.makedirs(bandit_output_dir, exist_ok=True)

dodgy_output_dir = "reports/dodgy"
os.makedirs(dodgy_output_dir, exist_ok=True)

semgrep_output_dir = "reports/semgrep"
os.makedirs(semgrep_output_dir, exist_ok=True)


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


def parse_python_script(file_path):
    """
    Parses a Python script to extract and categorize its components into variables,
    methods, and the main script block. It associates instances like 'app' with the
    main script if they're used within the `if __name__ == '__main__':` block and
    ensures they're not included in methods that do not reference them.

    Args:
        file_path (str): The path to the Python script file to be parsed.

    Returns:
        dict: A dictionary with keys 'global_variables', 'methods', and 'main_script'.
              - 'global_variables' maps to a string containing all variable assignments not used in methods.
              - 'methods' maps to a dictionary where keys are function names and values are their code.
              - 'main_script' maps to a string containing the code within the `if __name__ == '__main__':` block.
    """
    parsed_script = {
        'global_variables': '',
        'methods': {},
        'main_script': ''
    }

    with open(file_path, 'r') as file:
        script = file.read()

    tree = ast.parse(script)

    def get_source_segment(node):
        return ast.get_source_segment(script, node) or ''

    # Step 1: Identify global variables and imports
    global_vars = {}
    import_statements = []
    instance_assignments = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    global_vars[target.id] = get_source_segment(node)
                    # Track instances created by calling a class (e.g., app = Flask(__name__))
                    if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                        instance_assignments[target.id] = node.value.func.id
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            import_statements.append((node, get_source_segment(node)))

    # Step 2: Determine usage in functions and main script
    def is_name_used_in_node(name, target_node):
        class NameUsageVisitor(ast.NodeVisitor):
            def __init__(self):
                self.used = False

            def visit_Name(self, node):
                if node.id == name:
                    self.used = True
                self.generic_visit(node)

        visitor = NameUsageVisitor()
        visitor.visit(target_node)
        return visitor.used

    used_global_vars = set()
    used_imports = set()

    # Step 3: Include relevant globals and imports in function code
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            method_name = node.name
            method_code = get_source_segment(node)
            # Include decorators and preceding comments
            start_lineno = node.lineno - 1
            while start_lineno > 0:
                line = script.splitlines()[start_lineno - 1].strip()
                if line.startswith('@') or line.startswith('#'):
                    method_code = line + '\n' + method_code
                    start_lineno -= 1
                else:
                    break
            # Add relevant global variables
            for var_name, var_code in global_vars.items():
                if is_name_used_in_node(var_name, node):
                    method_code = var_code + '\n' + method_code
                    used_global_vars.add(var_name)
            # Add relevant import statements
            for imp_node, imp_code in import_statements:
                if isinstance(imp_node, ast.Import):
                    for alias in imp_node.names:
                        if is_name_used_in_node(alias.name, node):
                            method_code = imp_code + '\n' + method_code
                            used_imports.add(imp_code)
                elif isinstance(imp_node, ast.ImportFrom):
                    module = imp_node.module
                    for alias in imp_node.names:
                        if is_name_used_in_node(alias.name, node):
                            method_code = imp_code + '\n' + method_code
                            used_imports.add(imp_code)
            parsed_script['methods'][method_name] = method_code
        elif isinstance(node, ast.If) and '__main__' in get_source_segment(node):
            main_script_code = get_source_segment(node)
            # Add instances used in the main script
            for instance_name, class_name in instance_assignments.items():
                if is_name_used_in_node(instance_name, node):
                    main_script_code = global_vars[instance_name] + '\n' + main_script_code
                    used_global_vars.add(instance_name)
            parsed_script['main_script'] = main_script_code

    # Step 4: Collect unused global variables and imports
    unused_globals = [code for name, code in global_vars.items() if name not in used_global_vars]
    unused_imports = [code for _, code in import_statements if code not in used_imports]

    parsed_script['global_variables'] = '\n'.join(unused_imports + unused_globals).strip()

    return parsed_script


def organize_imports_and_globals(file_path):
    """
    Reads a Python file, organizes and deduplicates its import statements and global variables,
    detects instance creation assignments, and moves them to the top of the file.

    :param file_path: Path to the Python file to be processed.
    """

    def process_import_nodes(import_nodes):
        """
        Processes AST import nodes to deduplicate and organize them.

        :param import_nodes: List of import-related AST nodes.
        :return: String of organized import statements.
        """
        import_dict = {}
        for node in import_nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    import_dict.setdefault(None, set()).add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                if module not in import_dict:
                    import_dict[module] = set()
                import_dict[module].update(alias.name for alias in node.names)

        # Deduplicate and sort imports
        import_strings = []

        # Handle plain `import ...` statements (key=None)
        if None in import_dict:
            for name in sorted(import_dict.pop(None)):
                import_strings.append(f"import {name}")

        # Handle `from ... import ...` statements
        for module, names in sorted(import_dict.items()):
            sorted_names = ", ".join(sorted(names))
            import_strings.append(f"from {module} import {sorted_names}")

        # Group imports into standard library, third-party, and local
        std_lib_imports, third_party_imports, local_imports = group_imports(import_strings)

        # Combine organized imports
        organized_imports = "\n".join(
            std_lib_imports + [""] +
            third_party_imports + [""] +
            local_imports
        )
        return organized_imports.strip()  # Remove extra spaces

    def group_imports(import_strings):
        """
        Groups imports into standard library, third-party, and local imports.

        :param import_strings: List of import statements as strings.
        :return: Tuple of grouped imports (std_lib, third_party, local).
        """
        std_lib_modules = set(stdlib_list.stdlib_list("3.10"))  # Adjust for Python 3.10

        std_lib = []
        third_party = []
        local = []

        for imp in import_strings:
            if any(imp.startswith(f"import {mod}") or imp.startswith(f"from {mod}") for mod in std_lib_modules):
                std_lib.append(imp)
            elif imp.startswith("from .") or imp.startswith("import ."):
                local.append(imp)
            else:
                third_party.append(imp)

        return sorted(std_lib), sorted(third_party), sorted(local)

    with open(file_path, 'r') as file:
        source_code = file.read()

    # Parse the source code into an AST
    tree = ast.parse(source_code)
    import_statements = []
    global_variables = {}
    instance_creations = set()  # Use a set to prevent duplication
    other_code = []

    # Extract import statements, global variables, instance creations, and other code
    for node in tree.body:
        node_source = ast.get_source_segment(source_code, node)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_statements.append(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id.isupper():
                        # Handle global constants
                        global_variables[target.id] = node
                    elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                        # General pattern: variable = ClassName(argument)
                        class_name = node.value.func.id
                        if len(node.value.args) == 1 and isinstance(node.value.args[0], ast.Name):
                            argument_name = node.value.args[0].id
                            # Store the instance creation details as a tuple
                            instance_creation = (
                                target.id,
                                class_name,
                                argument_name,
                                node_source
                            )
                            instance_creations.add(instance_creation)
                        else:
                            other_code.append(node)
                    else:
                        other_code.append(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            # Preserve top-level docstrings or other expressions
            other_code.append(node)
        else:
            other_code.append(node)

    # Deduplicate and organize imports
    organized_imports = process_import_nodes(import_statements)

    # Generate global variables section
    global_variables_code = "\n".join(ast.unparse(node) for node in global_variables.values())

    # Generate instance creations section
    instance_creations_code = "\n".join(ic[3] for ic in instance_creations)

    # Generate remaining code
    other_code_source = ast.unparse(ast.Module(body=other_code, type_ignores=[]))

    # Combine sections into the final source code
    new_source_code = f"{organized_imports}\n\n{global_variables_code}\n\n{instance_creations_code}\n\n{other_code_source}"

    return new_source_code


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
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        bandit_output_file = os.path.join(bandit_output_dir, f"{timestamp}_bandit_single_file_{name}.json")

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


def get_bandit_issues(input_bandit_file):
    # Open and read the JSON file
    with open(input_bandit_file, 'r') as file:
        data = json.load(file)

    # Map test_id to (line_number, line_range, issue_text)
    test_id_mapping_with_range = {
        result["test_id"]: (result["line_number"], result["line_range"], result["issue_text"])
        for result in data["results"]
    }

    # Construct Bandit issues for user prompt
    bandit_issues = "\n".join(
        f"- Test ID: {test_id}, Line: {details[0]}, Line Range: {details[1]}, Issue: {details[2]}"
        for test_id, details in test_id_mapping_with_range.items()
    )

    return bandit_issues


def analyze_file_with_dodgy(file_path, logger):
    """
    Analyzes a single file using Dodgy and saves the results to a JSON report.

    Args:
        file_path (str): The path to the file to analyze.
        logger (logging.Logger): Logger instance for logging information.

    Returns:
        str: The path to the Dodgy report JSON file, or None if the analysis failed.
    """
    # Extract the file name for report generation
    base_name = os.path.basename(file_path)
    name, _ = os.path.splitext(base_name)

    timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    dodgy_output_file = os.path.join(dodgy_output_dir, f"{timestamp}_dodgy_single_file_{name}.json")

    try:
        # Read file contents
        with open(file_path, 'r') as file:
            file_contents = file.read()

        # Run Dodgy checks on the file contents
        issues = check_file_contents(file_contents)

        # Prepare the report data
        report_data = {
            "file": file_path,
            "issues": [
                {
                    "line_number": issue[0],
                    "variable_name": issue[1],
                    "reason": issue[2]
                }
                for issue in issues
            ]
        }

        # Save the report data to a JSON file
        with open(dodgy_output_file, "w") as report_file:
            json.dump(report_data, report_file, indent=4)

        logger.info(f"Dodgy report saved to: {dodgy_output_file}")
        return dodgy_output_file

    except Exception as e:
        logger.error(f"An error occurred while analyzing {file_path} with Dodgy: {e}")
        return None


def get_dodgy_issues(input_dodgy_file):
    """
    Reads a Dodgy JSON report and formats the issues into a user-friendly string.

    Args:
        input_dodgy_file (str): Path to the Dodgy JSON report file.

    Returns:
        str: A formatted string of Dodgy issues.
    """
    # Open and read the JSON file
    with open(input_dodgy_file, 'r') as file:
        data = json.load(file)

    # Extract issues from the JSON data
    dodgy_issues = [
        f"- Line: {issue['line_number']}, Variable: {issue['variable_name']}, Reason: {issue['reason']}"
        for issue in data.get("issues", [])
    ]

    # Join all issues into a single formatted string
    return "\n".join(dodgy_issues) if dodgy_issues else "No issues found."


def analyze_file_with_semgrep(file_path, extracted_libraries, logger):
    """
    Analyzes a Python file using Semgrep and saves a standardized report in JSON format.

    Args:
        file_path (str): Path to the Python file to analyze.
        extracted_libraries (list): List of libraries used in the Python file.
        logger (logging.Logger): Logger object for logging information and errors.

    Returns:
        str: Path to the standardized Semgrep report file, or None if analysis failed.
    """
    base_name = os.path.basename(file_path)
    name, _ = os.path.splitext(base_name)

    try:
        os.makedirs(semgrep_output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        semgrep_output_file = os.path.join(semgrep_output_dir, f"{timestamp}_semgrep_report_{name}.json")

        # Define Semgrep configurations to run
        semgrep_configs = [
            ('p/default', 'result_default'),
            ('p/owasp-top-ten', 'result_owasp_top_ten'),
            ('p/python', 'result_python')
        ]

        # Add framework-specific rules if relevant libraries are detected
        if 'django' in extracted_libraries:
            semgrep_configs.append(('p/django', 'result_django'))
        if 'flask' in extracted_libraries:
            semgrep_configs.append(('p/flask', 'result_flask'))

        all_findings = []

        # Run Semgrep analyses
        for config, result_var in semgrep_configs:
            result = subprocess.run(
                ['semgrep', '--config', config, '--json', file_path, '--metrics', 'off'],
                check=True,
                capture_output=True,
                text=True
            )
            # Parse JSON output
            result_json = json.loads(result.stdout)
            # Extract relevant information
            for finding in result_json.get('results', []):
                standardized_finding = {
                    'line': finding.get('start', {}).get('line'),
                    'message': finding.get('extra', {}).get('message'),
                    'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                    'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', [])
                }
                if standardized_finding not in all_findings:  # Avoid duplicate entries
                    all_findings.append(standardized_finding)

        # Write standardized report to JSON file
        with open(semgrep_output_file, 'w') as report_file:
            json.dump(all_findings, report_file, indent=4)

        logger.info(f"Semgrep report saved to: {semgrep_output_file}")
        return semgrep_output_file

    except subprocess.CalledProcessError as e:
        logger.error(f"Semgrep analysis failed for {file_path}: {e.stderr}")
        return None
    except Exception as e:
        logger.error(f"An error occurred during Semgrep analysis for {file_path}: {e}")
        return None


def get_semgrep_issues(input_semgrep_file):
    """
    Reads a Semgrep JSON report and formats the issues into a user-friendly string.

    Args:
        input_semgrep_file (str): Path to the Semgrep JSON report file.

    Returns:
        str: A formatted string of Semgrep issues.
    """
    try:
        # Open and read the JSON file
        with open(input_semgrep_file, 'r') as file:
            data = json.load(file)

        # Extract issues from the JSON data
        semgrep_issues = []
        for result in data:
            line = result.get('line', 'N/A')
            message = result.get('message', 'N/A')
            owasp = result.get('owasp', [])
            cwe = result.get('cwe', [])

            # Format OWASP and CWE references
            owasp_str = ', '.join(owasp) if owasp else 'None'
            cwe_str = ', '.join(cwe) if cwe else 'None'

            # Create a formatted issue string
            issue_str = (
                f"  Line: {line}\n"
                f"  Message: {message}\n"
                f"  OWASP: {owasp_str}\n"
                f"  CWE: {cwe_str}\n"
            )
            semgrep_issues.append(issue_str)

        # Join all issues into a single formatted string
        return "\n".join(semgrep_issues) if semgrep_issues else "No issues found."
    except Exception as e:
        return f"An error occurred while reading Semgrep issues: {e}"


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


def extract_code_block(text):
    """
    Extracts the first Python code block from the given text.

    Args:
        text (str): The input text containing code blocks.

    Returns:
        str: The extracted code block, or None if no code block is found.
    """
    match = re.search(r'```python\n(.*?)```', text, re.DOTALL)
    return match.group(1) if match else None


def extract_secure_implementation_title(text):
    pattern = r"\*\*Secure Implementation Title:?\*\*:?(.*?)\n"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip().replace("\n", "") if match else None


def extract_secure_implementation_statement(text):
    pattern = r"\*\*Secure Implementation Statement:?\*\*:?(.*?)\n+"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip().replace("\n", "") if match else None


def extract_secure_implementation_explanation_statement(text):
    pattern = r"\*\*Secure Code Implementation Statement:?\*\*:?(.*)\n*"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip().replace("\n", "") if match else None


def process_streamed_output(response, print_stream=False):
    """
    Processes the streamed output chunk by chunk.

    Args:
        response (iterator): An iterator yielding chunks of response content.
        logger: Logger object
        print_stream: Boolean for printing what is in the stream as it goes.

    Returns:
        str: The complete output from the stream.
    """
    complete_output = ""
    for chunk in response:
        content = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
        if print_stream:
            print(content, end="", flush=True)  # Print in real-time, do not using logging!
        complete_output += content
    if print_stream:
        print("\n")  # Ensure a new line after the streamed output, do not using logging!
    return complete_output


def run_mitigation_loop(
        bandit_allowance,
        base_name,
        llm,
        logger,
        mitigated_folder,
        mitigated_base_name,
        original_code,
        section):

    # Set initial and maximum temperature values
    initial_temperature = 0.0
    max_temperature = 2.0

    # Calculate increment per iteration
    temperature_increment = (max_temperature - initial_temperature) / bandit_allowance

    # Define initial constraints based on the current mitigated code
    initial_line_count = len(original_code.split("\n"))
    initial_word_count = len(original_code.split())

    # Load the module substitution JSON file
    with open('substitution/module.json', 'r') as file:
        module_associations = json.load(file)
        if not isinstance(module_associations, dict):
            raise ValueError("The loaded substitutions JSON data is not a dictionary.")

    iteration = 0
    name, ext = os.path.splitext(base_name)
    mitigated_file_name = f"{mitigated_base_name}_iteration_{section}_{iteration}{ext}"
    mitigated_file_path = os.path.join(mitigated_folder, mitigated_file_name)
    save_code_to_file(original_code, mitigated_file_path, logger)

    # Perform Vulnerability Scans
    # Static Code Analysis
    # Bandit is a static analysis tool designed to deeply inspect Python code for security issues.
    # It focuses on detecting vulnerabilities at the code level, such as the use of unsafe functions
    # (e.g., eval, exec), insecure cryptographic practices and code injection risks.
    bandit_scan_json_path = analyze_file_with_bandit(mitigated_file_path, logger)
    bandit_issues = get_bandit_issues(bandit_scan_json_path)

    # Dodgy is a lightweight security tool that complements Bandit by focusing on file-level issues.
    # It scans for hardcoded secrets (e.g., API keys, passwords), suspicious filenames (e.g., *.pem, id_rsa),
    # and insecure file paths (e.g., /tmp directories).
    dodgy_scan_json_path = analyze_file_with_dodgy(mitigated_file_path, logger)
    dodgy_issues = get_dodgy_issues(dodgy_scan_json_path)

    # Semgrep
    # Get libraries so the rulesets below (django and flask) can use them if they exist
    extracted_libraries = extract_libraries(original_code)

    # A lightweight static analysis tool that scans code for security vulnerabilities and enforces coding standards.
    # It offers customizable rules and supports taint analysis to track untrusted data through your codebase.
    semgrep_scan_json_path = analyze_file_with_semgrep(mitigated_file_path, extracted_libraries, logger)
    semgrep_issues = get_semgrep_issues(semgrep_scan_json_path)

    # Dependencies Scans
    # Safety
    # Focuses on identifying known security vulnerabilities in your project's dependencies by scanning requirements.txt
    # files. It cross-references your dependencies against a curated database of insecure packages to alert you to
    # potential risks.

    # Data Flow
    # Python Taint (PyT)
    #  A static analysis tool designed to detect security vulnerabilities in Python code by tracking the flow of tainted
    #  (untrusted) data to sensitive functions. It helps identify potential injection points and data leaks.

    logger.info(f"Running an iteration series of {bandit_allowance}.")
    while iteration < bandit_allowance:
        logger.info(f"{'-' * 35} Running iteration {iteration} {'-' * 35}")

        # Read the specified file
        try:
            mitigated_file_name = f"{mitigated_base_name}_iteration_{section}_{iteration}{ext}"
            mitigated_file_path = os.path.join(mitigated_folder, mitigated_file_name)
            with open(mitigated_file_path, 'r') as file:
                mitigated_code = file.read()
                logger.info(f"Successfully read file: {mitigated_file_path}")
        except FileNotFoundError:
            logger.error(f"The file '{mitigated_file_path}' was not found.")
            exit(1)
        except IOError as e:
            logger.error(f"An error occurred while reading the file '{mitigated_file_path}': {e}")
            exit(1)

        # Define the system and user prompts
        system_prompt = (
            "You are an AI programming assistant specializing in secure coding practices."
        )

        # Calculate increments per iteration
        line_count_increment = initial_line_count * 0.5 / bandit_allowance
        word_count_increment = initial_word_count * 0.5 / bandit_allowance

        # Adjust constraints dynamically based on the current iteration
        line_count = int(initial_line_count * 1.1 + line_count_increment * iteration)
        word_count = int(initial_word_count * 1.2 + word_count_increment * iteration)

        # Extract the libraries from the mitigated code
        extracted_libraries = extract_libraries(mitigated_code)

        # Filter the module.json dictionary
        suggestion_map = {key: value for key, value in module_associations.items() if key in mitigated_code}

        # Construct the substitution part of the code prompt
        if suggestion_map:
            substitution_statements = '\n'.join(
                [f"\t* For '{vuln_module}', {guidance}" for vuln_module, guidance in suggestion_map.items()]
            )
            substitution_code_instruction = (
                f"Please modify the code below strictly according to the provided instructions. Address only the "
                f"specific issues mentioned in the following substitution statements as they pertain to the code below,"
                f" without adding or assuming anything beyond what is explicitly stated:\n"
                f"{substitution_statements}\n"
            )
        else:
            substitution_code_instruction = ""

        # Construct the complete prompt
        bandit_issues_section = (f"Bandit has identified the following issues"
                                 f" in the provided Python code:\n{bandit_issues}\n\n") \
            if bandit_issues != "" else ""

        dodgy_issues_section = (f"Dodgy has identified the following issues"
                                f" in the provided Python code:\n{dodgy_issues}\n\n") \
            if dodgy_issues != "No issues found." else ""

        semgrep_issues_section = (f"Semgrep has identified the following issues"
                                  f" in the provided Python code:\n{semgrep_issues}\n\n") \
            if semgrep_issues != "No issues found." else ""

        code_prompt = (
            f"Ensure that all recommendations adhere to best security practices.\n"
            f"{bandit_issues_section}"
            f"{dodgy_issues_section}"
            f"{semgrep_issues_section}"
            f'Never hard code any credentials, keys, or other sensitive data. Always retrieve sensitive information securely from '
            f'environment variables, configuration files, or external services. Avoid embedding sensitive data directly in strings, '
            f'commands, or code logic that could expose them. When working with tools like SSH for automation, use methods such as '
            f'passing sensitive data through environment variables (e.g., using "sshpass --env" to reference an environment variable for a password) '
            f'to prevent exposure in command-line arguments. Ensure that temporary sensitive data is cleared from memory or the environment '
            f'immediately after use to minimize risks. Additionally, avoid using variable names containing "password" or similar terms for storing sensitive data.\n'
            f"them in command-line arguments.\n\n"
            f"{substitution_code_instruction}\n"
            f"Ensure the code does not exceed {word_count} words.\n"
            f"Ensure the code does not exceed {line_count} lines.\n\n"
            f"Only include the code, along with appropriate docstrings and inline comments:\n\n"
            f"```python\n{mitigated_code}\n```"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": code_prompt}
        ]

        # Adjust temperature to control randomness; increase to make output more diverse
        temperature = round(min(max_temperature, initial_temperature + temperature_increment * iteration), 2)

        # Generate code with adjusted parameters
        """
        Parameters for adjustment
        ----------
        temperature : float, optional
            Controls the randomness of the output, with a range from 0 to 2. Lower values (e.g., 0.2) produce more 
            focused and deterministic responses, while higher values (e.g., 0.8) yield more varied and creative outputs.
             It is generally recommended to adjust either `temperature` or `top_p`, but not both simultaneously. 

        top_p : float, optional
            Also known as nucleus sampling, this parameter ranges from 0 to 1 and determines the diversity of the output
             by considering only the tokens that comprise the top `p` probability mass. For instance, a `top_p` of 0.1 
             means only the tokens within the top 10% probability mass are considered. Adjusting `top_p` can influence 
             the creativity of the response, with lower values leading to more focused outputs.

        top_k : int, optional
            Limits the next token selection to the top `k` tokens with the highest probabilities. Setting `top_k` to 0 
            effectively disables this filtering, allowing the model to consider all possible tokens. Adjusting `top_k` 
            can control the diversity of the output, with lower values leading to more focused and deterministic 
            responses.
        """
        logger.info(f"Using an adjusted temperature of {temperature}.")
        adjusted_code_response = llm.create_chat_completion(
            messages=messages,  # system and user prompt
            temperature=temperature,
            top_p=1,
            top_k=0,
            stream=True,  # Enable streaming
            stop=["<|endoftext|>"]  # Stop generation at the end-of-text token
        )

        # Process the streamed response
        adjusted_code_block = process_streamed_output(adjusted_code_response)
        logger.info("Secure code generation completed.")

        # Extract the code block from the secure code suggestion
        code_block = extract_code_block(adjusted_code_block)

        if code_block:
            name, ext = os.path.splitext(base_name)
            iteration += 1
            mitigated_file_name = f"{mitigated_base_name}_iteration_{section}_{iteration}{ext}"
            mitigated_file_path = os.path.join(mitigated_folder, mitigated_file_name)
            logger.info(f"Applied autoimport to {mitigated_file_path}; imports have been updated.")
            fixed_code = autoimport.fix_code(code_block)
            logger.info(f"Saving code to file {mitigated_file_path}.")
            save_code_to_file(fixed_code, mitigated_file_path, logger)
        else:
            logger.warning("No adjusted code block found in the secure code suggestion. Stopping to diagnose issue.")
            break

        # Perform scans again
        logger.info(f"Performing scans on {mitigated_file_path}")
        bandit_scan_json_path = analyze_file_with_bandit(mitigated_file_path, logger)
        bandit_issues = get_bandit_issues(bandit_scan_json_path)

        dodgy_scan_json_path = analyze_file_with_dodgy(mitigated_file_path, logger)
        dodgy_issues = get_dodgy_issues(dodgy_scan_json_path)

        semgrep_scan_json_path = analyze_file_with_semgrep(mitigated_file_path, extracted_libraries, logger)
        semgrep_issues = get_semgrep_issues(semgrep_scan_json_path)

        if bandit_issues == '' and dodgy_issues == 'No issues found.' and semgrep_issues == 'No issues found.':
            return code_block

def save_code_to_file(code, path, logger):
    """
    Saves the given code to a specified file.

    Args:
        code (str): The code to be saved.
        path (str): The path to save the code in.
        logger (Logger): Logging object.
    """
    with open(path, 'w') as file_io:
        file_io.write(code)
    logger.info(f"Code saved to file: {path}")

def write_to_file(file_path, content):
    """Helper function to write content to a file."""
    with open(file_path, 'w') as file:
        file.write(content)

def test_llm():
    # Initialize the logger
    logger_main = setup_logger(f"utilities_test")

    # Path to your model
    model_path = "models/llama-3.2-3b-instruct-q8_0.gguf"

    total_layers = get_block_count_keys(model_path, logger_main)

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
    logger_main.info(output["choices"][0]["text"])


# Example usage
if __name__ == "__main__":
    # Leave blank for testing methods within utilities
    test_llm()
