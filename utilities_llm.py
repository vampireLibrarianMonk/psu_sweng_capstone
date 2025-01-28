import argparse
import ast
import json
import logging
import os
import re
import subprocess
import sys
import tokenize
import traceback
from io import StringIO
from typing import List, Tuple, Optional

import autoimport
import autopep8
import pyrsmi.rocml as rocml
import stdlib_list
from bandit.core.config import BanditConfig
from bandit.core.manager import BanditManager
from bandit.formatters.text import get_metrics
from dodgy.checks import check_file_contents
from gguf_parser import GGUFParser
from llama_cpp import Llama
from mypy import api
from vulture import Vulture

bandit_output_dir = "reports/bandit"
os.makedirs(bandit_output_dir, exist_ok=True)

dodgy_output_dir = "reports/dodgy"
os.makedirs(dodgy_output_dir, exist_ok=True)

semgrep_output_dir = "reports/semgrep"
os.makedirs(semgrep_output_dir, exist_ok=True)

mypy_output_dir = "reports/mypy"
os.makedirs(mypy_output_dir, exist_ok=True)

vulture_output_dir = "reports/vulture"
os.makedirs(vulture_output_dir, exist_ok=True)


def setup_logger(log_suffix, letter_conversion, name):
    """
    Set up a logger that writes logs to a file with a timestamped filename.

    Args:
        name: Name of operation being run.
        letter_conversion: Number converted to excel column letter.
        log_suffix (str): A custom suffix for the log file name to differentiate logs.

    Returns:
        logging.Logger: Configured logger instance.
    """
    # Create the 'logs' folder if it doesn't exist
    log_folder = "logs"

    # Generate a filename with a datetime group and custom suffix
    log_filepath = os.path.join(log_folder, log_suffix, name, letter_conversion, "main.log")

    # Create the base log directory
    os.makedirs(os.path.dirname(log_filepath), exist_ok=True)

    # Create and configure the logger
    logger = logging.getLogger(f"CustomLogger_{log_suffix}")
    logger.setLevel(logging.DEBUG)  # Set the logging level

    # Create file handler to write logs to the file
    file_handler = logging.FileHandler(log_filepath)
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


def count_directories_in_path(directory):
    """
    Counts the number of directories in the specified path.

    :param directory: The path to the directory where subdirectories are counted.
    :return: The count of subdirectories in the specified path.
    """
    count = 0
    try:
        # Iterate over all items in the specified directory
        for item in os.listdir(directory):
            # Check if the item is a directory
            if os.path.isdir(os.path.join(directory, item)):
                count += 1
    except FileNotFoundError:
        print(f"The directory {directory} does not exist.")
    except PermissionError:
        print(f"Permission denied to access {directory}.")
    return count


def number_to_excel_column(n):
    """
    Convert a zero-based index to an Excel-style column name.

    :param n: Zero-based index (e.g., 0 corresponds to 'A')
    :return: Corresponding Excel-style column name as a string
    """
    result = []
    while n >= 0:
        n, remainder = divmod(n, 26)
        result.append(chr(remainder + ord('A')))
        n -= 1
    return ''.join(reversed(result))


def prepend_to_file(file_path, content_to_prepend):
    # Read the existing content of the file
    with open(file_path, 'r') as file:
        existing_content = file.read()

    # Write the new content followed by the existing content
    if content_to_prepend not in existing_content:
        with open(file_path, 'w') as file:
            file.write(content_to_prepend)
            file.write(existing_content)


def rename_file(current_file_name, new_file_name):
    """
    Rename a file from current_file_name to new_file_name.

    :param current_file_name: The current name of the file.
    :param new_file_name: The new name for the file.
    """
    try:
        os.rename(current_file_name, new_file_name)
        print(f"File renamed from {current_file_name} to {new_file_name}.")
    except FileNotFoundError:
        print(f"The file {current_file_name} does not exist.")
    except PermissionError:
        print("You do not have the necessary permissions to rename this file.")
    except Exception as e:
        print(f"An error occurred: {e}")


def is_python_file(file_path):
    # Check if the file has a .py extension
    if not file_path.endswith('.py'):
        return False

    # Check if the file exists and is a file
    if not os.path.isfile(file_path):
        return False

    # Optionally, check for a Python shebang in the first line
    # with open(file_path, 'r') as file:
    #     first_line = file.readline().strip()
    #     if first_line.startswith('#!') and 'python' in first_line:
    #         return True

    return True


def generate_import_statement(file_path):
    # Normalize the path and split off the base name and extension
    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)

    # Remove the base file name from the path, and replace slashes with dots
    module_path = file_path.replace(ext, '').replace('/', '.')

    # Split into components
    *module_parts, module_name = module_path.split('.')

    # Construct the import statement
    import_statement = f"from {'.'.join(module_parts)}.{module_name}"
    return import_statement


def get_methods_from_file(file_path):
    """
    Extracts all method names and their corresponding code from a Python script.

    Args:
        file_path (str): Path to the Python script file.

    Returns:
        list: A list of tuples, where each tuple contains the method name and its corresponding code.
    """
    methods = []

    # Read the file content
    with open(file_path, "r", encoding="utf-8") as file:
        file_content = file.read()

    # Parse the file content into an AST
    tree = ast.parse(file_content)

    # Walk through the nodes of the AST
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):  # Check for function definitions
            method_name = node.name
            # method_code = ast.get_source_segment(file_content, node)
            # methods.append((method_name, method_code))
            methods.append(method_name)

    return methods


def get_methods_with_signatures(file_path: str) -> List[Tuple[str, str, Optional[str]]]:
    """
    Extracts method names, their input parameters with types, and return types from a Python script.

    Args:
        file_path (str): Path to the Python script file.

    Returns:
        List[Tuple[str, str, Optional[str]]]: A list of tuples, each containing:
            - Method name (str)
            - Method signature (str)
            - Return type (Optional[str])
    """
    methods = []

    # Read the file content
    with open(file_path, "r", encoding="utf-8") as file:
        file_content = file.read()

    # Parse the file content into an AST
    tree = ast.parse(file_content)

    # Walk through the nodes of the AST
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):  # Check for function definitions
            method_name = node.name

            # Retrieve the function's signature
            args = []
            for arg in node.args.args:
                arg_name = arg.arg
                arg_type = ast.unparse(arg.annotation) if arg.annotation else 'Any'
                args.append(f"{arg_name}: {arg_type}")
            args_str = ", ".join(args)

            # Retrieve the return type
            return_type = ast.unparse(node.returns) if node.returns else 'Any'

            # Format the method signature
            method_signature = f"def {method_name}({args_str}) -> {return_type}"

            methods.append((method_name, method_signature, return_type))

    return methods


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
        'import_statements': '',
        'global_variables': '',
        'main_script': '',
        'methods': {}
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

    # Step 3: Include relevant globals and imports in their respective methods
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
    global_variables = [code for name, code in global_vars.items() if name not in used_global_vars]
    imports_statements = [code for _, code in import_statements if code not in used_imports]

    parsed_script['global_variables'] = '\n'.join(global_variables).strip()
    parsed_script['import_statements'] = '\n'.join(imports_statements).strip()

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


def analyze_file_with_bandit(file_path, letter_conversion, logger):
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
        bandit_output_file = os.path.join(bandit_output_dir, name, letter_conversion, f"bandit.json")

        # Create custom directory
        os.makedirs(os.path.dirname(bandit_output_file), exist_ok=True)

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

    if not test_id_mapping_with_range:
        return "No issues found."

    # Construct Bandit issues for user prompt
    bandit_issues = "\n".join(
        f"- Test ID: {test_id}, Line: {details[0]}, Line Range: {details[1]}, Issue: {details[2]}"
        for test_id, details in test_id_mapping_with_range.items()
    )

    return bandit_issues


def analyze_file_with_dodgy(file_path, letter_conversion, logger):
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

    dodgy_output_file = os.path.join(dodgy_output_dir, name, letter_conversion, f"dodgy.json")

    # Create custom directory
    os.makedirs(os.path.dirname(dodgy_output_file), exist_ok=True)

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


def analyze_file_with_semgrep(file_path, letter_conversion, extracted_libraries, logger):
    """
    Analyzes a Python file using Semgrep and saves a standardized report in JSON format.

    Args:
        letter_conversion: Excel column conversion from integer.
        file_path (str): Path to the Python file to analyze.
        extracted_libraries (list): List of libraries used in the Python file.
        logger (logging.Logger): Logger object for logging information and errors.

    Returns:
        str: Path to the standardized Semgrep report file, or None if analysis failed.
    """
    base_name = os.path.basename(file_path)
    name, _ = os.path.splitext(base_name)

    try:
        semgrep_output_file = os.path.join(semgrep_output_dir, name, letter_conversion, f"semgrep.json")

        # Create custom directory
        os.makedirs(os.path.dirname(semgrep_output_file), exist_ok=True)

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


def analyze_file_with_mypy(file_path: str, letter_conversion: str, logger: logging.Logger) -> Optional[str]:
    """
    Analyzes a Python file using mypy and saves a standardized report in JSON format.

    Args:
        file_path (str): Path to the Python file to analyze.
        letter_conversion (str): Conversion of integer to Excel-style column name.
        logger (logging.Logger): Logger object for logging information and errors.

    Returns:
        Optional[str]: Path to the standardized mypy report file, or None if analysis failed.
    """
    base_name = os.path.basename(file_path)
    name, _ = os.path.splitext(base_name)

    try:
        # Define the output file path for the mypy JSON report
        mypy_output_file = os.path.join(mypy_output_dir, name, letter_conversion, f"mypy.json")

        # Create custom directory
        os.makedirs(os.path.dirname(mypy_output_file), exist_ok=True)

        # Run mypy on the given file
        mypy_result = api.run([file_path, "--warn-unused-ignores"])

        # Parse mypy output
        stdout, stderr, exit_code = mypy_result
        if exit_code != 0 and not stdout:
            logger.error(f"Mypy analysis failed for {file_path} with errors: {stderr}")
            return None

        findings = []

        # Process stdout line by line
        for line in stdout.splitlines():
            if ":" in line:
                # Split into 3 parts: file, line, and message
                parts = line.split(":", 2)  # Split at most into 3 parts
                if len(parts) == 3:
                    file, line_num, message = parts
                    try:
                        finding = {
                            "line": int(line_num.strip()),  # Convert line number to int
                            "message": message.strip(),  # Capture the full error message
                        }
                        findings.append(finding)
                    except ValueError as e:
                        logger.error(f"Error parsing line: {line}. Exception: {e}")

        # Write findings to JSON file
        with open(mypy_output_file, "w") as report_file:
            json.dump(findings, report_file, indent=4)

        logger.info(f"Mypy report saved to: {mypy_output_file}")
        return mypy_output_file

    except Exception as e:
        logger.error(f"An error occurred during mypy analysis for {file_path}: {e}")
        return None


def get_mypy_issues(input_mypy_file: str) -> str:
    """
    Reads a Mypy JSON report and formats the issues into a user-friendly string.

    Args:
        input_mypy_file (str): Path to the Mypy JSON report file.

    Returns:
        str: A formatted string of Mypy issues.
    """
    try:
        # Open and read the JSON file
        with open(input_mypy_file, 'r') as file:
            data = json.load(file)

        # Extract issues from the JSON data
        mypy_issues = []
        for result in data:
            line = result.get('line', 'N/A')
            message = result.get('message', 'N/A')

            # Create a formatted issue string
            issue_str = (
                f"Line: {line}\n"
                f"\tMessage: {message}\n"
            )
            mypy_issues.append(issue_str)

        # Join all issues into a single formatted string
        return "\n".join(mypy_issues) if mypy_issues else "No issues found."
    except Exception as e:
        return f"An error occurred while reading Mypy issues: {e}"


def analyze_file_with_vulture(file_path: str, letter_conversion: str, logger: logging.Logger) -> Optional[str]:
    """
    Analyzes a Python file using Vulture and saves a standardized report in JSON format.

    Args:
        file_path (str): Path to the Python file to analyze.
        letter_conversion (str): Conversion of integer to Excel-style column name.
        logger (logging.Logger): Logger object for logging information and errors.

    Returns:
        Optional[str]: Path to the standardized Vulture report file, or None if analysis failed.
    """
    base_name = os.path.basename(file_path)
    name, _ = os.path.splitext(base_name)

    try:
        # Define the output file path for the Vulture JSON report
        vulture_output_file = os.path.join(vulture_output_dir, name, letter_conversion, "vulture.json")

        # Create the directory structure for the output file
        os.makedirs(os.path.dirname(vulture_output_file), exist_ok=True)

        # Initialize Vulture
        vulture_analyzer = Vulture()

        # Read the file content and scan it
        with open(file_path, 'r') as file:
            source_code = file.read()
        vulture_analyzer.scan(source_code)

        # Collect unused code results
        unused_code = vulture_analyzer.get_unused_code()

        findings = []
        for item in unused_code:
            findings.append({
                "type": item.typ.capitalize(),  # Type of unused code (e.g., "Function", "Variable")
                "name": item.name,  # Name of the unused entity
            })

        # Write findings to a JSON file
        with open(vulture_output_file, "w") as report_file:
            json.dump(findings, report_file, indent=4)

        logger.info(f"Vulture report saved to: {vulture_output_file}")
        return vulture_output_file

    except Exception as e:
        logger.error(f"An error occurred during Vulture analysis for {file_path}: {e}")
        return None


def get_vulture_issues(input_vulture_file: str) -> str:
    """
    Reads a Vulture JSON report and formats the issues into a user-friendly string.

    Args:
        input_vulture_file (str): Path to the Vulture JSON report file.

    Returns:
        str: A formatted string of Vulture issues.
    """
    try:
        # Open and read the JSON file
        with open(input_vulture_file, 'r') as file:
            data = json.load(file)

        # Extract issues from the JSON data
        vulture_issues = []
        for result in data:
            issue_type = result.get('type', 'Unknown')
            name = result.get('name', 'N/A')
            line_start = result.get('line_start', 'N/A')  # Updated to reflect new key
            line_end = result.get('line_end', 'N/A')  # Updated to reflect new key

            # Create a formatted issue string
            issue_str = (
                f"\t\t\tType: {issue_type} --> Name: {name}\n"
            )
            vulture_issues.append(issue_str)

        # Join all issues into a single formatted string
        return "\n".join(vulture_issues) if vulture_issues else "No unused code found."
    except Exception as e:
        return f"An error occurred while reading Vulture issues: {e}"


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


def validate_iteration_allowance(value):
    """
    Validates that the provided iteration_allowance is a positive integer.

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
        raise argparse.ArgumentTypeError(f"Invalid value '{value}'. iteration_allowance must be a positive integer.")
    return ivalue


def validate_correction_limit(value):
    """
    Validates that the provided iteration_allowance is a positive integer.

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


def remove_comments_and_docstrings(source):
    """
    Remove comments and docstrings from the provided Python source code.

    Args:
        source (str): The original Python source code as a string.

    Returns:
        str: The source code with comments and docstrings removed.
    """
    output = []
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0

    tokens = tokenize.generate_tokens(StringIO(source).readline)
    for toktype, ttext, (slineno, scol), (elineno, ecol), ltext in tokens:
        if slineno > last_lineno:
            last_col = 0
        if scol > last_col:
            output.append(" " * (scol - last_col))
        if toktype == tokenize.COMMENT:
            # Skip comments
            pass
        elif toktype == tokenize.STRING and prev_toktype == tokenize.INDENT:
            # Skip docstrings
            pass
        else:
            output.append(ttext)
        prev_toktype = toktype
        last_col = ecol
        last_lineno = elineno

    return ''.join(output)


def run_code_quality_scan(llm, input_file_path, logger):
    logger.info(f"Running customized static code quality scan on {input_file_path}.")

    # Read the contents of the organized file
    with open(input_file_path, 'r') as file:
        code_content = file.read()
        code_content = remove_comments_and_docstrings(code_content)
        autopep8.fix_code(code_content)

    system_prompt = """
    You are a Python assistant. Analyze provided code snippets and list issues that would result in exceptions/errors in 
    concise, one-line formats. Each entry should include the priority level in square brackets, the line number(s), 
    and a brief corrective action. Ensure the output is clear and consistent for easy regex parsing. Important: Do not
    suggest code modifications or rewrites; only identify potential exceptions/errors. Exclude analysis of security
    vulnerabilities.
    """

    user_prompt = f"""
    Provide concise, one-line outputs for each issue in the format [PRIORITY] Line X: Corrective Action, where PRIORITY
     is LOW, MEDIUM, HIGH, or CRITICAL based on the urgency of the fix.

    {code_content}
    """

    unit_test_messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    unit_test_summary_llm_config = create_chat_completion_llm(
        llm,
        messages=unit_test_messages,
        temperature=0.0,  # Set temperature for deterministic output
        top_p=1,  # Use nucleus sampling with top_p probability
        top_k=0,  # Disable top-k sampling
        stream=True,  # Enable streaming of the response
        stop=["<|endoftext|>"]  # Define stopping criteria for generation
    )

    # Process the streamed output to obtain the adjusted code block
    response = process_streamed_output(unit_test_summary_llm_config)

    # Define the regex pattern
    pattern = r"\[(LOW|MEDIUM|HIGH)\] Line (\d+(-\d+)?): (.+)"

    # Parse the output
    matches = re.findall(pattern, response)

    # Print parsed results
    parsed_issues = []
    for match in matches:
        priority = match[0]
        # line_numbers = match[1]
        corrective_action = match[3]
        if "logger" not in corrective_action:
            parsed_issues.append(f"priority: {priority}, corrective action: {corrective_action}")

    parsed_issues_string = "\n".join(parsed_issues)

    return parsed_issues_string


def run_mitigation_loop(
        mitigation_system_prompt,
        mitigation_user_prompt,
        iteration_allowance,
        base_name,
        llm,
        logger,
        mitigated_folder,
        mitigated_base_name,
        letter_conversion,
        original_code,
        section):
    # Set initial and maximum temperature values
    initial_temperature = 0.0
    max_temperature = 2.0

    # Calculate increment per iteration
    temperature_increment = (max_temperature - initial_temperature) / iteration_allowance

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
    bandit_scan_json_path = analyze_file_with_bandit(mitigated_file_path, letter_conversion, logger)
    bandit_issues = get_bandit_issues(bandit_scan_json_path)

    # Dodgy is a lightweight security tool that complements Bandit by focusing on file-level issues.
    # It scans for hardcoded secrets (e.g., API keys, passwords), suspicious filenames (e.g., *.pem, id_rsa),
    # and insecure file paths (e.g., /tmp directories).
    dodgy_scan_json_path = analyze_file_with_dodgy(mitigated_file_path, letter_conversion, logger)
    dodgy_issues = get_dodgy_issues(dodgy_scan_json_path)

    # Semgrep
    # Get libraries so the rulesets below (django and flask) can use them if they exist
    extracted_libraries = extract_libraries(original_code)

    # A lightweight static analysis tool that scans code for security vulnerabilities and enforces coding standards.
    # It offers customizable rules and supports taint analysis to track untrusted data through your codebase.
    semgrep_scan_json_path = analyze_file_with_semgrep(mitigated_file_path, letter_conversion, extracted_libraries,
                                                       logger)
    semgrep_issues = get_semgrep_issues(semgrep_scan_json_path)

    # Initialize mypy issues with no issues string
    # Do not want to scan the file that is going to potentially change from other scans
    mypy_issues = "No issues found."

    # Dependencies Scans
    # Safety
    # Focuses on identifying known security vulnerabilities in your project's dependencies by scanning requirements.txt
    # files. It cross-references your dependencies against a curated database of insecure packages to alert you to
    # potential risks.

    # Data Flow
    # Python Taint (PyT)
    #  A static analysis tool designed to detect security vulnerabilities in Python code by tracking the flow of tainted
    #  (untrusted) data to sensitive functions. It helps identify potential injection points and data leaks.

    logger.info(f"Running an iteration series of {iteration_allowance}.")
    while iteration < iteration_allowance:
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

        # Calculate increments per iteration
        line_count_increment = initial_line_count * 0.5 / iteration_allowance
        word_count_increment = initial_word_count * 0.5 / iteration_allowance

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

        # Construct the mitigation user prompt
        bandit_issues_section = (f"Bandit has identified the following issues"
                                 f" in the provided Python code:\n{bandit_issues}\n\n") \
            if bandit_issues != "No issues found." else ""

        dodgy_issues_section = (f"Dodgy has identified the following issues"
                                f" in the provided Python code:\n{dodgy_issues}\n\n") \
            if dodgy_issues != "No issues found." else ""

        semgrep_issues_section = (f"Semgrep has identified the following issues"
                                  f" in the provided Python code:\n{semgrep_issues}\n\n") \
            if semgrep_issues != "No issues found." else ""

        mypy_issues_section = (f"Mypy has identified the following issues"
                               f" in the provided Python code:\n{mypy_issues}\n\n") \
            if mypy_issues != "No issues found." else ""

        if (
                bandit_issues != "No issues found." and
                dodgy_issues != "No issues found." and
                semgrep_issues != "No issues found."
        ):

            security_issues_section = (
            f"""      
            **Adhere to Best Security Practices:**
            {bandit_issues_section}
            {dodgy_issues_section}
            {semgrep_issues_section}
            """)
        else:
            security_issues_section = ""

        if mypy_issues != "No issues found.":
            linter_issues_section = (
                f"""
                **Adhere to These Linter Findings:**'
                {mypy_issues_section}
                """
            )
        else:
            linter_issues_section = ""

        issues_section = f"{security_issues_section}\n\n{linter_issues_section}\n\n".strip()

        mitigation_user_prompt = (f"{issues_section}\n\n" +
                                      mitigation_user_prompt.format(
                                        substitution_code_instruction = substitution_code_instruction,
                                        word_count = word_count,
                                        line_count = line_count,
                                        mitigated_code = mitigated_code
                                    )).strip()

        messages = [
            {"role": "system", "content": mitigation_system_prompt},
            {"role": "user", "content": mitigation_user_prompt}
        ]

        # Adjust temperature to control randomness; increase to make output more diverse
        temperature = round(min(max_temperature, initial_temperature + temperature_increment * iteration), 2)

        # Create chat completion llama object
        adjusted_code_response = create_chat_completion_llm(
            llm,
            messages,
            temperature,
            1,
            0,
            True,
            ["<|endoftext|>"]
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

        # Perform vulnerability/linter scans on mitigated file
        # Perform vulnerability scans again
        (bandit_issues, dodgy_issues, semgrep_issues, mypy_issues) = perform_scans(
            mitigated_file_path,
            letter_conversion,
            extracted_libraries,
            logger
        )

        passed_scans = (bandit_issues == 'No issues found.' and
                              dodgy_issues == 'No issues found.' and
                              semgrep_issues == 'No issues found.' and
                              mypy_issues == 'No issues found.')

        if not passed_scans:
            logger.error(f"After {iteration} iterations issues still persist.")

        return code_block

def run_method_unit_test_creation_loop(
        correction_limit,
        base_name,
        llm,
        logger,
        generated_unit_test_dir,
        file_base_name,
        letter_conversion,
        original_code,
        method,
        import_string):
    # Define the system and user prompts
    system_prompt = (
        "You are an AI assistant that generates Python unit tests using the pytest framework."
    )

    code_prompt = (
        f"""
        Generate a single functional unit test method for the specified code, strictly adhering to the following essential rules:

        - **Single Test Case**: Generate only one test method focused on a specific functionality or scenario. Do not include multiple test methods or unrelated code.
        - **Clarity and Purpose**: Use a clear and descriptive test case name that indicates the functionality being tested.
        - **Isolation**: Ensure the test is atomic, independent of other tests, and avoids relying on shared state or resources.
        - **Setup and Teardown**: Include setup and cleanup methods if necessary to initialize and dispose of resources (e.g., databases, mock objects).
        - **Test Coverage**: Address a typical scenario or an edge case relevant to the functionality.
        - **Assertions**: Use meaningful and precise assertions to validate the expected outcome against the actual result.
        - **Mocking and Dependency Isolation**: Mock external dependencies (e.g., APIs, services) to isolate the code under test and avoid external failures.
        - **Readability**: Add a descriptive docstring and inline comments to explain the purpose and behavior of the test.
        - **Performance**: Ensure the test executes efficiently and avoids unnecessary delays.
        - **Logging**: Include adequate logging to trace test execution and aid in debugging.

        Based on the above rules, generate a single test method for the following code:

        ```python
        {original_code}
        ```

        **Include only the single test method, with appropriate docstrings and inline comments for clarity.**
        """
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": code_prompt}
    ]

    # Create chat completion llama object
    functional_unit_test_code_response = create_chat_completion_llm(
        llm,
        messages,
        0.0,
        1,
        0,
        True,
        ["<|endoftext|>"]
    )

    # Process the streamed response
    functional_unit_test_code_block = process_streamed_output(functional_unit_test_code_response)
    logger.info("Secure code generation completed.")

    # Extract the code block from the secure code suggestion
    functional_unit_test_code_block = extract_code_block(functional_unit_test_code_block)

    iteration = 0

    if functional_unit_test_code_block:
        name, ext = os.path.splitext(base_name)
        unit_test_file_name = f"{file_base_name}_iteration_{method}_{iteration}{ext}"
        unit_test_file_path = os.path.join(generated_unit_test_dir, letter_conversion, unit_test_file_name)
        logger.info(f"Applied autoimport to {unit_test_file_path}; imports have been updated.")
        fixed_code = autoimport.fix_code(functional_unit_test_code_block)
        fixed_code = re.sub(r"^from your_module import .*", "", fixed_code, flags=re.MULTILINE)
        logger.info(f"Saving code to file {unit_test_file_path}.")
        save_code_to_file(fixed_code, unit_test_file_path, logger)

        # Prepend the generated import statements again if necessary
        prepend_to_file(unit_test_file_path, import_string + "\n")

    else:
        logger.warning("No adjusted code block found in the secure code suggestion. Stopping to diagnose issue.")
        sys.exit(1)

    # Set initial and maximum temperature values
    initial_temperature = 0.0
    max_temperature = 2.0

    # Calculate increment per iteration
    temperature_increment = (max_temperature - initial_temperature) / correction_limit

    # Define initial constraints based on the current mitigated code
    initial_line_count = len(fixed_code.split("\n"))
    initial_word_count = len(fixed_code.split())

    # Begin loop here
    while iteration < correction_limit:
        iteration += 1

        logger.info(f"Testing file {unit_test_file_path}.")
        stdout, stderr = execute_unit_test_file(unit_test_file_path)

        # Check if there are any errors in the test execution
        if "FAIL" not in stdout.upper() and "ERROR" not in stdout.upper() and "ERROR" not in stderr.upper():
            logger.info(f"All tests passed successfully for {unit_test_file_path}.")
            return functional_unit_test_code_block

        logger.warning("Errors detected in the unit tests. Attempting to correct...")

        # Adjust temperature to control randomness; increase to make output more diverse
        temperature = round(min(max_temperature, initial_temperature + temperature_increment * iteration), 2)

        # Calculate increments per iteration
        line_count_increment = initial_line_count * 0.5 / correction_limit
        word_count_increment = initial_word_count * 0.5 / correction_limit

        # Adjust constraints dynamically based on the current iteration
        line_count = int(initial_line_count * 1.1 + line_count_increment * iteration)
        word_count = int(initial_word_count * 1.2 + word_count_increment * iteration)

        # Combine stdout and stderr for error analysis
        error_output = f"Standard Output:\n{stdout}\n\nStandard Error Output:\n{stderr}."

        error_summary_system_prompt = (
            f""" 
            Analyze the given unit test and its failure details to identify the underlying issues causing the test failure. 
            Focus on accurately diagnosing the root cause and ensuring the resolution aligns with best practices. The analysis 
            and recommendations should adhere to the following guidelines:

            1. **Summarize the Failure**: Clearly describe the test's purpose, the error or failure message, and the behavior 
                observed during execution.
            2. **Identify the Root Cause**: Use the error details, logs, and code context to pinpoint the exact reason for the 
                failure. If external dependencies (e.g., APIs, databases) are involved, identify potential misconfigurations 
                or integration issues.
            3. **Provide Actionable Fixes**:
                - Clearly specify how to fix the identified issues within the failing test.
                - If the root cause lies in the code under test, recommend changes to that code, but DO NOT modify the test's 
                    primary purpose.
                - Address best practices for test design, including mocking, assertions, and resource management, where applicable.
            4. **Generate the Corrected Test Method**: After diagnosing the issue and determining the fix, produce a corrected 
                version of the failing unit test method. Ensure the corrected test:
                - Accurately validates the intended functionality.
                - Passes successfully once the corrections are applied.
                - Maintains readability, atomicity, and proper resource handling.
                - Adheres to the existing test's primary purpose.
                - Is enclosed within a code block formatted as ` ```python ... ``` ` to ensure it is parseable.
            5. **Clarity and Precision**: Avoid ambiguous suggestions. Provide detailed and practical steps to implement the fix.

            Ensure the response is concise, actionable, and strictly aligned with these guidelines. Include the fixed single 
            method unit test at the end of your analysis, enclosed in ` ```python ... ``` ` for proper parsing.
            """
        )

        error_summary_user_prompt = (
            f"""
            The following is the stdout and stderr generated by the Python unit tests. Analyze the output to identify the root 
            cause of the failure and fix the provided test. Ensure that the fixed test adheres to the best practices outlined 
            in the system prompt and is functional.

            Error Output:
            {error_output}

            Provide the fixed single method unit test enclosed within a ` ```python ... ``` ` block for proper parsing.
            
            Ensure the code does not exceed {word_count} words or {line_count} lines.
            """
        )

        error_summary_messages = [
            {"role": "system", "content": error_summary_system_prompt},
            {"role": "user", "content": error_summary_user_prompt}
        ]

        # Use the LLM to fix the errors
        error_correction_llm_config = create_chat_completion_llm(
            llm,
            messages=error_summary_messages,
            temperature=temperature,  # Deterministic output
            top_p=1,  # Use nucleus sampling
            top_k=0,  # Disable top-k sampling
            stream=True,  # Enable streaming of the response
            stop=["<|endoftext|>"]  # Define stopping criteria
        )

        # Process the streamed output to obtain the corrected code
        error_correction_response = process_streamed_output(error_correction_llm_config)

        # Extract the corrected code block from the LLM response
        corrected_unit_test_code = extract_code_block(error_correction_response)

        # Use autoimport to fix any lingering import statements
        corrected_unit_test_code = autoimport.fix_code(corrected_unit_test_code)

        # Define filename and path for the final output file
        unit_test_file_name = f"{base_name}_unit_test_{iteration}{ext}"
        unit_test_file_path = os.path.join(generated_unit_test_dir, name, letter_conversion,
                                           unit_test_file_name)

        # Save the corrected code back to the unit test file
        write_to_file(unit_test_file_path, corrected_unit_test_code)

        # Prepend the generated import statements again if necessary
        prepend_to_file(unit_test_file_path, import_string + "\n")

        logger.info(f"Unable to mitigate unit test for file {base_name}.")


def perform_scans(file_path, associated_letter_conversion, libraries, logger):
    # Perform scans again
    logger.info(f"Performing scans on {file_path}")

    # Bandit
    bandit_scan_json_path = analyze_file_with_bandit(file_path, associated_letter_conversion, logger)
    bandit_issues = get_bandit_issues(bandit_scan_json_path)

    if bandit_issues == 'No issues found.':
        logger.info("No issues encountered after bandit scan.")
    else:
        logger.info(f"Issues found in bandit scan: {bandit_scan_json_path}")

    # Dodgy
    dodgy_scan_json_path = analyze_file_with_dodgy(file_path, associated_letter_conversion, logger)
    dodgy_issues = get_dodgy_issues(dodgy_scan_json_path)

    if dodgy_issues == 'No issues found.':
        logger.info("No issues encountered after dodgy scan.")
    else:
        logger.info(f"Issues found in dodgy scan: {dodgy_scan_json_path}")

    # Semgrep
    semgrep_scan_json_path = analyze_file_with_semgrep(file_path, associated_letter_conversion, libraries, logger)
    semgrep_issues = get_semgrep_issues(semgrep_scan_json_path)

    if semgrep_issues == 'No issues found.':
        logger.info("No issues encountered after semgrep scan.")
    else:
        logger.info(f"Issues found in semgrep scan: {semgrep_scan_json_path}")

    # Mypy
    mypy_scan_json_path = analyze_file_with_mypy(file_path, associated_letter_conversion, logger)
    mypy_issues = get_mypy_issues(mypy_scan_json_path)

    if mypy_issues == 'No issues found.':
        logger.info("No issues encountered after mypy scan.")
    else:
        logger.info(f"Issues found in mypy scan: {mypy_scan_json_path}")

    # vulture
    # vulture_scan_json_path = analyze_file_with_vulture(file_path, associated_letter_conversion, logger)
    # vulture_issues = get_vulture_issues(vulture_scan_json_path)
    #
    # if vulture_issues == 'No unused code found.':
    #     logger.info("No issues encountered after vulture scan.")
    # else:
    #     logger.info(f"Issues found in vulture scan: {vulture_scan_json_path}")

    return bandit_issues, dodgy_issues, semgrep_issues, mypy_issues


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


def create_chat_completion_llm(llm, messages, temperature=0.0, top_p=1.0, top_k=0, stream=False, stop=None):
    """
    Generates a chat completion using the specified language model (LLM) and parameters.

    Parameters
    ----------
    llm : Llama
        The language model instance used to generate the chat completion. This object should have a method
        `create_chat_completion` that accepts the parameters defined below.

    messages : list of dict
        A list of message dictionaries that form the conversation history. Each dictionary should contain
        keys such as 'role' (e.g., 'user', 'assistant') and 'content' (the message text).

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

    stream : bool, optional
        If set to True, enables streaming of the response, allowing partial outputs to be received as they are
        generated. If False, the function will return the complete response after generation.

    stop : list of str or None, optional
        Defines stopping criteria for the generation. If a list of strings is provided, the generation will halt
        when any of the specified strings are encountered in the output. If None, no specific stopping criteria
        are applied.

    Returns
    -------
    dict
        A dictionary containing the generated chat completion. The structure of the returned dictionary depends
        on the implementation of the `create_chat_completion` method of the `llm` object.

    Notes
    -----
    - Ensure that the `llm` object provided has a `create_chat_completion` method compatible with the parameters
      specified above.
    - The `messages` parameter should accurately represent the conversation history to generate coherent and
      contextually relevant responses.
    - Adjusting `temperature`, `top_p`, and `top_k` can significantly impact the quality and style of the generated
      responses. Experiment with different values to achieve the desired outcome.

    Example
    -------
    ```python
    llm_instance = SomeLLMModel()
    conversation_history = [
        {"role": "user", "content": "Hello, how are you?"},
        {"role": "assistant", "content": "I'm good, thank you! How can I assist you today?"}
    ]
    response = create_chat_completion_llm(
        llm=llm_instance,
        messages=conversation_history,
        temperature=0.7,
        top_p=0.9,
        top_k=50,
        stream=False,
        stop=["\n"]
    )
    print(response)
    ```
    """
    chat_completion_llm = llm.create_chat_completion(
        messages=messages,
        temperature=temperature,  # Set temperature for deterministic output
        top_p=top_p,  # Use nucleus sampling with top_p probability
        top_k=top_k,  # Limit next token selection to top_k tokens
        stream=stream,  # Enable or disable streaming of the response
        stop=stop  # Define stopping criteria for generation
    )

    return chat_completion_llm


def execute_unit_test_file(unit_test_file_path):
    try:
        # Run the pytest command on the generated unit test file
        result = subprocess.run(
            ["pytest", unit_test_file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout, result.stderr
    except Exception as e:
        return "", traceback.format_exc()


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
