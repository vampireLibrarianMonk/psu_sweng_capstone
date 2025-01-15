import ast
from collections import defaultdict

def extract_imports_from_script(script):
    # Parse the script into an AST
    tree = ast.parse(script)

    # Dictionary to hold modules and their imports
    imports = defaultdict(list)

    # Traverse the AST nodes
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # Handle 'import module' statements
            for alias in node.names:
                module_name = alias.name
                imports[module_name]  # Initialize with an empty list
        elif isinstance(node, ast.ImportFrom):
            # Handle 'from module import ...' statements
            module_name = node.module
            for alias in node.names:
                imports[module_name].append(alias.name)

    return dict(imports)

# Example usage
script = """
import subprocess
import requests
from flask import Flask, request
import pickle
"""

import_map = extract_imports_from_script(script)
print(import_map)