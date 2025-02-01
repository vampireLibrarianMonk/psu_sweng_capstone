import ast

class CodeExtractor(ast.NodeVisitor):
    """Extracts imports and function definitions from a Python file."""
    def __init__(self):
        self.imports = set()
        self.functions = {}

    def visit_Import(self, node):
        self.imports.add(ast.unparse(node).strip())

    def visit_ImportFrom(self, node):
        self.imports.add(ast.unparse(node).strip())

    def visit_FunctionDef(self, node):
        if node.name not in self.functions:
            self.functions[node.name] = ast.unparse(node)

def parse_python_file(file_path):
    """Parses a Python file and extracts imports and function definitions."""
    with open(file_path, 'r') as file:
        file_content = file.read()
    tree = ast.parse(file_content)
    extractor = CodeExtractor()
    extractor.visit(tree)
    return extractor.imports, extractor.functions

def combine_files(file_paths):
    """Combines imports and functions from multiple Python files without duplication."""
    all_imports = set()
    all_functions = {}

    for file_path in file_paths:
        imports, functions = parse_python_file(file_path)
        all_imports.update(imports)
        all_functions.update(functions)

    return sorted(all_imports), all_functions

def create_main_method(function_names):
    """Creates a main method that calls all extracted functions."""
    function_calls = '\n    '.join([f"{name}()" for name in function_names])
    main_method = f"""if __name__ == "__main__":\n    {function_calls}"""
    return main_method

def write_combined_file(output_path, imports, functions, main_method):
    """Writes the combined Python code to a new file."""
    with open(output_path, 'w') as file:
        # Write imports
        file.write('\n'.join(imports) + '\n\n')

        # Write functions
        for function_body in functions.values():
            file.write(function_body + '\n\n')

        # Write main method
        file.write(main_method)

if __name__ == "__main__":
    # Input: List of file paths to combine TODO insert paths for testing each time
    file_paths = []

    # Combine imports and functions
    imports, functions = combine_files(file_paths)

    # Generate the main method
    main_method = create_main_method(functions.keys())

    # Output: Path to save the combined Python file
    output_path = "combined_script.py"

    # Write the combined Python file
    write_combined_file(output_path, imports, functions, main_method)

    print(f"Combined script written to {output_path}")
