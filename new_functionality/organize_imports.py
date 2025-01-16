import ast
import os
import stdlib_list


def organize_imports_and_globals(file_path):
    """
    Reads a Python file, organizes and deduplicates its import statements and global variables,
    and moves them to the top of the file.

    :param file_path: Path to the Python file to be processed.
    """
    with open(file_path, 'r') as file:
        source_code = file.read()

    # Parse the source code into an AST
    tree = ast.parse(source_code)
    import_statements = []
    global_variables = {}
    other_code = []

    # Extract import statements, global variables, and other code
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_statements.append(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    # Deduplicate by overwriting existing global variables
                    global_variables[target.id] = node
                    break
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            # Preserve top-level docstrings or other expressions
            other_code.append(node)
        else:
            other_code.append(node)

    # Deduplicate and organize imports
    organized_imports = _process_import_nodes(import_statements)

    # Generate global variables section
    global_variables_code = "\n".join(ast.unparse(node) for node in global_variables.values())

    # Generate remaining code
    other_code_source = ast.unparse(ast.Module(body=other_code, type_ignores=[]))

    # Combine sections into the final source code
    new_source_code = f"{organized_imports}\n\n{global_variables_code}\n\n{other_code_source}"

    # Save the updated file
    new_file_path = os.path.splitext(file_path)[0] + "_organized.py"
    with open(new_file_path, 'w') as file:
        file.write(new_source_code)

    print(f"Organized imports and global variables saved to {new_file_path}")


def _process_import_nodes(import_nodes):
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
    std_lib_imports, third_party_imports, local_imports = _group_imports(import_strings)

    # Combine organized imports
    organized_imports = "\n".join(
        std_lib_imports + [""] +
        third_party_imports + [""] +
        local_imports
    )
    return organized_imports.strip()  # Remove extra spaces


def _group_imports(import_strings):
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


if __name__ == "__main__":
    # Specify the file path
    file_path = "/home/flaniganp/repositories/psu_sweng_capstone/mitigated_files/VulnerablePythonScript_mitigated_final.py"  # Replace with your file path

    # Ensure the file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        exit()

    # Run the organize_imports_and_globals method
    print(f"Processing file: {file_path}")
    organize_imports_and_globals(file_path)

    # Display the result file path
    new_file_path = os.path.splitext(file_path)[0] + "_organized.py"
    if os.path.exists(new_file_path):
        print(f"Organized file created: {new_file_path}")
    else:
        print("Error: Failed to create the organized file.")
