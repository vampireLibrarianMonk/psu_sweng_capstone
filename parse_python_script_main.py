from utilities_llm import parse_python_script

# Example usage
file_path = 'vulnerable_repos/Intentionally-Vulnerable-Python-Application/VulnerablePythonScript.py'
parsed = parse_python_script(file_path)
for section, content in parsed.items():
    if isinstance(content, dict):
        print(f"{section}:")
        for method_name, method_code in content.items():
            print(f"  {method_name}:\n    " + method_code.replace('\n', '\n    ') + "\n")
    else:
        print(f"{section}:\n  " + content.replace('\n', '\n  ') + "\n")
