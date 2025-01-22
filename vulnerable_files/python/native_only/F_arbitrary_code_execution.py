import yaml

def load_user_config(yaml_data):
    """
    Loads user configuration from a YAML string.

    WARNING: This function is vulnerable to arbitrary code execution attacks
    because it uses yaml.load() with untrusted input without specifying a safe
    loader. An attacker could exploit this to execute malicious code.

    :param yaml_data: A string containing YAML-formatted user configuration.
    :return: The deserialized Python object.
    """
    # Vulnerable use of yaml.load()
    return yaml.load(yaml_data, Loader=yaml.FullLoader)

if __name__ == "__main__":
    user_input = input("Enter your YAML configuration:\n")
    try:
        config = load_user_config(user_input)
        print(f"Loaded configuration: {config}")
    except yaml.YAMLError as e:
        print(f"Error loading YAML: {e}")
