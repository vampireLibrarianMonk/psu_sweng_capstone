import logging
import os
from datetime import datetime

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


# Example usage
if __name__ == "__main__":
    # Provide a suffix to differentiate logs
    logger = setup_logger("example")

    logger.debug("This is a debug message with a custom suffix")
    logger.info("This is an info message with a custom suffix")
    logger.warning("This is a warning message with a custom suffix")
    logger.error("This is an error message with a custom suffix")
    logger.critical("This is a critical message with a custom suffix")
