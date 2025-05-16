import json

def format_output(data):
    """
    Formats output for logging or API responses.
    """
    return json.dumps(data, indent=4)

def log_error(error_message):
    """
    Logs errors to the console.
    """
    print(f"[ERROR]: {error_message}")
