import subprocess

def run_whois(domain):
    """
    Runs the 'whois' command for the given domain and returns the result.
    """
    try:
        result = subprocess.check_output(["whois", domain], text=True)
        return {"status": "success", "data": result}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": str(e)}

def parse_whois(raw_data):
    """
    Parses WHOIS data to extract key fields (e.g., registrar, expiration date).
    """
    parsed_data = {}
    try:
        lines = raw_data.splitlines()
        for line in lines:
            if "Registrar:" in line:
                parsed_data["registrar"] = line.split(":")[1].strip()
            if "Expiration Date:" in line:
                parsed_data["expiration_date"] = line.split(":")[1].strip()
            if "Updated Date:" in line:
                parsed_data["updated_date"] = line.split(":")[1].strip()
    except Exception as e:
        parsed_data["error"] = f"Failed to parse WHOIS data: {str(e)}"
    return parsed_data
