import subprocess

def run_dig(domain, record_type="ANY"):
    """
    Runs the 'dig' command for the given domain and record type.
    """
    try:
        result = subprocess.check_output(
            ["dig", domain, record_type], text=True
        )
        return {"status": "success", "data": result}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": str(e)}

def check_mx_records(domain):
    """
    Checks for MX records for the given domain.
    """
    dig_result = run_dig(domain, "MX")
    if dig_result["status"] == "success":
        if "ANSWER SECTION" in dig_result["data"]:
            return {"status": "success", "message": "MX records found"}
        else:
            return {"status": "warning", "message": "No MX records found"}
    return dig_result

def check_dnssec(domain):
    """
    Checks if the domain has DNSSEC enabled.
    """
    dig_result = run_dig(domain, "DNSKEY")
    if dig_result["status"] == "success":
        if "ANSWER SECTION" in dig_result["data"]:
            return {"status": "success", "message": "DNSSEC is enabled"}
        else:
            return {"status": "warning", "message": "DNSSEC not found"}
    return dig_result
