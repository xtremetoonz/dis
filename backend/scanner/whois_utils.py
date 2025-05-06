# /srv/git/dis/backend/scanner/whois_utils.py
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Optional, Union

WHOIS_TIMEOUT = 12
FALLBACK_SERVERS = ["whois.verisign-grs.com", "whois.iana.org"]

PRIVACY_PATTERNS = [
    r"WhoisGuard", r"DomainsByProxy", r"Private[\s_-]?Registration",
    r"Contact Privacy Inc", r"Privacy Protection Service"
]

def run_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=WHOIS_TIMEOUT,
            check=False
        )
        if result.returncode != 0 and result.stderr:
            return f"Command error: {result.stderr.strip()}"
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Command timed out after {WHOIS_TIMEOUT} seconds"
    except FileNotFoundError:
        return f"Required command not found: {command[0]}"
    except Exception as e:
        return f"Error running command: {str(e)}"

def parse_date(raw: str) -> str:
    try:
        # Handle common date formats
        raw = raw.strip()
        if 'Z' in raw:
            raw = raw.replace('Z', '+00:00')
        return str(datetime.fromisoformat(raw))
    except Exception:
        # Fallback to basic date extraction
        match = re.search(r"\d{4}-\d{2}-\d{2}", raw)
        return match.group(0) if match else raw.strip()

def fallback_whois(domain: str) -> str:
    for server in FALLBACK_SERVERS:
        result = run_command(["whois", f"-h{server}", domain])
        if result and not result.startswith(("Command error:", "Error running")):
            return result
    return ""

def parse_whois_data(output: str) -> Dict[str, Union[str, List[str]]]:
    if not output or output.startswith(("Command error:", "Error running")):
        return {}

    patterns = {
        "Registrar": r"Registrar:\s*(.+)",
        "Registration Date": r"Creation Date:\s*(.+)",
        "Expiration Date": r"Registry Expiry Date:\s*(.+)",
        "Updated Date": r"Updated Date:\s*(.+)",
        "Name Servers": r"Name Server:\s*(\S+)",
        "WHOIS Server": r"Whois Server:\s*(.+)",
        "Registrant Name": r"Registrant Name:\s*(.+)",
        "Registrant Organization": r"Registrant Organization:\s*(.+)",
        "Registrant Email": r"Registrant Email:\s*(.+)",
        "Tech Name": r"Tech Name:\s*(.+)",
        "Tech Organization": r"Tech Organization:\s*(.+)",
        "Tech Email": r"Tech Email:\s*(.+)",
    }

    data = {}
    for key, pattern in patterns.items():
        if key == "Name Servers":
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                data[key] = matches
        else:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                data[key] = parse_date(val) if "Date" in key else val

    return data

def detect_privacy_blocking(whois_text: str) -> bool:
    return any(re.search(pat, whois_text, re.IGNORECASE) for pat in PRIVACY_PATTERNS)

def get_whois_info(domain: str) -> str:
    output = run_command(["whois", domain])
    if not output or output.startswith(("Command error:", "Error running")):
        output = fallback_whois(domain)
    if not output:
        return "⚠️ No WHOIS data found"

    info = parse_whois_data(output)
    if not info:
        return "⚠️ Unable to parse WHOIS data"

    results = ["WHOIS Info:"]
    
    # Essential fields first
    for field in ["Registrar", "Registration Date", "Expiration Date", "Updated Date", "WHOIS Server"]:
        if field in info:
            results.append(f"✅ {field}: {info[field]}")

    # Name servers
    if "Name Servers" in info:
        ns_list = ", ".join(info["Name Servers"])
        results.append(f"✅ Name Servers: {ns_list}")

    # Contact information
    contact_fields = [
        "Registrant Name", "Registrant Organization", "Registrant Email",
        "Tech Name", "Tech Organization", "Tech Email"
    ]
    for field in contact_fields:
        if field in info:
            results.append(f"✅ {field}: {info[field]}")

    if detect_privacy_blocking(output):
        results.append("ℹ️ WHOIS data may be masked by privacy protection")

    return "\n".join(results)
