import subprocess
import re
from typing import Dict, Any
import logging

# Configure module logger
logger = logging.getLogger(__name__)

def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves WHOIS information for a domain without analysis.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing WHOIS information
    """
    results = {
        "raw_data": None,
        "parsed": {},
        "found": False,
        "privacy_protected": False,
        "errors": [],
        "debug_info": {}  # Add debugging information
    }
    
    try:
        # Check if whois is installed and get its path
        which_process = subprocess.run(
            ["which", "whois"], 
            capture_output=True, 
            text=True, 
            check=False
        )
        
        if which_process.returncode != 0:
            results["errors"].append("WHOIS command not found in PATH")
            results["debug_info"]["which_error"] = which_process.stderr
            return results
            
        whois_path = which_process.stdout.strip()
        results["debug_info"]["whois_path"] = whois_path
        
        # Check the whois version
        version_process = subprocess.run(
            ["whois", "-V"], 
            capture_output=True, 
            text=True, 
            check=False
        )
        results["debug_info"]["whois_version"] = version_process.stdout
        
        # Try running whois with full path
        process = subprocess.run(
            [whois_path, domain],
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )
        
        results["debug_info"]["returncode"] = process.returncode
        results["debug_info"]["stderr"] = process.stderr
        
        if process.returncode != 0:
            results["errors"].append(f"WHOIS command failed with return code {process.returncode}")
            results["debug_info"]["error_details"] = process.stderr
            return results
            
        whois_data = process.stdout
        results["raw_data"] = whois_data
        results["found"] = bool(whois_data.strip())
        
        # Only parse if we have data
        if results["found"]:
            # Parse common WHOIS fields
            parsed = {}
            
            # Registrar information
            registrar_match = re.search(r"Registrar:(.+?)$", whois_data, re.MULTILINE)
            if registrar_match:
                parsed["registrar"] = registrar_match.group(1).strip()
                
            # Registration date
            creation_match = re.search(r"Creation Date:(.+?)$", whois_data, re.MULTILINE)
            if creation_match:
                parsed["creation_date"] = creation_match.group(1).strip()
            
            # Expiration date
            expiry_match = re.search(r"Registrar Registration Expiration Date:(.+?)$|Registry Expiry Date:(.+?)$", whois_data, re.MULTILINE)
            if expiry_match:
                parsed["expiration_date"] = (expiry_match.group(1) or expiry_match.group(2)).strip()
                
            # Updated date
            updated_match = re.search(r"Updated Date:(.+?)$", whois_data, re.MULTILINE)
            if updated_match:
                parsed["updated_date"] = updated_match.group(1).strip()
                
            # WHOIS server
            whois_server_match = re.search(r"Whois Server:(.+?)$", whois_data, re.MULTILINE)
            if whois_server_match:
                parsed["whois_server"] = whois_server_match.group(1).strip()
                
            # Name servers
            nameservers = re.findall(r"Name Server:(.+?)$", whois_data, re.MULTILINE)
            if nameservers:
                parsed["nameservers"] = [ns.strip() for ns in nameservers]
                
            # Check for privacy protection
            privacy_patterns = [
                r"Privacy", r"Private", r"Protected", r"Redacted",
                r"WhoisGuard", r"Contact Privacy", r"Domain Admin"
            ]
            
            for pattern in privacy_patterns:
                if re.search(pattern, whois_data, re.IGNORECASE):
                    results["privacy_protected"] = True
                    break
                    
            results["parsed"] = parsed
        
    except subprocess.TimeoutExpired:
        results["errors"].append("WHOIS command timed out")
        
    except Exception as e:
        error_message = f"Error retrieving WHOIS information: {str(e)}"
        results["errors"].append(error_message)
        results["debug_info"]["exception"] = str(e)
        import traceback
        results["debug_info"]["traceback"] = traceback.format_exc()
        
    return results
