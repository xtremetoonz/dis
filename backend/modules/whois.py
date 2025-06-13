import subprocess
import re
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import logging
import json
import socket
import ipaddress
import shutil

# Configure module logger
logger = logging.getLogger(__name__)

# Common date formats in WHOIS data
WHOIS_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",               # 2023-05-16T10:00:00Z (ISO format)
    "%Y-%m-%d %H:%M:%S",                # 2023-05-16 10:00:00
    "%Y-%m-%dT%H:%M:%S.%fZ",            # 2023-05-16T10:00:00.000Z (ISO with ms)
    "%Y-%m-%d %H:%M:%S %Z",             # 2023-05-16 10:00:00 UTC
    "%d-%b-%Y",                         # 16-May-2023
    "%d %b %Y",                         # 16 May 2023
    "%d %b %Y %H:%M:%S %Z",             # 16 May 2023 10:00:00 UTC
    "%a %b %d %H:%M:%S %Z %Y",          # Mon May 16 10:00:00 UTC 2023
    "%Y/%m/%d",                         # 2023/05/16
    "%Y.%m.%d",                         # 2023.05.16
    "%d.%m.%Y",                         # 16.05.2023
    "%Y-%m-%d",                         # 2023-05-16
    "%d/%m/%Y",                         # 16/05/2023
]

# Common privacy protection services
PRIVACY_SERVICES = [
    "privacy", "private", "whoisguard", "protection", "redacted", "withheld", 
    "proxy", "contactprivacy", "domains by proxy", "perfect privacy", "contact privacy",
    "privacyguardian", "identity shield", "identity protect", "domain discreet",
    "privacy protect", "blur", "anonymize", "masked", "gdpr", "protected",
    "whois privacy", "privacy service", "identity protection", "guard",
]

# Common registrars
COMMON_REGISTRARS = {
    "godaddy": "GoDaddy",
    "tucows": "Tucows",
    "enom": "eNom",
    "networksolutions": "Network Solutions",
    "namesilo": "NameSilo",
    "namecheap": "Namecheap",
    "cloudflare": "Cloudflare",
    "name.com": "Name.com",
    "amazon": "Amazon Registrar",
    "google": "Google Domains",
    "porkbun": "Porkbun",
    "dynadot": "Dynadot",
    "hover": "Hover",
    "fastdomain": "FastDomain",
    "dreamhost": "DreamHost",
    "bluehost": "Bluehost",
    "hostgator": "HostGator",
    "inmotionhosting": "InMotion Hosting",
    "ovh": "OVH",
    "gandi": "Gandi",
    "ionos": "IONOS",
    "1and1": "1&1",
    "squarespace": "Squarespace",
    "shopify": "Shopify",
    "wix": "Wix",
    "rebel.com": "Rebel.com",
    "wild west domains": "Wild West Domains",
}

def parse_date(date_str: str) -> Optional[datetime]:
    """
    Parse a date string using various formats common in WHOIS data.
    
    Args:
        date_str (str): Date string to parse
        
    Returns:
        Optional[datetime]: Parsed datetime object or None if parsing fails
    """
    if not date_str or not isinstance(date_str, str):
        return None
        
    # Clean up the string
    date_str = date_str.strip()
    
    # Try each format
    for fmt in WHOIS_DATE_FORMATS:
        try:
            dt = datetime.strptime(date_str, fmt)
            # Assume UTC for dates without timezone
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
            
    # Could not parse the date
    logger.debug(f"Could not parse date: {date_str}")
    return None

def calculate_domain_age(creation_date: Optional[datetime]) -> Optional[Dict[str, Any]]:
    """
    Calculate domain age from creation date.
    
    Args:
        creation_date (Optional[datetime]): Domain creation date
        
    Returns:
        Optional[Dict]: Age information or None if no creation date
    """
    if not creation_date:
        return None
        
    now = datetime.now(timezone.utc)
    age = now - creation_date
    
    years = age.days // 365
    months = (age.days % 365) // 30
    days = (age.days % 365) % 30
    
    return {
        "days": age.days,
        "years": years,
        "months": months,
        "remaining_days": days,
        "total_seconds": age.total_seconds(),
        "human_readable": f"{years} years, {months} months, {days} days"
    }

def calculate_expiry_time(expiry_date: Optional[datetime]) -> Optional[Dict[str, Any]]:
    """
    Calculate time until domain expiration.
    
    Args:
        expiry_date (Optional[datetime]): Domain expiration date
        
    Returns:
        Optional[Dict]: Time until expiry or None if no expiry date
    """
    if not expiry_date:
        return None
        
    now = datetime.now(timezone.utc)
    
    if expiry_date < now:
        # Domain is expired
        return {
            "expired": True,
            "days": 0,
            "human_readable": "Expired"
        }
        
    time_left = expiry_date - now
    
    years = time_left.days // 365
    months = (time_left.days % 365) // 30
    days = (time_left.days % 365) % 30
    
    return {
        "expired": False,
        "days": time_left.days,
        "years": years,
        "months": months,
        "remaining_days": days,
        "total_seconds": time_left.total_seconds(),
        "human_readable": f"{years} years, {months} months, {days} days"
    }

def detect_privacy_protection(whois_data: str) -> Dict[str, Any]:
    """
    Detect if privacy protection services are being used.
    
    Args:
        whois_data (str): Raw WHOIS data
        
    Returns:
        Dict: Privacy protection information
    """
    result = {
        "privacy_protected": False,
        "redacted_fields": [],
        "protection_service": None,
        "confidence": 0.0  # 0.0 to 1.0
    }
    
    # Check for common redacted field patterns
    redacted_patterns = [
        r"redacted for privacy",
        r"data protected",
        r"personal data",
        r"not disclosed",
        r"information not available",
        r"private registration",
        r"registration private",
        r"redacted",
        r"data redacted",
        r"[^@]+@.*\.domains\.com",
        r"identity[^@]+@",
        r"gdpr",
        r"withheld for privacy",
        r"statutory masks",
        r"personal data redacted",
    ]
    
    # Keep track of matching terms for confidence score
    privacy_matches = set()
    
    # Check for privacy services
    for service in PRIVACY_SERVICES:
        if service.lower() in whois_data.lower():
            privacy_matches.add(service)
            result["privacy_protected"] = True
            
            # Try to determine the specific service
            context = re.search(r"(?i)[^\n]*\b" + re.escape(service) + r"\b[^\n]*", whois_data)
            if context and not result["protection_service"]:
                result["protection_service"] = context.group(0).strip()
                
    # Check for redacted fields
    for pattern in redacted_patterns:
        matches = re.finditer(r"(?i)[^:]+:[^\n]*" + pattern + r"[^\n]*", whois_data)
        for match in matches:
            field_line = match.group(0).strip()
            
            # Try to extract the field name
            field_match = re.match(r"([^:]+):", field_line)
            if field_match:
                field_name = field_match.group(1).strip()
                if field_name not in result["redacted_fields"]:
                    result["redacted_fields"].append(field_name)
                    privacy_matches.add(pattern)
                    result["privacy_protected"] = True
    
    # Calculate confidence based on number of matches
    result["confidence"] = min(1.0, len(privacy_matches) * 0.2)  # 0.2 per match, max 1.0
    
    return result

def extract_registrar_info(whois_data: str) -> Dict[str, Any]:
    """
    Extract and normalize registrar information.
    
    Args:
        whois_data (str): Raw WHOIS data
        
    Returns:
        Dict: Registrar information
    """
    result = {
        "registrar": None,
        "registrar_url": None,
        "registrar_normalized": None
    }
    
    # Try different patterns for registrar
    registrar_patterns = [
        r"(?i)Registrar:\s*(.+?)$",
        r"(?i)Sponsoring Registrar:\s*(.+?)$",
        r"(?i)Registrar Name:\s*(.+?)$",
        r"(?i)Registered through:\s*(.+?)$",
        r"(?i)Registration Service Provider:\s*(.+?)$"
    ]
    
    for pattern in registrar_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["registrar"] = match.group(1).strip()
            break
            
    # Try to extract registrar URL
    url_patterns = [
        r"(?i)Registrar URL:\s*(https?://\S+)",
        r"(?i)Registrar Website:\s*(https?://\S+)",
        r"(?i)URL:\s*(https?://\S+)",
        r"(?i)Registration URL:\s*(https?://\S+)"
    ]
    
    for pattern in url_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["registrar_url"] = match.group(1).strip()
            break
            
    # Normalize registrar name
    if result["registrar"]:
        registrar_lower = result["registrar"].lower()
        
        for key, normalized in COMMON_REGISTRARS.items():
            if key.lower() in registrar_lower:
                result["registrar_normalized"] = normalized
                break
                
    return result

def extract_contact_info(whois_data: str) -> Dict[str, Any]:
    """
    Extract contact information from WHOIS data.
    
    Args:
        whois_data (str): Raw WHOIS data
        
    Returns:
        Dict: Contact information
    """
    result = {
        "registrant": {
            "organization": None,
            "country": None
        },
        "admin": {
            "organization": None,
            "country": None
        },
        "tech": {
            "organization": None,
            "country": None
        }
    }
    
    # Registrant information patterns
    registrant_org_patterns = [
        r"(?i)Registrant Organization:\s*(.+?)$",
        r"(?i)Registrant Organisation:\s*(.+?)$",
        r"(?i)Registrant Name:\s*(.+?)$"
    ]
    
    for pattern in registrant_org_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["registrant"]["organization"] = match.group(1).strip()
            break
            
    # Admin information patterns
    admin_org_patterns = [
        r"(?i)Admin Organization:\s*(.+?)$",
        r"(?i)Admin Organisation:\s*(.+?)$",
        r"(?i)Administrative Contact Organization:\s*(.+?)$"
    ]
    
    for pattern in admin_org_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["admin"]["organization"] = match.group(1).strip()
            break
            
    # Tech information patterns
    tech_org_patterns = [
        r"(?i)Tech Organization:\s*(.+?)$",
        r"(?i)Tech Organisation:\s*(.+?)$",
        r"(?i)Technical Contact Organization:\s*(.+?)$"
    ]
    
    for pattern in tech_org_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["tech"]["organization"] = match.group(1).strip()
            break
            
    # Country patterns
    country_patterns = {
        "registrant": [
            r"(?i)Registrant Country:\s*(.+?)$",
            r"(?i)Registrant Country/Economy:\s*(.+?)$"
        ],
        "admin": [
            r"(?i)Admin Country:\s*(.+?)$",
            r"(?i)Administrative Contact Country:\s*(.+?)$"
        ],
        "tech": [
            r"(?i)Tech Country:\s*(.+?)$",
            r"(?i)Technical Contact Country:\s*(.+?)$"
        ]
    }
    
    for contact_type, patterns in country_patterns.items():
        for pattern in patterns:
            match = re.search(pattern, whois_data, re.MULTILINE)
            if match:
                result[contact_type]["country"] = match.group(1).strip()
                break
                
    return result

def parse_whois_dates(whois_data: str) -> Dict[str, Any]:
    """
    Parse and extract all date-related information from WHOIS data.
    
    Args:
        whois_data (str): Raw WHOIS data
        
    Returns:
        Dict: Dictionary with parsed dates
    """
    result = {
        "created": None,
        "updated": None,
        "expires": None,
        "created_date": None,
        "updated_date": None,
        "expiry_date": None,
        "domain_age": None,
        "time_until_expiry": None
    }
    
    # Creation date patterns
    creation_patterns = [
        r"(?i)Creation Date:\s*(.+?)$",
        r"(?i)Created Date:\s*(.+?)$",
        r"(?i)Domain Registration Date:\s*(.+?)$",
        r"(?i)Domain Created:\s*(.+?)$",
        r"(?i)Created:\s*(.+?)$",
        r"(?i)Registered on:\s*(.+?)$",
        r"(?i)Registration Date:\s*(.+?)$",
        r"(?i)Domain Name Commencement Date:\s*(.+?)$",
        r"(?i)Registration Time:\s*(.+?)$"
    ]
    
    for pattern in creation_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["created"] = match.group(1).strip()
            # Try to parse the date
            result["created_date"] = parse_date(result["created"])
            break
            
    # Updated date patterns
    updated_patterns = [
        r"(?i)Updated Date:\s*(.+?)$",
        r"(?i)Last Updated:\s*(.+?)$",
        r"(?i)Domain Last Updated Date:\s*(.+?)$",
        r"(?i)Domain Updated:\s*(.+?)$",
        r"(?i)Modified:\s*(.+?)$",
        r"(?i)Last Modified:\s*(.+?)$",
        r"(?i)Update Date:\s*(.+?)$",
        r"(?i)Last Update:\s*(.+?)$"
    ]
    
    for pattern in updated_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["updated"] = match.group(1).strip()
            # Try to parse the date
            result["updated_date"] = parse_date(result["updated"])
            break
            
    # Expiration date patterns
    expiry_patterns = [
        r"(?i)Expir(?:y|ation) Date:\s*(.+?)$",
        r"(?i)Registry Expiry Date:\s*(.+?)$",
        r"(?i)Registrar Registration Expiration Date:\s*(.+?)$",
        r"(?i)Domain Expiration Date:\s*(.+?)$",
        r"(?i)Expiration Time:\s*(.+?)$",
        r"(?i)Expiration:\s*(.+?)$",
        r"(?i)Expires on:\s*(.+?)$",
        r"(?i)Expires:\s*(.+?)$",
        r"(?i)Expiry:\s*(.+?)$"
    ]
    
    for pattern in expiry_patterns:
        match = re.search(pattern, whois_data, re.MULTILINE)
        if match:
            result["expires"] = match.group(1).strip()
            # Try to parse the date
            result["expiry_date"] = parse_date(result["expires"])
            break
            
    # Calculate domain age if we have a creation date
    if result["created_date"]:
        result["domain_age"] = calculate_domain_age(result["created_date"])
        
    # Calculate time until expiry if we have an expiration date
    if result["expiry_date"]:
        result["time_until_expiry"] = calculate_expiry_time(result["expiry_date"])
        
    return result

def extract_name_servers(whois_data: str) -> List[str]:
    """
    Extract name servers from WHOIS data.
    
    Args:
        whois_data (str): Raw WHOIS data
        
    Returns:
        List[str]: List of name servers
    """
    name_servers = []
    
    # Different patterns for name servers
    ns_patterns = [
        r"(?i)Name Server:\s*(.+?)$",
        r"(?i)Nameserver:\s*(.+?)$",
        r"(?i)nserver:\s*(.+?)$",
        r"(?i)DNS[0-9]*:\s*(.+?)$"
    ]
    
    for pattern in ns_patterns:
        for match in re.finditer(pattern, whois_data, re.MULTILINE):
            ns = match.group(1).strip().lower()
            
            # Clean up and normalize name server
            ns = re.sub(r'\s+', '', ns)  # Remove whitespace
            
            # Skip if it's an IP address
            try:
                ipaddress.ip_address(ns)
                continue
            except ValueError:
                pass
                
            # Add to list if not already present
            if ns and ns not in name_servers:
                name_servers.append(ns)
                
    return name_servers

def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves and analyzes WHOIS information for a domain.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing WHOIS information and analysis
    """

    results = {
        "raw_data": None,
        "parsed": {},
        "found": False,
        "privacy_protected": False,
        "errors": [],
        "warnings": [],
        "recommendations": [],
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
            
        whois_path = shutil.which('whois')
        results["debug_info"]["whois_path"] = whois_path
        if not whois_path:
            raise FileNotFoundError("whois command not found")
        
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
            # Check for privacy protection
            privacy_info = detect_privacy_protection(whois_data)
            results["privacy_protected"] = privacy_info["privacy_protected"]
            results["parsed"]["privacy"] = privacy_info
            
            # Parse dates
            date_info = parse_whois_dates(whois_data)
            results["parsed"]["dates"] = date_info
            
            # Extract registrar information
            registrar_info = extract_registrar_info(whois_data)
            results["parsed"]["registrar"] = registrar_info
            
            # Extract contact info
            contact_info = extract_contact_info(whois_data)
            results["parsed"]["contacts"] = contact_info
            
            # Extract name servers
            name_servers = extract_name_servers(whois_data)
            results["parsed"]["nameservers"] = name_servers
            
            # Add warnings and recommendations based on the parsed data
            
            # Check for domain expiry
            if date_info.get("time_until_expiry"):
                expiry_time = date_info["time_until_expiry"]
                
                if expiry_time.get("expired", False):
                    results["warnings"].append("Domain has expired")
                    results["recommendations"].append("Renew the domain immediately to prevent loss")
                elif expiry_time.get("days", 0) < 30:
                    results["warnings"].append(f"Domain expires in {expiry_time.get('days')} days")
                    results["recommendations"].append("Renew the domain soon to prevent service interruption")
                elif expiry_time.get("days", 0) < 90:
                    results["warnings"].append(f"Domain expires in {expiry_time.get('days')} days")
                    results["recommendations"].append("Consider renewing the domain in the coming months")
            
            # Check nameserver count
            if len(name_servers) < 2:
                results["warnings"].append(f"Only {len(name_servers)} nameservers found - recommended minimum is 2")
                results["recommendations"].append("Add at least one more nameserver for redundancy")
            
            # Generate a domain age summary
            if date_info.get("domain_age"):
                age = date_info["domain_age"]
                years = age.get("years", 0)
                
                if years < 1:
                    results["warnings"].append("Domain is less than 1 year old")
                    results["recommendations"].append("New domains may have lower reputation - monitor spam scores carefully")
            
            # Domain parking detection
            if "parking" in whois_data.lower() or "parked" in whois_data.lower():
                results["warnings"].append("Domain may be parked")
                
            # Provide grade based on age, privacy, etc.
            results["grade"] = grade_domain(results)
        
    except subprocess.TimeoutExpired:
        results["errors"].append("WHOIS command timed out")
        
    except Exception as e:
        error_message = f"Error retrieving WHOIS information: {str(e)}"
        results["errors"].append(error_message)
        results["debug_info"]["exception"] = str(e)
        import traceback
        results["debug_info"]["traceback"] = traceback.format_exc()
        
    return results

def grade_domain(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Grade the domain based on WHOIS information.
    
    Args:
        results (Dict): WHOIS analysis results
        
    Returns:
        Dict: Grade information
    """
    grade = {
        "score": 0,
        "grade": "C",
        "description": "Average domain registration"
    }
    
    # If WHOIS data not found or had errors
    if not results["found"] or results["errors"]:
        grade["grade"] = "F"
        grade["description"] = "Could not retrieve WHOIS data"
        return grade
    
    # Start with a baseline score
    score = 5.0
    
    # Check domain age
    age_info = results.get("parsed", {}).get("dates", {}).get("domain_age", {})
    age_years = age_info.get("years", 0) if age_info else 0
    
    if age_years >= 15:
        score += 3.0  # Excellent
    elif age_years >= 10:
        score += 2.5  # Very good
    elif age_years >= 5:
        score += 1.5  # Good
    elif age_years >= 2:
        score += 1.0  # Decent
    elif age_years < 1:
        score -= 1.0  # New domains could be risky
    
    # Check expiry time
    expiry_info = results.get("parsed", {}).get("dates", {}).get("time_until_expiry", {})
    expiry_days = expiry_info.get("days", 0) if expiry_info else 0
    
    if expiry_info and expiry_info.get("expired", False):
        score -= 3.0  # Expired
    elif expiry_days <= 30:
        score -= 2.0  # About to expire
    elif expiry_days <= 90:
        score -= 1.0  # Expiring soon
    elif expiry_days >= 365:
        score += 0.5  # Long validity
    
    # Check nameservers count
    nameservers = results.get("parsed", {}).get("nameservers", [])
    ns_count = len(nameservers)
    
    if ns_count >= 4:
        score += 1.0  # Excellent
    elif ns_count == 3:
        score += 0.5  # Good
    elif ns_count == 2:
        score += 0.0  # Standard
    elif ns_count < 2:
        score -= 1.0  # Poor
    
    # Privacy protection is neutral
    
    # Any warnings affect the score
    score -= len(results.get("warnings", [])) * 0.5  # -0.5 per warning
    
    # Calculate grade
    grade["score"] = round(score, 1)
    
    if score >= 8.0:
        grade["grade"] = "A+"
        grade["description"] = "Excellent domain registration"
    elif score >= 7.0:
        grade["grade"] = "A"
        grade["description"] = "Very good domain registration"
    elif score >= 6.0:
        grade["grade"] = "B+"
        grade["description"] = "Good domain registration"
    elif score >= 5.0:
        grade["grade"] = "B"
        grade["description"] = "Above average domain registration"
    elif score >= 4.0:
        grade["grade"] = "C+"
        grade["description"] = "Decent domain registration"
    elif score >= 3.0:
        grade["grade"] = "C"
        grade["description"] = "Average domain registration"
    elif score >= 2.0:
        grade["grade"] = "D"
        grade["description"] = "Below average domain registration"
    else:
        grade["grade"] = "F"
        grade["description"] = "Poor domain registration"
    
    return grade
