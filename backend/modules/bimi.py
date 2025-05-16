import dns.resolver
import requests
from typing import Dict, Any, Optional
import re
import logging
import json
from io import BytesIO
from urllib.parse import urlparse

# Configure module logger
logger = logging.getLogger(__name__)

def get_dmarc_policy(domain: str) -> Dict[str, Any]:
    """
    Get DMARC policy for a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: DMARC policy information
    """
    result = {
        "record": None,
        "found": False,
        "policy": None,
        "pct": None,
        "enforcement": False,
        "errors": []
    }
    
    try:
        resolver = dns.resolver.Resolver()
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
            
            for record in dmarc_answers:
                txt_value = "".join(s.decode() for s in record.strings)
                
                if txt_value.startswith('v=DMARC1'):
                    result["record"] = txt_value
                    result["found"] = True
                    
                    # Parse DMARC record
                    policy_match = re.search(r'p=([^;]+)', txt_value)
                    if policy_match:
                        result["policy"] = policy_match.group(1)
                        # Check if policy is enforced (quarantine or reject)
                        result["enforcement"] = result["policy"] in ["quarantine", "reject"]
                    
                    # Get percentage
                    pct_match = re.search(r'pct=([^;]+)', txt_value)
                    if pct_match:
                        try:
                            result["pct"] = int(pct_match.group(1))
                        except ValueError:
                            result["errors"].append(f"Invalid pct value: {pct_match.group(1)}")
                    else:
                        # Default is 100% if not specified
                        result["pct"] = 100
                    
                    break
            
            if not result["found"]:
                result["errors"].append("No DMARC record found")
                
        except dns.resolver.NXDOMAIN:
            result["errors"].append("DMARC record does not exist")
        except dns.resolver.NoAnswer:
            result["errors"].append("No DMARC record found")
        except Exception as e:
            result["errors"].append(f"Error checking DMARC: {str(e)}")
            
    except Exception as e:
        result["errors"].append(f"Error checking DMARC: {str(e)}")
        
    return result

def check_svg_file(url: str) -> Dict[str, Any]:
    """
    Check if a URL points to a valid SVG file.
    
    Args:
        url (str): URL to check
        
    Returns:
        Dict: SVG validation results
    """
    result = {
        "valid": False,
        "content_type": None,
        "file_size": None,
        "errors": []
    }
    
    try:
        # Parse URL
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            result["errors"].append("Invalid URL format")
            return result
            
        # Only allow https URLs
        if parsed_url.scheme != "https":
            result["errors"].append("URL must use HTTPS protocol")
            return result
            
        # Fetch the file
        response = requests.get(url, timeout=10)
        
        # Check status code
        if response.status_code != 200:
            result["errors"].append(f"HTTP error: {response.status_code}")
            return result
            
        # Check content type
        content_type = response.headers.get('Content-Type', '')
        result["content_type"] = content_type
        
        if not content_type.startswith(('image/svg+xml', 'application/xml', 'text/xml')):
            result["errors"].append(f"Invalid content type: {content_type}")
            return result
            
        # Check file size (shouldn't be more than 32KB)
        file_size = len(response.content)
        result["file_size"] = file_size
        
        if file_size > 32 * 1024:  # 32KB
            result["errors"].append(f"SVG file too large: {file_size} bytes (max 32KB)")
            return result
            
        # Check if content starts with SVG tag
        content = response.text.strip()
        if not content.startswith(('<svg', '<?xml')):
            result["errors"].append("File does not appear to be a valid SVG")
            return result
            
        # Basic check passed
        result["valid"] = True
        
    except requests.exceptions.RequestException as e:
        result["errors"].append(f"Error fetching SVG: {str(e)}")
    except Exception as e:
        result["errors"].append(f"Error checking SVG: {str(e)}")
        
    return result

def check_bimi(domain: str) -> Dict[str, Any]:
    """
    Check BIMI configuration for a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: BIMI check results
    """
    results = {
        "record_found": False,
        "record": None,
        "parsed": {},
        "dmarc_status": None,
        "image_found": False,
        "image_valid": False,
        "vmc_found": False,
        "selector": "default",
        "errors": [],
        "recommendations": []
    }
    
    # First check DMARC enforcement
    dmarc_result = get_dmarc_policy(domain)
    results["dmarc_status"] = dmarc_result
    
    if not dmarc_result["found"]:
        results["errors"].append("DMARC record must be present for BIMI")
        results["recommendations"].append("Implement DMARC with quarantine or reject policy")
    elif not dmarc_result["enforcement"]:
        results["errors"].append("DMARC policy must be set to quarantine or reject for BIMI")
        results["recommendations"].append("Update DMARC policy to p=quarantine or p=reject")
    elif dmarc_result["pct"] < 100:
        results["errors"].append(f"DMARC percentage (pct={dmarc_result['pct']}) should be 100% for BIMI")
        results["recommendations"].append("Set DMARC pct=100")
    
    # Check for the BIMI record
    try:
        resolver = dns.resolver.Resolver()
        bimi_domain = f"default._bimi.{domain}"
        
        try:
            bimi_answers = resolver.resolve(bimi_domain, 'TXT')
            
            for record in bimi_answers:
                txt_value = "".join(s.decode() for s in record.strings)
                
                if txt_value.startswith('v=BIMI1'):
                    results["record_found"] = True
                    results["record"] = txt_value
                    
                    # Parse BIMI record
                    parsed = {}
                    
                    # Extract version
                    version_match = re.search(r'v=([^;]+)', txt_value)
                    if version_match:
                        parsed["version"] = version_match.group(1)
                        
                    # Extract location (l=)
                    location_match = re.search(r'l=([^;]+)', txt_value)
                    if location_match:
                        location = location_match.group(1).strip()
                        parsed["location"] = location
                        
                        # Check if the location URL is valid
                        if location:
                            results["image_found"] = True
                            svg_check = check_svg_file(location)
                            results["image_valid"] = svg_check["valid"]
                            
                            if not svg_check["valid"]:
                                for error in svg_check["errors"]:
                                    results["errors"].append(f"SVG file error: {error}")
                    else:
                        results["errors"].append("No location (l=) specified in BIMI record")
                        results["recommendations"].append("Add SVG image location with l= parameter")
                        
                    # Extract authority (a=)
                    authority_match = re.search(r'a=([^;]+)', txt_value)
                    if authority_match:
                        authority = authority_match.group(1).strip()
                        parsed["authority"] = authority
                        
                        if authority:
                            results["vmc_found"] = True
                            # We can't validate the VMC certificate here as it requires special tools
                    
                    results["parsed"] = parsed
                    break
            
            if not results["record_found"]:
                results["errors"].append("No BIMI record found")
                if dmarc_result["enforcement"]:
                    results["recommendations"].append("Add a BIMI record at default._bimi.{domain}")
                
        except dns.resolver.NXDOMAIN:
            results["errors"].append("BIMI record does not exist")
            if dmarc_result["enforcement"]:
                results["recommendations"].append("Add a BIMI record at default._bimi.{domain}")
        except dns.resolver.NoAnswer:
            results["errors"].append("No BIMI record found")
            if dmarc_result["enforcement"]:
                results["recommendations"].append("Add a BIMI record at default._bimi.{domain}")
        except Exception as e:
            results["errors"].append(f"Error checking BIMI record: {str(e)}")
            
    except Exception as e:
        results["errors"].append(f"Error checking BIMI: {str(e)}")
        
    # Add general recommendations
    if not results["record_found"] and dmarc_result["enforcement"]:
        results["recommendations"].append("Implement BIMI to display your logo in email clients")
    elif results["record_found"] and not results["image_valid"]:
        results["recommendations"].append("Fix the SVG file to comply with BIMI requirements")
    elif results["record_found"] and not results["vmc_found"]:
        results["recommendations"].append("Consider adding a Verified Mark Certificate (VMC) for wider support")
        
    # Final validation - JSON serialization check
    try:
        json.dumps(results)
    except (TypeError, OverflowError) as e:
        logger.error(f"JSON serialization error: {str(e)}")
        # Return a simplified version that will serialize
        return {
            "error": "Could not serialize BIMI results",
            "message": "The BIMI results contain data that cannot be converted to JSON",
            "bimi_found": results.get("record_found", False),
            "errors": results.get("errors", []) + ["JSON serialization error"]
        }
        
    return results
