import ssl
import socket
import dns.resolver
import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging
import re
import urllib.parse

# Configure module logger
logger = logging.getLogger(__name__)

# List of common CA issuers for reference
COMMON_CA_ISSUERS = {
    "letsencrypt.org": "Let's Encrypt",
    "pki.goog": "Google Trust Services",
    "digicert.com": "DigiCert",
    "sectigo.com": "Sectigo",
    "globalsign.com": "GlobalSign",
    "godaddy.com": "GoDaddy",
    "amazonaws.com": "Amazon",
    "ssl.com": "SSL.com",
    "entrust.net": "Entrust",
    "usertrust.com": "Comodo/Sectigo",
    "comodoca.com": "Comodo/Sectigo",
    "3.amazonaws.com": "Amazon",
    "cloudflare.com": "Cloudflare"
}

def get_ssl_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves SSL/TLS information for a domain with enhanced analysis.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing SSL/TLS information and analysis
    """
    results = {
        "has_ssl": False,
        "certificate": None,
        "protocol_version": None,
        "cipher": None,
        "valid": False,
        "expires_in_days": None,
        "errors": [],
        "warnings": [],
        "recommendations": [],
        "caa_records": None,
        "ct_logs": None,
        "grade": None,
        "grade_description": None
    }
    
    # Check CAA records
    caa_results = check_caa_records(domain)
    results["caa_records"] = caa_results
    
    # Add warnings and recommendations from CAA check
    if "warnings" in caa_results:
        results["warnings"].extend(caa_results["warnings"])
    if "recommendations" in caa_results:
        results["recommendations"].extend(caa_results["recommendations"])
    
    # If no CAA records found, check Certificate Transparency logs
    if caa_results.get("has_caa_records", False) == False:
        ct_results = check_certificate_transparency(domain)
        results["ct_logs"] = ct_results
        
        # Add warnings and recommendations from CT check
        if "warnings" in ct_results:
            results["warnings"].extend(ct_results["warnings"])
        if "recommendations" in ct_results:
            results["recommendations"].extend(ct_results["recommendations"])
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the domain
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results["has_ssl"] = True
                results["protocol_version"] = ssock.version()
                
                # Get cipher information
                cipher = ssock.cipher()
                if cipher:
                    results["cipher"] = {
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": cipher[2]
                    }
                
                # Get certificate information
                cert = ssock.getpeercert()
                if cert:
                    results["valid"] = True
                    
                    # Format certificate information
                    certificate = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "alt_names": [],
                    }
                    
                    # Parse expiration date and calculate days until expiry
                    try:
                        expiration_date = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                        now = datetime.now()
                        days_until_expiry = (expiration_date - now).days
                        
                        certificate["expires_in_days"] = days_until_expiry
                        results["expires_in_days"] = days_until_expiry
                        
                        # Add warnings for certificates about to expire
                        if days_until_expiry < 30:
                            results["warnings"].append(f"Certificate expires in {days_until_expiry} days")
                            results["recommendations"].append("Renew SSL certificate soon to avoid service disruption")
                        elif days_until_expiry < 60:
                            results["warnings"].append(f"Certificate expires in {days_until_expiry} days")
                    except Exception as e:
                        logger.error(f"Error parsing certificate expiration date: {str(e)}")
                    
                    # Get subject alternative names
                    if 'subjectAltName' in cert:
                        for type_name, value in cert['subjectAltName']:
                            if type_name == 'DNS':
                                certificate["alt_names"].append(value)
                    
                    # Check for wildcard certificates
                    has_wildcard = False
                    for alt_name in certificate["alt_names"]:
                        if alt_name.startswith('*.'):
                            has_wildcard = True
                            break
                    
                    certificate["has_wildcard"] = has_wildcard
                    
                    # Get issuer information
                    issuer_org = certificate["issuer"].get('organizationName')
                    certificate["issuer_organization"] = issuer_org
                    
                    # Match issuer with CAA records if available
                    if issuer_org and caa_results.get("has_caa_records", False):
                        issuer_matched = False
                        for caa_record in caa_results.get("records", []):
                            if caa_record.get("tag") == "issue" or caa_record.get("tag") == "issuewild":
                                ca_domain = caa_record.get("value", "")
                                if ca_domain in str(issuer_org).lower():
                                    issuer_matched = True
                                    break
                        
                        if not issuer_matched:
                            results["warnings"].append(
                                "Certificate issuer does not appear to match CAA records"
                            )
                            results["recommendations"].append(
                                f"Update CAA records to include certificate issuer: {issuer_org}"
                            )
                    
                    results["certificate"] = certificate
                    
                    # Check protocol versions
                    if results["protocol_version"] == "TLSv1" or results["protocol_version"] == "TLSv1.1":
                        results["warnings"].append(f"Using outdated protocol: {results['protocol_version']}")
                        results["recommendations"].append("Upgrade to TLSv1.2 or TLSv1.3 for better security")
                        
                    # Check weak ciphers
                    if results["cipher"] and "CBC" in results["cipher"]["name"]:
                        results["warnings"].append(f"Using CBC mode cipher: {results['cipher']['name']}")
                        results["recommendations"].append("Configure server to prefer AEAD ciphers (GCM, CCM, ChaCha20-Poly1305)")
                        
                    # Add grade
                    results["grade"] = grade_ssl_configuration(results)
                    
    except ssl.SSLError as e:
        logger.error(f"SSL error for {domain}: {str(e)}")
        results["errors"].append(f"SSL error: {str(e)}")
        results["grade"] = "F"
        results["grade_description"] = "SSL connection failed"
        
    except socket.gaierror as e:
        logger.error(f"DNS resolution error for {domain}: {str(e)}")
        results["errors"].append(f"DNS resolution error: {str(e)}")
        results["grade"] = "F"
        results["grade_description"] = "DNS resolution failed"
        
    except socket.timeout as e:
        logger.error(f"Timeout connecting to {domain}: {str(e)}")
        results["errors"].append(f"Connection timeout: {str(e)}")
        results["grade"] = "F"
        results["grade_description"] = "Connection timed out"
        
    except Exception as e:
        logger.error(f"Error checking SSL for {domain}: {str(e)}")
        results["errors"].append(f"Error checking SSL: {str(e)}")
        results["grade"] = "F"
        results["grade_description"] = "Connection failed"
        
    return results

def check_caa_records(domain: str) -> Dict[str, Any]:
    """
    Checks CAA (Certificate Authority Authorization) records for a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: CAA record information and analysis
    """
    result = {
        "has_caa_records": False,
        "records": [],
        "errors": [],
        "warnings": [],
        "recommendations": []
    }
    
    try:
        # Try to resolve CAA records
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        
        try:
            answers = resolver.resolve(domain, 'CAA')
            result["has_caa_records"] = True
            
            for record in answers:
                caa_record = {
                    "flag": record.flags,
                    "tag": record.tag.decode('utf-8'),
                    "value": record.value.decode('utf-8')
                }
                result["records"].append(caa_record)
            
            # Check if issue records exist
            has_issue = False
            has_issuewild = False
            has_iodef = False
            
            for record in result["records"]:
                if record["tag"] == "issue":
                    has_issue = True
                elif record["tag"] == "issuewild":
                    has_issuewild = True
                elif record["tag"] == "iodef":
                    has_iodef = True
            
            # Add warnings and recommendations
            if not has_issue:
                result["warnings"].append("No 'issue' CAA records found")
                result["recommendations"].append("Add 'issue' CAA records to specify authorized certificate authorities")
                
            if not has_issuewild and has_issue:
                result["warnings"].append("No 'issuewild' CAA records found")
                result["recommendations"].append("Consider adding 'issuewild' CAA records for wildcard certificates")
                
            if not has_iodef:
                result["recommendations"].append("Consider adding 'iodef' CAA record for notification of certificate issuance violations")
                
        except dns.resolver.NoAnswer:
            result["has_caa_records"] = False
            result["warnings"].append("No CAA records found")
            result["recommendations"].append("Implement CAA records to restrict which CAs can issue certificates for your domain")
            
        except dns.resolver.NXDOMAIN:
            result["errors"].append("Domain does not exist")
            
        except Exception as e:
            result["errors"].append(f"Error checking CAA records: {str(e)}")
            
    except Exception as e:
        result["errors"].append(f"Error setting up resolver: {str(e)}")
        
    return result

def check_certificate_transparency(domain: str) -> Dict[str, Any]:
    """
    Queries Certificate Transparency (CT) logs for a domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: Certificate Transparency information
    """
    result = {
        "certificates_found": 0,
        "issuers": [],
        "certificates": [],
        "errors": [],
        "warnings": [],
        "recommendations": []
    }
    
    try:
        # Try to get the API key from environment
        import os
        ct_api_key = os.getenv("CERTSPOTTER_API_KEY", "")
        
        if not ct_api_key:
            logger.warning("No CERTSPOTTER_API_KEY found in environment variables")
            result["warnings"].append("No API key for Certificate Transparency logs")
        
        # Encode domain for URL
        encoded_domain = urllib.parse.quote(domain)
        
        # Query Certificate Spotter API
        url = f"https://api.certspotter.com/v1/issuances?domain={encoded_domain}&include_subdomains=true&expand=dns_names&expand=issuer"
        
        headers = {}
        if ct_api_key:
            headers["Authorization"] = f"Bearer {ct_api_key}"
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            try:
                data = response.json()
                
                if data:
                    # Process certificate data
                    issuers_seen = set()
                    valid_certs = []
                    
                    now = datetime.now()
                    
                    for cert in data:
                        # Skip expired certificates older than 90 days
                        try:
                            not_after = cert.get('not_after')
                            if not_after:
                                expiry_date = datetime.fromtimestamp(not_after)
                                if expiry_date < now - timedelta(days=90):
                                    continue
                        except (ValueError, TypeError):
                            # If we can't parse the date, still include it
                            pass
                        
                        # Get issuer name
                        issuer = cert.get('issuer', {})
                        if issuer:
                            issuer_name = issuer.get('name', '')
                            if issuer_name:
                                issuers_seen.add(issuer_name)
                        
                        # Get DNS names
                        dns_names = cert.get('dns_names', [])
                        
                        # Add to valid certificates
                        valid_certs.append({
                            "id": cert.get('id'),
                            "serial_number": cert.get('cert_sha256'),
                            "dns_names": dns_names[:5] if dns_names else [],  # Limit to 5 names
                            "issuer": issuer_name if 'issuer_name' in locals() else None,
                            "not_before": cert.get('not_before'),
                            "not_after": cert.get('not_after')
                        })
                    
                    # Update result
                    result["certificates_found"] = len(valid_certs)
                    result["issuers"] = list(issuers_seen)
                    
                    # Only include the 10 most recent certificates to avoid huge responses
                    result["certificates"] = valid_certs[:10]
                    
                    # Add recommendations based on CT log data
                    if len(issuers_seen) > 0:
                        ca_recommendations = []
                        for issuer in issuers_seen:
                            # Try to match with common CA issuers
                            matched_ca = None
                            for ca_domain, ca_name in COMMON_CA_ISSUERS.items():
                                if ca_domain.lower() in issuer.lower():
                                    matched_ca = ca_name
                                    break
                            
                            if matched_ca:
                                ca_recommendations.append(f"{matched_ca} ({issuer})")
                            else:
                                ca_recommendations.append(issuer)
                        
                        result["recommendations"].append(
                            f"Consider adding CAA records for detected certificate issuers: {', '.join(ca_recommendations[:3])}"
                        )
                    
                else:
                    result["warnings"].append("No certificates found in Certificate Transparency logs")
                    
            except (ValueError, json.JSONDecodeError) as e:
                result["errors"].append(f"Error parsing CT log response: {str(e)}")
                
        # Fallback to crt.sh if Certificate Spotter fails or returns no results
        elif response.status_code != 200 or result["certificates_found"] == 0:
            # Try crt.sh as fallback
            fallback_url = f"https://crt.sh/?q={encoded_domain}&output=json"
            
            fallback_response = requests.get(fallback_url, timeout=10)
            
            if fallback_response.status_code == 200:
                try:
                    fallback_data = fallback_response.json()
                    
                    if fallback_data:
                        # Process certificate data
                        issuers_seen = set()
                        valid_certs = []
                        
                        now = datetime.now()
                        
                        for cert in fallback_data:
                            # Skip expired certificates older than 90 days
                            try:
                                expiry_date = datetime.strptime(cert.get('not_after', ''), "%Y-%m-%dT%H:%M:%S")
                                if expiry_date < now - timedelta(days=90):
                                    continue
                            except (ValueError, TypeError):
                                # If we can't parse the date, still include it
                                pass
                            
                            # Get issuer name
                            issuer_name = cert.get('issuer_name', '')
                            if issuer_name:
                                # Extract organization from issuer name
                                org_match = re.search(r'O=([^,]+)', issuer_name)
                                if org_match:
                                    issuer_org = org_match.group(1).strip()
                                    issuers_seen.add(issuer_org)
                            
                            # Add to valid certificates
                            valid_certs.append({
                                "id": cert.get('id'),
                                "serial_number": cert.get('serial_number'),
                                "common_name": cert.get('common_name'),
                                "issuer": issuer_name,
                                "not_before": cert.get('not_before'),
                                "not_after": cert.get('not_after')
                            })
                        
                        # Update result
                        result["certificates_found"] = len(valid_certs)
                        result["issuers"] = list(issuers_seen)
                        
                        # Only include the 10 most recent certificates to avoid huge responses
                        result["certificates"] = valid_certs[:10]
                        
                        # Add recommendations based on CT log data
                        if len(issuers_seen) > 0:
                            ca_recommendations = []
                            for issuer in issuers_seen:
                                # Try to match with common CA issuers
                                matched_ca = None
                                for ca_domain, ca_name in COMMON_CA_ISSUERS.items():
                                    if ca_domain.lower() in issuer.lower():
                                        matched_ca = ca_name
                                        break
                                
                                if matched_ca:
                                    ca_recommendations.append(f"{matched_ca} ({issuer})")
                                else:
                                    ca_recommendations.append(issuer)
                            
                            result["recommendations"].append(
                                f"Consider adding CAA records for detected certificate issuers: {', '.join(ca_recommendations[:3])}"
                            )
                        
                    else:
                        result["warnings"].append("No certificates found in Certificate Transparency logs")
                        
                except (ValueError, json.JSONDecodeError) as e:
                    result["errors"].append(f"Error parsing fallback CT log response: {str(e)}")
            else:
                result["errors"].append(f"HTTP error from both CT log services: {response.status_code} and {fallback_response.status_code}")
        else:
            result["errors"].append(f"HTTP error from CT log: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        result["errors"].append(f"Error querying Certificate Transparency logs: {str(e)}")
        
    except Exception as e:
        result["errors"].append(f"Error in Certificate Transparency check: {str(e)}")
        
    return result

def grade_ssl_configuration(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Grades the SSL/TLS configuration based on protocol, cipher and certificate.
    
    Args:
        results (Dict): SSL check results
        
    Returns:
        Dict: Grade information
    """
    # Initialize with default grade
    grade = {
        "grade": "C",
        "description": "Average SSL configuration"
    }
    
    # Check if SSL is working at all
    if not results["has_ssl"]:
        grade["grade"] = "F"
        grade["description"] = "SSL not implemented"
        return grade
        
    # Check for certificate validity
    if not results["valid"]:
        grade["grade"] = "F"
        grade["description"] = "Invalid SSL certificate"
        return grade
    
    # Default to C grade
    points = 3.0
    
    # Check protocol version
    protocol = results.get("protocol_version")
    if protocol == "TLSv1.3":
        points += 2.0  # Excellent
    elif protocol == "TLSv1.2":
        points += 1.0  # Good
    elif protocol == "TLSv1.1":
        points -= 1.0  # Poor
    elif protocol == "TLSv1" or protocol == "SSLv3":
        points -= 2.0  # Very poor
    
    # Check cipher strength
    cipher = results.get("cipher")
    if cipher:
        if "GCM" in cipher.get("name", "") or "CHACHA20" in cipher.get("name", ""):
            points += 1.0  # Excellent ciphers
        elif "CBC" in cipher.get("name", ""):
            points -= 0.5  # CBC mode has some vulnerabilities
        
        # Check key bits
        bits = cipher.get("bits", 0)
        if bits >= 256:
            points += 1.0  # Excellent
        elif bits >= 128:
            points += 0.5  # Good
        elif bits <= 64:
            points -= 2.0  # Very poor
    
    # Check certificate expiration
    expires_in_days = results.get("expires_in_days")
    if expires_in_days is not None:
        if expires_in_days <= 0:
            points -= 3.0  # Expired
        elif expires_in_days < 15:
            points -= 2.0  # About to expire
        elif expires_in_days < 30:
            points -= 1.0  # Expiring soon
        elif expires_in_days > 365:
            points += 0.5  # Long validity
    
    # Check CAA records
    if results.get("caa_records", {}).get("has_caa_records", False):
        points += 1.0  # Has CAA records
    
    # Determine grade based on points
    if points >= 7.0:
        grade["grade"] = "A+"
        grade["description"] = "Excellent SSL configuration"
    elif points >= 6.0:
        grade["grade"] = "A"
        grade["description"] = "Very good SSL configuration"
    elif points >= 5.0:
        grade["grade"] = "A-"
        grade["description"] = "Good SSL configuration"
    elif points >= 4.0:
        grade["grade"] = "B"
        grade["description"] = "Decent SSL configuration"
    elif points >= 3.0:
        grade["grade"] = "C"
        grade["description"] = "Average SSL configuration"
    elif points >= 2.0:
        grade["grade"] = "D"
        grade["description"] = "Below average SSL configuration"
    else:
        grade["grade"] = "F"
        grade["description"] = "Poor SSL configuration"
    
    return grade
