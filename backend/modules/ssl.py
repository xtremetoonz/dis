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
                    
                    # Generate CAA recommendations based on certificate and CT logs
                    if not caa_results.get("has_caa_records", False):
                        # Clear existing CAA recommendations (which are generic)
                        recommendations = [rec for rec in results["recommendations"] 
                                           if "CAA record" not in rec and "CA " not in rec]
                        
                        # Generate specific CAA recommendations
                        caa_recommendations = generate_caa_recommendations(results)
                        recommendations.extend(caa_recommendations)
                        
                        # Update recommendations list
                        results["recommendations"] = recommendations
                    
                    # Add grade
                    results["grade"] = grade_ssl_configuration(results)
                    
    except ssl.SSLError as e:
        logger.error(f"SSL error for {domain}: {str(e)}")
        results["errors"].append(f"SSL error: {str(e)}")
        results["grade"] = {
            "grade": "F",
            "description": "SSL connection failed"
        }
        
    except socket.gaierror as e:
        logger.error(f"DNS resolution error for {domain}: {str(e)}")
        results["errors"].append(f"DNS resolution error: {str(e)}")
        results["grade"] = {
            "grade": "F",
            "description": "DNS resolution failed"
        }
        
    except socket.timeout as e:
        logger.error(f"Timeout connecting to {domain}: {str(e)}")
        results["errors"].append(f"Connection timeout: {str(e)}")
        results["grade"] = {
            "grade": "F",
            "description": "Connection timed out"
        }
        
    except Exception as e:
        logger.error(f"Error checking SSL for {domain}: {str(e)}")
        results["errors"].append(f"Error checking SSL: {str(e)}")
        results["grade"] = {
            "grade": "F",
            "description": "Connection failed"
        }
        
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

def generate_caa_recommendations(results: Dict[str, Any]) -> List[str]:
    """
    Generates specific CAA record recommendations based on CT logs and certificate data.

    Args:
        results (Dict): SSL check results

    Returns:
        List[str]: List of specific recommendations
    """
    recommendations = []

    # Check if CAA records already exist
    caa_records = results.get("caa_records", {})
    if caa_records.get("has_caa_records", False):
        # Existing CAA records found - check if they're complete
        has_issue = False
        has_issuewild = False
        has_iodef = False

        for record in caa_records.get("records", []):
            tag = record.get("tag", "")
            if tag == "issue":
                has_issue = True
            elif tag == "issuewild":
                has_issuewild = True
            elif tag == "iodef":
                has_iodef = True

        # Add recommendations for missing record types
        if not has_issue:
            recommendations.append("Add 'issue' CAA record to specify authorized certificate authorities")

        if not has_issuewild:
            recommendations.append("Add 'issuewild' CAA record to control wildcard certificate issuance")

        if not has_iodef:
            recommendations.append("Add 'iodef' CAA record for violation reporting")

        return recommendations

    # No CAA records - generate recommendations based on certificate and CT logs

    # First, check current certificate
    certificate = results.get("certificate", {})
    current_issuer = None
    issuer_org = certificate.get("issuer_organization")

    if issuer_org:
        current_issuer = issuer_org

        # Try to match with common CA names
        matched_ca = None
        for ca_domain, ca_name in COMMON_CA_ISSUERS.items():
            if ca_domain.lower() in str(issuer_org).lower():
                matched_ca = ca_name
                break

        if matched_ca:
            recommendations.append(
                f"Add CAA record: '0 issue \"{ca_domain}\"' to allow {matched_ca}"
            )
        else:
            # Generic recommendation based on current issuer
            recommendations.append(
                f"Add CAA record: '0 issue \"{issuer_org}\"' based on your current certificate issuer"
            )

    # Next, check CT logs for additional issuers
    ct_logs = results.get("ct_logs", {})
    issuers = ct_logs.get("issuers", [])

    if issuers:
        # Find issuers different from the current one
        other_issuers = [issuer for issuer in issuers
                        if current_issuer is None or issuer.lower() not in current_issuer.lower()]

        # Create recommendations for other issuers seen in CT logs
        for issuer in other_issuers[:2]:  # Limit to 2 additional issuers
            # Try to match with common CA names
            for ca_domain, ca_name in COMMON_CA_ISSUERS.items():
                if ca_domain.lower() in issuer.lower():
                    recommendations.append(
                        f"Consider adding CAA record: '0 issue \"{ca_domain}\"' to allow {ca_name} "
                        f"(previously used for this domain according to CT logs)"
                    )
                    break

    # Add wildcard recommendation if using a wildcard certificate
    if certificate.get("has_wildcard", False):
        if current_issuer:
            # If we already have a current issuer
            recommendations.append(
                f"Add CAA record: '0 issuewild \"{current_issuer}\"' to control wildcard certificate issuance"
            )
        else:
            # Generic recommendation
            recommendations.append(
                "Add 'issuewild' CAA record to control wildcard certificate issuance"
            )

    # Always recommend iodef
    recommendations.append(
        "Add CAA record: '0 iodef \"mailto:security@yourdomain.com\"' for violation reporting "
        "(replace with your security contact email)"
    )

    # If no specific recommendations could be generated
    if not recommendations:
        recommendations.append(
            "Implement CAA records to restrict which Certificate Authorities can issue certificates for your domain"
        )
        recommendations.append(
            "Example CAA record: '0 issue \"letsencrypt.org\"' for Let's Encrypt"
        )

    # Add a general guide at the end
    recommendations.append(
        "For more information on implementing CAA records, consult your DNS provider's documentation"
    )

    return recommendations

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
    Grades the SSL/TLS configuration based on protocol, cipher, certificate, and CAA records.

    Args:
        results (Dict): SSL check results

    Returns:
        Dict: Grade information
    """
    # Initialize with default grade
    grade = {
        "grade": "C",
        "description": "Average SSL configuration",
        "points": 0,
        "details": []  # Add a detailed breakdown of points
    }

    # Check if SSL is working at all
    if not results["has_ssl"]:
        grade["grade"] = "F"
        grade["description"] = "SSL not implemented"
        grade["points"] = 0
        grade["details"].append("No SSL/TLS implementation found (-5.0)")
        return grade

    # Check for certificate validity
    if not results["valid"]:
        grade["grade"] = "F"
        grade["description"] = "Invalid SSL certificate"
        grade["points"] = 0
        grade["details"].append("Invalid SSL certificate (-5.0)")
        return grade

    # Start with baseline points
    points = 3.0
    grade["details"].append("Baseline score (3.0)")

    # --- Check protocol version ---
    protocol = results.get("protocol_version")
    if protocol == "TLSv1.3":
        points += 2.0  # Excellent
        grade["details"].append("Using TLSv1.3 (+2.0)")
    elif protocol == "TLSv1.2":
        points += 1.0  # Good
        grade["details"].append("Using TLSv1.2 (+1.0)")
    elif protocol == "TLSv1.1":
        points -= 1.0  # Poor
        grade["details"].append("Using outdated TLSv1.1 (-1.0)")
    elif protocol == "TLSv1" or protocol == "SSLv3":
        points -= 2.0  # Very poor
        grade["details"].append(f"Using obsolete protocol {protocol} (-2.0)")

    # --- Check cipher strength ---
    cipher = results.get("cipher")
    if cipher:
        cipher_name = cipher.get("name", "")

        if "GCM" in cipher_name or "CHACHA20" in cipher_name:
            points += 1.0  # Excellent ciphers
            grade["details"].append(f"Using strong AEAD cipher: {cipher_name} (+1.0)")
        elif "CBC" in cipher_name:
            points -= 0.5  # CBC mode has some vulnerabilities
            grade["details"].append(f"Using CBC mode cipher: {cipher_name} (-0.5)")

        # Check key bits
        bits = cipher.get("bits", 0)
        if bits >= 256:
            points += 1.0  # Excellent
            grade["details"].append(f"Strong cipher strength: {bits} bits (+1.0)")
        elif bits >= 128:
            points += 0.5  # Good
            grade["details"].append(f"Good cipher strength: {bits} bits (+0.5)")
        elif bits <= 64:
            points -= 2.0  # Very poor
            grade["details"].append(f"Weak cipher strength: {bits} bits (-2.0)")

    # --- Check certificate expiration ---
    expires_in_days = results.get("expires_in_days")
    if expires_in_days is not None:
        if expires_in_days <= 0:
            points -= 3.0  # Expired
            grade["details"].append("Certificate has expired (-3.0)")
        elif expires_in_days < 15:
            points -= 2.0  # About to expire
            grade["details"].append(f"Certificate expires in {expires_in_days} days (-2.0)")
        elif expires_in_days < 30:
            points -= 1.0  # Expiring soon
            grade["details"].append(f"Certificate expires in {expires_in_days} days (-1.0)")
        elif expires_in_days > 365:
            points += 0.5  # Long validity
            grade["details"].append(f"Long certificate validity: {expires_in_days} days (+0.5)")

    # --- Enhanced CAA record checking ---
    caa_records = results.get("caa_records", {})
    caa_record_types = set()

    # Basic CAA presence check
    if caa_records.get("has_caa_records", False):
        # Start with base points for having CAA
        caa_points = 0.5
        grade["details"].append("Has CAA records (+0.5)")

        # Check for specific record types
        has_issue = False
        has_issuewild = False
        has_iodef = False

        for record in caa_records.get("records", []):
            record_tag = record.get("tag", "")
            caa_record_types.add(record_tag)

            if record_tag == "issue":
                has_issue = True
            elif record_tag == "issuewild":
                has_issuewild = True
            elif record_tag == "iodef":
                has_iodef = True

        # Award points for comprehensive CAA implementation
        if has_issue:
            caa_points += 0.5
            grade["details"].append("Has 'issue' CAA record (+0.5)")

        if has_issuewild:
            caa_points += 0.5
            grade["details"].append("Has 'issuewild' CAA record (+0.5)")

        if has_iodef:
            caa_points += 0.5
            grade["details"].append("Has 'iodef' CAA record for reporting (+0.5)")

        # Check if certificate issuer matches CAA records
        cert_info = results.get("certificate", {})
        issuer_org = cert_info.get("issuer_organization")

        if issuer_org and has_issue:
            # Check if any CAA record value contains the issuer name
            issuer_matched = False
            for record in caa_records.get("records", []):
                if record.get("tag") == "issue":
                    ca_domain = record.get("value", "")
                    # Simple substring check - a more sophisticated check would be better
                    if ca_domain.lower() in str(issuer_org).lower() or str(issuer_org).lower() in ca_domain.lower():
                        issuer_matched = True
                        break

            if issuer_matched:
                caa_points += 0.5
                grade["details"].append("Certificate issuer matches CAA records (+0.5)")
            else:
                # Minor deduction - this is just a warning, not a serious issue
                caa_points -= 0.2
                grade["details"].append("Certificate issuer may not match CAA records (-0.2)")

        # Cap the total CAA points
        caa_points = min(2.0, caa_points)
        points += caa_points

    else:
        # No CAA records
        grade["details"].append("No CAA records (0.0)")

    # --- Wildcard certificate check ---
    cert_info = results.get("certificate", {})
    if cert_info.get("has_wildcard", False):
        # Wildcard certificates are slightly less secure - small deduction
        points -= 0.3
        grade["details"].append("Using wildcard certificate (-0.3)")

    # --- Final grade calculation ---
    # Store the total points
    grade["points"] = round(max(0.0, min(10.0, points)), 1)  # Clamp between 0-10

    # Determine grade based on points
    if points >= 7.5:
        grade["grade"] = "A+"
        grade["description"] = "Excellent SSL configuration"
    elif points >= 6.5:
        grade["grade"] = "A"
        grade["description"] = "Very good SSL configuration"
    elif points >= 5.5:
        grade["grade"] = "A-"
        grade["description"] = "Good SSL configuration"
    elif points >= 4.5:
        grade["grade"] = "B+"
        grade["description"] = "Above average SSL configuration"
    elif points >= 3.5:
        grade["grade"] = "B"
        grade["description"] = "Decent SSL configuration"
    elif points >= 2.5:
        grade["grade"] = "C+"
        grade["description"] = "Average SSL configuration"
    elif points >= 1.5:
        grade["grade"] = "C"
        grade["description"] = "Below average SSL configuration"
    elif points >= 0.5:
        grade["grade"] = "D"
        grade["description"] = "Poor SSL configuration"
    else:
        grade["grade"] = "F"
        grade["description"] = "Failing SSL configuration"

    # Add CAA status to description if it significantly affects the grade
    if caa_records.get("has_caa_records", False) and len(caa_record_types) >= 2:
        grade["description"] += " with good CAA records"
    elif not caa_records.get("has_caa_records", False) and points >= 5.0:
        grade["description"] += " (could be improved with CAA records)"

    return grade
