import ssl
import socket
from datetime import datetime
import logging
from typing import Dict, Any

# Configure module logger
logger = logging.getLogger(__name__)

def get_ssl_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves SSL/TLS information for a domain without analysis.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing SSL/TLS information
    """
    results = {
        "has_ssl": False,
        "certificate": None,
        "protocol_version": None,
        "cipher": None,
        "valid": False,
        "errors": []
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the domain
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results["has_ssl"] = True
                results["protocol_version"] = ssock.version()
                results["cipher"] = ssock.cipher()
                
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
                    
                    # Get subject alternative names
                    if 'subjectAltName' in cert:
                        for type_name, value in cert['subjectAltName']:
                            if type_name == 'DNS':
                                certificate["alt_names"].append(value)
                    
                    results["certificate"] = certificate
                    
    except ssl.SSLError as e:
        logger.error(f"SSL error for {domain}: {str(e)}")
        results["errors"].append(f"SSL error: {str(e)}")
        
    except socket.gaierror as e:
        logger.error(f"DNS resolution error for {domain}: {str(e)}")
        results["errors"].append(f"DNS resolution error: {str(e)}")
        
    except socket.timeout as e:
        logger.error(f"Timeout connecting to {domain}: {str(e)}")
        results["errors"].append(f"Connection timeout: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error checking SSL for {domain}: {str(e)}")
        results["errors"].append(f"Error checking SSL: {str(e)}")
        
    return results
