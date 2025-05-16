import dns.resolver
from typing import Dict, List, Any
import logging

# Configure module logger
logger = logging.getLogger(__name__)

def get_mx_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves MX records for a domain without analysis.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing MX records and related information
    """
    results = {
        "mx_records": [],
        "has_mx": False,
        "errors": []
    }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        
        # Query MX records
        mx_answers = resolver.resolve(domain, 'MX')
        
        # Process MX records
        mx_records = []
        for rdata in mx_answers:
            mx_name = str(rdata.exchange).rstrip('.')
            
            # Try to get IP addresses for the MX server
            try:
                a_records = resolver.resolve(mx_name, 'A')
                ip_addresses = [str(ip) for ip in a_records]
            except Exception:
                ip_addresses = []
                
            mx_records.append({
                "preference": rdata.preference,
                "exchange": mx_name,
                "ip_addresses": ip_addresses
            })
            
        results["mx_records"] = sorted(mx_records, key=lambda x: x["preference"])
        results["has_mx"] = len(mx_records) > 0
        
    except dns.resolver.NoAnswer:
        logger.info(f"No MX records found for {domain}")
        results["errors"].append("No MX records found")
        
    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain {domain} does not exist")
        results["errors"].append("Domain does not exist")
        
    except Exception as e:
        logger.error(f"Error retrieving MX records for {domain}: {str(e)}")
        results["errors"].append(f"Error retrieving MX records: {str(e)}")
        
    return results
