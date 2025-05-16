import dns.resolver
from typing import Dict, Any
import logging

# Configure module logger
logger = logging.getLogger(__name__)

def get_dmarc_policy(domain: str) -> Dict[str, Any]:
    """
    Retrieves DMARC policy for a domain without analysis.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing DMARC policy information
    """
    results = {
        "record": None,
        "parsed": None,
        "found": False,
        "errors": []
    }
    
    try:
        resolver = dns.resolver.Resolver()
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            # Query DMARC record
            dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
            
            # Process DMARC records
            for record in dmarc_answers:
                txt_value = "".join(s.decode() for s in record.strings)
                
                # Check if this is a DMARC record
                if txt_value.startswith('v=DMARC1'):
                    results["record"] = txt_value
                    results["found"] = True
                    
                    # Parse DMARC record
                    parsed = {}
                    for tag in txt_value.split(';'):
                        tag = tag.strip()
                        if '=' in tag:
                            key, value = tag.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            parsed[key] = value
                    
                    results["parsed"] = parsed
                    break
                    
            if not results["found"]:
                results["errors"].append("No valid DMARC record found")
                
        except dns.resolver.NoAnswer:
            logger.info(f"No DMARC record found for {domain}")
            results["errors"].append("No DMARC record found")
            
        except dns.resolver.NXDOMAIN:
            logger.info(f"DMARC record does not exist for {domain}")
            results["errors"].append("DMARC record does not exist")
            
    except Exception as e:
        logger.error(f"Error retrieving DMARC policy for {domain}: {str(e)}")
        results["errors"].append(f"Error retrieving DMARC policy: {str(e)}")
        
    return results
