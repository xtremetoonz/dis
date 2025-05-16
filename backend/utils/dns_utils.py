import dns.resolver
import dns.exception
import logging

logger = logging.getLogger(__name__)

def get_authoritative_nameserver(domain):
    """
    Get the authoritative nameserver for a domain
    
    Args:
        domain (str): Domain to check
        
    Returns:
        str: Primary nameserver or None if not found
    """
    try:
        soa_answers = dns.resolver.resolve(domain, 'SOA')
        if soa_answers:
            # Return the primary nameserver from the SOA record
            return str(soa_answers[0].mname)
        return None
    except Exception as e:
        logger.error(f"Error getting authoritative nameserver for {domain}: {str(e)}")
        return None

def is_domain_exists(domain):
    """
    Check if a domain exists by looking for SOA record
    
    Args:
        domain (str): Domain to check
        
    Returns:
        bool: True if domain exists
    """
    try:
        dns.resolver.resolve(domain, 'SOA')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception as e:
        logger.error(f"Error checking if domain exists: {str(e)}")
        return False
