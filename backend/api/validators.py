import re
from flask import request
from .errors import BadRequestError

# Domain validation regex pattern
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$',
    re.IGNORECASE
)

def validate_domain(domain):
    """
    Validates that a domain name matches the expected format.
    
    Args:
        domain (str): Domain name to validate
        
    Returns:
        bool: True if valid, False otherwise
        
    Raises:
        BadRequestError: If domain is invalid
    """
    if not domain:
        raise BadRequestError("Domain parameter is required")
        
    if not isinstance(domain, str):
        raise BadRequestError("Domain must be a string")
        
    if not DOMAIN_PATTERN.match(domain):
        raise BadRequestError("Invalid domain format")
        
    return True

def get_domain_param():
    """
    Extract and validate domain from request parameters
    
    Returns:
        str: Validated domain name
        
    Raises:
        BadRequestError: If domain is missing or invalid
    """
    domain = request.args.get('domain')
    validate_domain(domain)
    return domain
