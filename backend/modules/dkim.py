import dns.resolver
import re
from typing import Dict, List, Any, Optional, Set
import logging
import json

# Configure module logger
logger = logging.getLogger(__name__)

# Default selectors to check if none provided
DEFAULT_SELECTORS = [
    # Microsoft selectors - always check these
    "selector1", "selector2",
    # Google Workspace selectors - always check these
    "google", "s1", "s2",
    # Common email provider selectors
    "default", "dkim", "k1", "mail",
    # Common ESP selectors
    "sendgrid", "amazonses"
]

# Provider groupings for selectors
PROVIDER_GROUPS = {
    "Microsoft": ["selector1", "selector2"],
    "Google": ["google", "s1", "s2"],
    "Amazon SES": ["amazonses"],
    "Mailchimp/Mandrill": ["k1", "k2", "k3", "mte1", "mte2", "mandrill"],
    "SendGrid": ["sendgrid", "smtpapi"],
    "Generic": ["default", "dkim", "mail", "key1"]
}

def get_authoritative_nameserver(domain: str) -> Optional[str]:
    """
    Get the authoritative nameserver for a domain.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Optional[str]: Primary nameserver or None if not found
    """
    try:
        soa_answers = dns.resolver.resolve(domain, 'SOA')
        if soa_answers:
            # Return the primary nameserver from the SOA record
            return str(soa_answers[0].mname).rstrip('.')
        return None
    except Exception as e:
        logger.error(f"Error getting authoritative nameserver for {domain}: {str(e)}")
        return None

def get_nameserver_ip(nameserver: str) -> Optional[str]:
    """
    Get the IP address for a nameserver.
    
    Args:
        nameserver (str): Nameserver hostname
        
    Returns:
        Optional[str]: IP address or None if not found
    """
    try:
        a_records = dns.resolver.resolve(nameserver, 'A')
        if a_records:
            return str(a_records[0])
        return None
    except Exception as e:
        logger.error(f"Error resolving nameserver IP for {nameserver}: {str(e)}")
        return None

def create_resolver_for_domain(domain: str, query_domain: str) -> dns.resolver.Resolver:
    """
    Creates a resolver appropriate for the domain being queried.
    For subdomains of the main domain, uses the authoritative nameserver.
    For external domains, uses the default resolver.
    
    Args:
        domain (str): The main domain being checked
        query_domain (str): The specific domain to query (might be different for CNAME)
        
    Returns:
        dns.resolver.Resolver: Configured resolver
    """
    resolver = dns.resolver.Resolver()
    # Set shorter timeouts for all resolvers
    resolver.timeout = 2.0  # 2 seconds per attempt
    resolver.lifetime = 5.0  # 5 seconds total
    
    # Check if query_domain is a subdomain of the main domain
    if query_domain.endswith('.' + domain) or query_domain == domain:
        # Use authoritative nameserver for this domain
        try:
            auth_ns = get_authoritative_nameserver(domain)
            if auth_ns:
                ns_ip = get_nameserver_ip(auth_ns)
                if ns_ip:
                    resolver.nameservers = [ns_ip]
                    logger.info(f"Using authoritative nameserver {auth_ns} ({ns_ip}) for {query_domain}")
                    return resolver
        except Exception as e:
            logger.warning(f"Could not use authoritative nameserver for {query_domain}: {str(e)}")
    
    # For external domains or if authoritative NS fails, use default resolver
    logger.info(f"Using default resolver for {query_domain}")
    return resolver

def get_mx_provider(domain: str) -> Optional[str]:
    """
    Determines the email provider based on MX records.
    
    Args:
        domain (str): Domain to check
        
    Returns:
        Optional[str]: Detected provider or None
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 5.0
        
        mx_records = resolver.resolve(domain, 'MX')
        
        for record in mx_records:
            mx_hostname = str(record.exchange).lower().rstrip('.')
            
            # Check for Microsoft
            if any(microsoft_domain in mx_hostname for microsoft_domain in [
                "outlook.com", "protection.outlook.com", "mail.protection.outlook.com",
                "hotmail.com", "microsoft.com"
            ]):
                return "Microsoft"
                
            # Check for Google
            if any(google_domain in mx_hostname for google_domain in [
                "google.com", "googlemail.com", "gmail.com", "aspmx.l.google.com",
                "alt1.aspmx.l.google.com", "alt2.aspmx.l.google.com", 
                "aspmx2.googlemail.com", "aspmx3.googlemail.com", "aspmx4.googlemail.com",
                "aspmx5.googlemail.com"
            ]):
                return "Google"
                
            # Could add other providers here
                
    except Exception as e:
        logger.error(f"Error determining MX provider for {domain}: {str(e)}")
        
    return None

def has_valid_dkim_key(txt_record: str) -> bool:
    """
    Checks if a TXT record contains a valid DKIM key.
    
    Args:
        txt_record (str): The TXT record content
        
    Returns:
        bool: True if record contains a valid DKIM key
    """
    # Basic validation - must have v=DKIM1 and p= tags
    return 'v=DKIM1' in txt_record and 'p=' in txt_record

def check_dkim_selector(domain: str, selector: str, follow_cname: bool = True) -> Dict[str, Any]:
    """
    Checks a single DKIM selector.
    
    Args:
        domain (str): Domain to check
        selector (str): DKIM selector to check
        follow_cname (bool): Whether to follow CNAME records
        
    Returns:
        Dict: Results of the DKIM selector check
    """
    result = {
        "selector": selector,
        "domain": domain,
        "fqdn": f"{selector}._domainkey.{domain}",
        "found": False,
        "has_valid_key": False,
        "is_cname": False,
        "cname_target": None,
        "txt_record": None,
        "errors": [],
        "warnings": []
    }
    
    fqdn = f"{selector}._domainkey.{domain}"
    
    try:
        # Use appropriate resolver
        resolver = create_resolver_for_domain(domain, fqdn)
        
        # Check for CNAME record first
        try:
            cname_records = resolver.resolve(fqdn, 'CNAME')
            cname_target = str(cname_records[0]).rstrip('.')
            
            result["found"] = True
            result["is_cname"] = True
            result["cname_target"] = cname_target
            
            # Follow CNAME if requested
            if follow_cname:
                try:
                    # Use default resolver for external domains
                    cname_resolver = create_resolver_for_domain(domain, cname_target)
                    txt_records = cname_resolver.resolve(cname_target, 'TXT')
                    
                    for txt_record in txt_records:
                        txt_value = "".join(s.decode() for s in txt_record.strings)
                        
                        if has_valid_dkim_key(txt_value):
                            result["txt_record"] = txt_value
                            result["has_valid_key"] = True
                            break
                            
                    if not result["has_valid_key"]:
                        result["errors"].append(f"CNAME target {cname_target} does not contain a valid DKIM key")
                        
                except Exception as e:
                    result["errors"].append(f"Error resolving TXT record for CNAME target {cname_target}: {str(e)}")
            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # No CNAME, try TXT directly
            try:
                txt_records = resolver.resolve(fqdn, 'TXT')
                
                for txt_record in txt_records:
                    txt_value = "".join(s.decode() for s in txt_record.strings)
                    
                    if has_valid_dkim_key(txt_value):
                        result["found"] = True
                        result["txt_record"] = txt_value
                        result["has_valid_key"] = True
                        break
                        
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # No TXT record found
                pass
            except Exception as e:
                result["errors"].append(f"Error resolving TXT record for {fqdn}: {str(e)}")
                
    except Exception as e:
        result["errors"].append(f"Error checking DKIM selector {selector} for {domain}: {str(e)}")
        
    return result

def check_dkim_selectors(domain: str, selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Checks DKIM selectors for a domain and validates both Microsoft and Google selectors.

    Args:
        domain (str): Domain to check
        selectors (List[str], optional): List of selectors to check. If None, checks defaults.

    Returns:
        Dict: Dictionary containing DKIM check results
    """
    results = {
        "domain": domain,
        "selectors_checked_count": 0,
        "selectors_found": [],
        "mx_provider_detected": None,
        "records": {},
        "errors": [],
        "warnings": [],
        "recommendations": []
    }

    try:
        # Try to determine email provider from MX records
        mx_provider = get_mx_provider(domain)
        results["mx_provider_detected"] = mx_provider

        # Keep track of which selectors were explicitly requested
        explicit_selectors = set(selectors) if selectors else set()

        # Determine which selectors to check
        if selectors:
            # User specified selectors - check only those
            selectors_to_check = selectors
            # Don't add provider-specific warnings when explicit selectors are requested
            check_provider_specific = False
        else:
            # Always check both Microsoft and Google selectors, plus common ones
            selectors_to_check = PROVIDER_GROUPS["Microsoft"] + PROVIDER_GROUPS["Google"] + [
                "default", "dkim", "k1", "mail", "sendgrid", "amazonses"
            ]
            # Do add provider-specific warnings when no selectors are specified
            check_provider_specific = True

        results["selectors_checked_count"] = len(selectors_to_check)

        # Track selectors actually found
        found_selectors = []
        valid_selectors = []

        # Store provider-specific status
        microsoft_found = []
        microsoft_valid = []
        google_found = []
        google_valid = []

        # Check each selector
        for selector in selectors_to_check:
            try:
                selector_result = check_dkim_selector(domain, selector)

                # If found, track it
                if selector_result["found"]:
                    found_selectors.append(selector)

                    # Check if it has a valid key
                    if selector_result["has_valid_key"]:
                        valid_selectors.append(selector)

                        # Add to records dictionary (always include valid selectors)
                        results["records"][selector] = selector_result

                    else:
                        # Found but invalid - issue a warning
                        results["warnings"].append(f"Selector {selector} found but does not contain a valid DKIM key")

                        # Add Microsoft-specific recommendation for key rotation
                        if selector in PROVIDER_GROUPS["Microsoft"]:
                            microsoft_key_message = "Go to your Microsoft DKIM admin center and rotate your keys"
                            results["recommendations"].append(microsoft_key_message)
                            results["warnings"].append(microsoft_key_message)  # Also add to warnings

                        # Include in output if it's Microsoft, Google, or explicitly requested
                        if (selector in PROVIDER_GROUPS["Microsoft"] or
                            selector in PROVIDER_GROUPS["Google"] or
                            selector in explicit_selectors):
                            results["records"][selector] = selector_result

                    # Track Microsoft selectors
                    if selector in PROVIDER_GROUPS["Microsoft"]:
                        microsoft_found.append(selector)
                        if selector_result["has_valid_key"]:
                            microsoft_valid.append(selector)

                    # Track Google selectors
                    if selector in PROVIDER_GROUPS["Google"]:
                        google_found.append(selector)
                        if selector_result["has_valid_key"]:
                            google_valid.append(selector)

            except Exception as e:
                logger.error(f"Error checking selector {selector}: {str(e)}")
                # Don't include errors for selectors that failed in the output

        # Update selectors_found with actually found selectors
        results["selectors_found"] = found_selectors

        # Add provider-specific information only if relevant
        results["provider_status"] = {}

        # Only include Microsoft status if Microsoft selectors were found or MX is Microsoft
        if microsoft_found or mx_provider == "Microsoft":
            results["provider_status"]["Microsoft"] = {
                "selectors_found": microsoft_found,
                "selectors_valid": microsoft_valid,
                "configured": len(microsoft_valid) > 0
            }

        # Only include Google status if Google selectors were found or MX is Google
        if google_found or mx_provider == "Google":
            results["provider_status"]["Google"] = {
                "selectors_found": google_found,
                "selectors_valid": google_valid,
                "configured": len(google_valid) > 0
            }

        # Provider-specific recommendations
        # Only make provider-specific recommendations if not checking explicit selectors
        # or if the explicit selectors include provider selectors
        if check_provider_specific or any(s in explicit_selectors for s in PROVIDER_GROUPS["Microsoft"]):
            # If MX is Microsoft but Microsoft DKIM is not configured
            if mx_provider == "Microsoft" and (not microsoft_valid):
                if not microsoft_found:
                    results["errors"].append("Microsoft MX detected but no Microsoft DKIM selectors found")
                    results["recommendations"].append("Add Microsoft DKIM selectors: selector1 and selector2")
                else:
                    results["errors"].append("Microsoft MX detected but Microsoft DKIM selectors don't have valid keys")
                    results["recommendations"].append("Configure valid DKIM keys for Microsoft selectors")
                    # Note: The specific recommendation for key rotation is now added when the selector is checked

        # Only make Google-specific recommendations if we're not checking explicit selectors
        # or if the explicit selectors include Google selectors
        if check_provider_specific or any(s in explicit_selectors for s in PROVIDER_GROUPS["Google"]):
            # If MX is Google but Google DKIM is not configured
            if mx_provider == "Google" and (not google_valid):
                if not google_found:
                    results["errors"].append("Google MX detected but no Google DKIM selectors found")
                    results["recommendations"].append("Add at least one Google DKIM selector (google, s1, or s2)")
                else:
                    results["errors"].append("Google MX detected but Google DKIM selectors don't have valid keys")
                    results["recommendations"].append("Configure valid DKIM keys for Google selectors")

        # If no DKIM is configured at all and we're not doing an explicit selector check
        if check_provider_specific and not found_selectors:
            results["errors"].append("No DKIM selectors found")
            results["recommendations"].append("Implement DKIM to improve email deliverability and security")
        elif check_provider_specific and not valid_selectors:
            results["errors"].append("DKIM selectors found but none have valid keys")
            results["recommendations"].append("Ensure DKIM selectors have valid keys")

        # Add stats about found selectors
        results["stats"] = {
            "selectors_found_count": len(found_selectors),
            "selectors_with_valid_keys": len(valid_selectors),
            "status": "configured" if valid_selectors else "missing"
        }

    except Exception as e:
        results["errors"].append(f"Error checking DKIM selectors: {str(e)}")

    # Ensure the result is JSON serializable
    try:
        json.dumps(results)
    except (TypeError, OverflowError) as e:
        logger.error(f"JSON serialization error: {str(e)}")
        # Return a simplified version that will serialize
        return {
            "domain": domain,
            "selectors_checked_count": results.get("selectors_checked_count", 0),
            "selectors_found": results.get("selectors_found", []),
            "mx_provider_detected": results.get("mx_provider_detected"),
            "errors": results.get("errors", []) + ["JSON serialization error"],
            "warnings": results.get("warnings", []),
            "recommendations": results.get("recommendations", [])
        }

    return results
