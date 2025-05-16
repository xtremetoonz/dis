import dns.resolver
import re
from typing import Dict, Any, List, Optional
import logging
import json
import ipaddress

# Configure module logger
logger = logging.getLogger(__name__)

# DMARC tag definitions
DMARC_TAGS = {
    "v": {"required": True, "description": "Protocol version"},
    "p": {"required": True, "description": "Policy for the domain", 
         "values": ["none", "quarantine", "reject"]},
    "sp": {"required": False, "description": "Policy for subdomains", 
          "values": ["none", "quarantine", "reject"]},
    "pct": {"required": False, "description": "Percentage of messages to filter"},
    "rua": {"required": False, "description": "Aggregate report URI"},
    "ruf": {"required": False, "description": "Forensic report URI"},
    "fo": {"required": False, "description": "Failure reporting options", 
          "values": ["0", "1", "d", "s"]},
    "adkim": {"required": False, "description": "DKIM alignment mode", 
             "values": ["r", "s"]},
    "aspf": {"required": False, "description": "SPF alignment mode", 
            "values": ["r", "s"]},
    "ri": {"required": False, "description": "Report interval"}
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

def create_auth_resolver(domain: str) -> dns.resolver.Resolver:
    """
    Creates a resolver configured to use domain's authoritative nameserver.
    
    Args:
        domain (str): Domain to find authoritative nameserver for
        
    Returns:
        dns.resolver.Resolver: Configured resolver
    """
    resolver = dns.resolver.Resolver()
    
    try:
        # Get the authoritative nameserver
        auth_ns = get_authoritative_nameserver(domain)
        if auth_ns:
            # Get the IP address
            ns_ip = get_nameserver_ip(auth_ns)
            if ns_ip:
                # Configure resolver to use this nameserver
                resolver.nameservers = [ns_ip]
                resolver.timeout = 5.0
                resolver.lifetime = 10.0
                logger.info(f"Using authoritative nameserver {auth_ns} ({ns_ip}) for DMARC query on {domain}")
                return resolver
    except Exception as e:
        logger.error(f"Error setting up authoritative resolver: {str(e)}")
    
    # If anything fails, return default resolver
    logger.warning(f"Using default resolver for DMARC query on {domain}")
    return resolver

def validate_uri(uri: str) -> Dict[str, Any]:
    """
    Validate a URI for DMARC reporting.
    
    Args:
        uri (str): URI to validate
        
    Returns:
        Dict: Validation results
    """
    result = {
        "uri": uri,
        "valid": False,
        "scheme": None,
        "address": None,
        "errors": []
    }
    
    # Basic structure check
    if ":" not in uri:
        result["errors"].append("URI missing scheme separator ':'")
        return result
        
    # Split scheme and address
    scheme, address = uri.split(":", 1)
    result["scheme"] = scheme.lower()
    result["address"] = address
    
    # Check scheme
    valid_schemes = ["mailto", "https"]
    if scheme.lower() not in valid_schemes:
        result["errors"].append(f"Invalid scheme: {scheme}. Must be one of: {', '.join(valid_schemes)}")
        
    # Check mailto format
    if scheme.lower() == "mailto":
        # Basic email format check
        if "@" not in address:
            result["errors"].append("Invalid email address: missing @")
        else:
            username, domain = address.split("@", 1)
            if not username:
                result["errors"].append("Invalid email address: missing username")
            if not domain:
                result["errors"].append("Invalid email address: missing domain")
                
    # Check https format
    elif scheme.lower() == "https":
        if not address.startswith("//"):
            result["errors"].append("HTTPS URI should start with //")
            
    # Set valid flag
    result["valid"] = len(result["errors"]) == 0
    
    return result

def check_all_reporting_destinations(parsed_policy: Dict[str, str], domain: str) -> Dict[str, Any]:
    """
    Check all reporting destinations (both RUA and RUF) for potential issues.
    
    Args:
        parsed_policy (Dict): Parsed DMARC policy tags
        domain (str): The domain being checked
        
    Returns:
        Dict: Combined reporting analysis
    """
    result = {
        "aggregate": None,
        "forensic": None,
        "warnings": [],
        "recommendations": [],
        "errors": []
    }
    
    # Track if any reports are sent to the same domain
    reports_to_self = False
    has_postmaster = False
    
    # Process RUA (aggregate reports)
    rua = parsed_policy.get("rua")
    if rua:
        aggregate_result = {
            "destinations": [],
            "errors": []
        }
        
        uris = [u.strip() for u in rua.split(",")]
        for uri in uris:
            # Validate the URI format
            validation = validate_uri(uri)
            aggregate_result["destinations"].append(validation)
            
            # Add any errors
            for error in validation.get("errors", []):
                aggregate_result["errors"].append(f"URI '{uri}': {error}")
                
            # Check for postmaster addresses and same-domain reporting
            if validation["scheme"] == "mailto" and validation["valid"]:
                email = validation["address"]
                if email.lower().startswith("postmaster@"):
                    has_postmaster = True
                
                # Check if reports go to the same domain
                if "@" in email:
                    email_domain = email.split("@", 1)[1].lower()
                    if email_domain.lower() == domain.lower():
                        reports_to_self = True
        
        result["aggregate"] = aggregate_result
    else:
        result["warnings"].append("No aggregate reporting (rua) configured")
        result["recommendations"].append("Add aggregate reporting (rua) to receive DMARC reports")
    
    # Process RUF (forensic reports)
    ruf = parsed_policy.get("ruf")
    if ruf:
        forensic_result = {
            "destinations": [],
            "errors": []
        }
        
        uris = [u.strip() for u in ruf.split(",")]
        for uri in uris:
            # Validate the URI format
            validation = validate_uri(uri)
            forensic_result["destinations"].append(validation)
            
            # Add any errors
            for error in validation.get("errors", []):
                forensic_result["errors"].append(f"URI '{uri}': {error}")
                
            # Check for postmaster addresses and same-domain reporting
            if validation["scheme"] == "mailto" and validation["valid"]:
                email = validation["address"]
                if email.lower().startswith("postmaster@"):
                    has_postmaster = True
                
                # Check if reports go to the same domain
                if "@" in email:
                    email_domain = email.split("@", 1)[1].lower()
                    if email_domain.lower() == domain.lower():
                        reports_to_self = True
        
        result["forensic"] = forensic_result
    
    # Add common warnings and recommendations
    if reports_to_self:
        result["warnings"].append("Reports are being sent to the same domain being checked")
        result["recommendations"].append(
            "DMARC reports sent to your own domain are difficult to analyze effectively. "
            "Consider using a dedicated DMARC analysis platform for better reporting capabilities"
        )
    
    if has_postmaster:
        result["warnings"].append("Using postmaster address which may be an unmonitored mailbox")
        result["recommendations"].append(
            "Consider using a dedicated DMARC analysis platform instead of postmaster address "
            "for better reporting and analysis"
        )
    
    return result

def is_internal_domain(domain: str) -> bool:
    """
    Check if a domain appears to be internal/private.
    
    Args:
        domain (str): Domain to check
        
    Returns:
        bool: True if domain appears to be internal
    """
    # Check for common internal TLDs
    internal_tlds = [".local", ".internal", ".corp", ".lan", ".intranet", ".private"]
    for tld in internal_tlds:
        if domain.endswith(tld):
            return True
            
    # Check for IP address domains
    try:
        # Try parsing as IPv4
        if domain.count(".") == 3:
            octets = domain.split(".")
            if all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                ip = ipaddress.IPv4Address(domain)
                return ip.is_private
                
    except ValueError:
        pass
        
    return False

def analyze_dmarc_policy(parsed_policy: Dict[str, str]) -> Dict[str, Any]:
    """
    Analyze DMARC policy for security and best practices.
    
    Args:
        parsed_policy (Dict): Parsed DMARC policy tags
        
    Returns:
        Dict: Analysis results
    """
    domain = parsed_policy.get("domain", "")
    analysis = {
        "policy_strength": "none",
        "coverage": 0,
        "warnings": [],
        "recommendations": [],
        "issues": [],
        "reporting": None
    }
    
    # Check version
    if parsed_policy.get("v") != "DMARC1":
        analysis["issues"].append("Invalid DMARC version - must be 'DMARC1'")
        return analysis
        
    # Check for required tags
    required_tags = [tag for tag, info in DMARC_TAGS.items() if info["required"]]
    missing_tags = [tag for tag in required_tags if tag not in parsed_policy]
    
    if missing_tags:
        for tag in missing_tags:
            analysis["issues"].append(f"Missing required tag: {tag}")
        return analysis
        
    # Check policy strength
    policy = parsed_policy.get("p", "none").lower()
    analysis["policy_strength"] = policy
    
    if policy == "none":
        analysis["warnings"].append("Policy 'none' provides monitoring only without enforcement")
        analysis["recommendations"].append("Consider using 'quarantine' or 'reject' for better protection")
    elif policy == "quarantine":
        analysis["recommendations"].append("Consider using 'reject' for maximum protection")
        
    # Check subdomain policy - only if explicitly set
    if "sp" in parsed_policy:
        subdomain_policy = parsed_policy.get("sp").lower()
        analysis["subdomain_strength"] = subdomain_policy
        
        if subdomain_policy == "none" and policy != "none":
            analysis["warnings"].append("Subdomain policy is weaker than domain policy")
            analysis["recommendations"].append("Set subdomain policy (sp) equal to or stronger than domain policy")
        elif subdomain_policy != policy:
            # Adding informational note when subdomain policy differs
            analysis["warnings"].append(f"Subdomain policy ({subdomain_policy}) differs from domain policy ({policy})")
    
    # If no explicit sp tag, don't add the subdomain_strength field
        
    # Check percentage
    pct_str = parsed_policy.get("pct", "100")
    try:
        pct = int(pct_str)
        analysis["coverage"] = pct
        
        if pct < 100:
            analysis["warnings"].append(f"Policy applies to only {pct}% of emails")
            if policy != "none":
                analysis["recommendations"].append("Increase pct to 100 for full protection")
    except ValueError:
        analysis["issues"].append(f"Invalid percentage value: {pct_str}")
        
    # Check alignment
    dkim_alignment = parsed_policy.get("adkim", "r").lower()
    spf_alignment = parsed_policy.get("aspf", "r").lower()
    
    if dkim_alignment == "s":
        analysis["warnings"].append("DKIM using strict alignment - may increase false positives")
    
    if spf_alignment == "s":
        analysis["warnings"].append("SPF using strict alignment - may increase false positives")
    
    # Check reporting
    reporting_analysis = check_all_reporting_destinations(parsed_policy, domain)
    analysis["reporting"] = reporting_analysis
    
    # Add warnings and recommendations from reporting analysis
    if "warnings" in reporting_analysis:
        analysis["warnings"].extend(reporting_analysis.get("warnings", []))
    if "recommendations" in reporting_analysis:
        analysis["recommendations"].extend(reporting_analysis.get("recommendations", []))
    if "errors" in reporting_analysis:
        analysis["issues"].extend(reporting_analysis.get("errors", []))

    # Check forensic options specifically for RUF
    if "ruf" in parsed_policy:
        fo = parsed_policy.get("fo", "0")
        if fo not in ["0", "1", "d", "s"]:
            analysis["issues"].append(f"Invalid forensic options (fo): {fo}")
        elif fo != "0" and policy == "none":
            analysis["warnings"].append("Detailed forensic reports requested but policy is 'none'")
            
    return analysis

def get_dmarc_policy(domain: str) -> Dict[str, Any]:
    """
    Retrieves and analyzes DMARC policy for a domain.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing DMARC policy information and analysis
    """
    results = {
        "record": None,
        "parsed": None,
        "found": False,
        "valid": False,
        "domain": domain,
        "errors": [],
        "warnings": [],
        "recommendations": [],
        "analysis": None,
        "authoritative_nameserver": None
    }
    
    try:
        # Get authoritative resolver
        resolver = create_auth_resolver(domain)
        
        # Store the authoritative nameserver info if available
        auth_ns = get_authoritative_nameserver(domain)
        if auth_ns:
            results["authoritative_nameserver"] = auth_ns
            
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
                    parsed = {"domain": domain}
                    for tag in txt_value.split(';'):
                        tag = tag.strip()
                        if '=' in tag:
                            key, value = tag.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            parsed[key] = value
                    
                    results["parsed"] = parsed
                    
                    # Validate record
                    if "p" in parsed:
                        results["valid"] = True
                        
                        # Add policy analysis
                        analysis = analyze_dmarc_policy(parsed)
                        results["analysis"] = analysis
                        
                        # Use sets for deduplication
                        warnings_set = set(results["warnings"])
                        recommendations_set = set(results["recommendations"])
                        
                        # Add warnings and recommendations from analysis
                        if "warnings" in analysis:
                            for warning in analysis.get("warnings", []):
                                warnings_set.add(warning)
                        
                        if "recommendations" in analysis:
                            for recommendation in analysis.get("recommendations", []):
                                recommendations_set.add(recommendation)
                        
                        # Convert back to lists
                        results["warnings"] = list(warnings_set)
                        results["recommendations"] = list(recommendations_set)
                        
                        # Add critical issues to errors
                        if "issues" in analysis:
                            for issue in analysis.get("issues", []):
                                results["errors"].append(f"DMARC issue: {issue}")
                    else:
                        results["errors"].append("DMARC record missing required 'p' tag")
                        results["recommendations"].append("Add required 'p' tag to DMARC record")
                    
                    break
                    
            if not results["found"]:
                results["errors"].append("No valid DMARC record found")
                results["recommendations"].append("Implement DMARC to improve email security and deliverability")
                # Organizational domain fallback check
                if domain.count(".") > 1:
                    # Try checking organizational domain
                    org_domain = ".".join(domain.split(".")[-2:])
                    results["recommendations"].append(
                        f"Consider checking for DMARC on organizational domain: {org_domain}"
                    )
                
        except dns.resolver.NoAnswer:
            logger.info(f"No DMARC record found for {domain}")
            results["errors"].append("No DMARC record found")
            results["recommendations"].append("Implement DMARC to improve email security and deliverability")
            
        except dns.resolver.NXDOMAIN:
            logger.info(f"DMARC record does not exist for {domain}")
            results["errors"].append("DMARC record does not exist")
            results["recommendations"].append("Implement DMARC to improve email security and deliverability")
            
    except Exception as e:
        logger.error(f"Error retrieving DMARC policy for {domain}: {str(e)}")
        results["errors"].append(f"Error retrieving DMARC policy: {str(e)}")
    
    # Add overall grade based on policy and configuration
    if not results["found"]:
        results["grade"] = "F"
        results["grade_description"] = "Missing DMARC"
    elif not results["valid"]:
        results["grade"] = "F"
        results["grade_description"] = "Invalid DMARC configuration"
    else:
        parsed = results["parsed"]
        analysis = results["analysis"]
        
        policy = parsed.get("p", "none").lower()
        pct = int(parsed.get("pct", "100"))
        has_rua = "rua" in parsed
        
        if policy == "reject" and pct == 100:
            results["grade"] = "A"
            results["grade_description"] = "Optimal DMARC protection"
        elif policy == "reject" and pct < 100:
            results["grade"] = "B"
            results["grade_description"] = f"Strong policy but only applied to {pct}% of messages"
        elif policy == "quarantine" and pct == 100:
            results["grade"] = "B"
            results["grade_description"] = "Good protection but not maximum"
        elif policy == "quarantine" and pct < 100:
            results["grade"] = "C"
            results["grade_description"] = f"Medium protection and only applied to {pct}% of messages"
        elif policy == "none" and has_rua:
            results["grade"] = "D"
            results["grade_description"] = "Monitoring only without enforcement"
        else:
            results["grade"] = "F"
            results["grade_description"] = "Minimal DMARC configuration"
    
    # Ensure the result is JSON serializable
    try:
        json.dumps(results)
    except (TypeError, OverflowError) as e:
        logger.error(f"JSON serialization error: {str(e)}")
        # Return a simplified version that will serialize
        return {
            "record": results.get("record"),
            "parsed": results.get("parsed"),
            "found": results.get("found", False),
            "valid": results.get("valid", False),
            "domain": domain,
            "errors": results.get("errors", []) + ["JSON serialization error"],
            "warnings": results.get("warnings", []),
            "recommendations": results.get("recommendations", []),
            "authoritative_nameserver": results.get("authoritative_nameserver")
        }
    
    return results
