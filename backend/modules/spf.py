import dns.resolver
from dns.exception import DNSException
from typing import Dict, List, Any, Set, Optional
import re
import logging
import json

# Configure module logger
logger = logging.getLogger(__name__)

# SPF Mechanisms that require DNS lookups
LOOKUP_MECHANISMS = ['a', 'mx', 'include', 'exists', 'redirect']

# SPF Qualifiers and their meanings
SPF_QUALIFIERS = {
    '+': 'pass',     # Default if no qualifier specified
    '-': 'fail',     # Hard fail
    '~': 'softfail', # Soft fail
    '?': 'neutral'   # Neutral
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
    auth_resolver = dns.resolver.Resolver()
    
    try:
        # Get the authoritative nameserver
        auth_ns = get_authoritative_nameserver(domain)
        if auth_ns:
            # Get the IP address
            ns_ip = get_nameserver_ip(auth_ns)
            if ns_ip:
                # Configure resolver to use this nameserver
                auth_resolver.nameservers = [ns_ip]
                auth_resolver.timeout = 5.0
                auth_resolver.lifetime = 10.0
                logger.info(f"Using authoritative nameserver {auth_ns} ({ns_ip}) for SPF query on {domain}")
                return auth_resolver
    except Exception as e:
        logger.error(f"Error setting up authoritative resolver: {str(e)}")
    
    # If anything fails, return default resolver
    logger.warning(f"Using default resolver for {domain}")
    return auth_resolver

def parse_spf_record(spf_text: str) -> Dict[str, Any]:
    """
    Parses an SPF record to extract its components.
    
    Args:
        spf_text (str): The SPF record text
        
    Returns:
        Dict: The parsed SPF components
    """
    if not spf_text:
        return {}
        
    # Initialize result structure
    parsed = {
        "version": None,
        "mechanisms": [],
        "modifiers": [],
        "includes": [],
        "all_mechanism": None,
        "all_qualifier": None,
        "redirect": None,
        "ip4": [],
        "ip6": [],
        "a": [],
        "mx": [],
        "exists": [],
        "exp": None
    }
    
    # Extract components
    components = spf_text.split()
    
    # Version should be the first component
    if components and components[0].startswith('v='):
        parsed["version"] = components[0]
        components = components[1:]  # Skip version for further processing
    else:
        logger.warning(f"SPF record doesn't start with v=spf1: {spf_text}")
        return {}  # Not a valid SPF record
    
    # Process each component
    for component in components:
        component = component.strip()
        
        # Parse modifiers (like redirect, exp)
        if '=' in component:
            modifier_name, modifier_value = component.split('=', 1)
            parsed["modifiers"].append({
                "name": modifier_name,
                "value": modifier_value
            })
            
            # Special handling for redirect
            if modifier_name == 'redirect':
                parsed["redirect"] = modifier_value
                
            # Special handling for exp
            elif modifier_name == 'exp':
                parsed["exp"] = modifier_value
                
            continue
            
        # Extract qualifier (default is '+')
        qualifier = '+'
        mechanism = component
        if component[0] in SPF_QUALIFIERS:
            qualifier = component[0]
            mechanism = component[1:]
            
        # Check if this is the 'all' mechanism
        if mechanism == 'all':
            parsed["all_mechanism"] = f"{qualifier}all"
            parsed["all_qualifier"] = SPF_QUALIFIERS[qualifier]
            parsed["mechanisms"].append({
                "type": "all",
                "qualifier": qualifier,
                "qualifier_meaning": SPF_QUALIFIERS[qualifier],
                "value": None
            })
            continue
            
        # Extract mechanism type and value
        if ':' in mechanism:
            mechanism_type, mechanism_value = mechanism.split(':', 1)
        else:
            mechanism_type = mechanism
            mechanism_value = None
            
        # Add to mechanisms list
        mechanism_obj = {
            "type": mechanism_type,
            "qualifier": qualifier,
            "qualifier_meaning": SPF_QUALIFIERS[qualifier],
            "value": mechanism_value
        }
        parsed["mechanisms"].append(mechanism_obj)
        
        # Special handling for specific mechanism types
        if mechanism_type == 'include':
            if mechanism_value:
                parsed["includes"].append(mechanism_value)
        elif mechanism_type == 'ip4':
            if mechanism_value:
                parsed["ip4"].append(mechanism_value)
        elif mechanism_type == 'ip6':
            if mechanism_value:
                parsed["ip6"].append(mechanism_value)
        elif mechanism_type == 'a':
            parsed["a"].append(mechanism_value or "")
        elif mechanism_type == 'mx':
            parsed["mx"].append(mechanism_value or "")
        elif mechanism_type == 'exists':
            if mechanism_value:
                parsed["exists"].append(mechanism_value)
    
    return parsed

def count_dns_lookups(parsed: Dict[str, Any], domain: str, visited: Set[str] = None) -> Dict[str, Any]:
    """
    Counts the number of potential DNS lookups in an SPF record, including recursively
    checking included domains and providing detailed breakdown.
    
    Args:
        parsed (Dict): The parsed SPF record
        domain (str): The domain being evaluated
        visited (Set[str]): Set of already visited domains to prevent loops
        
    Returns:
        Dict: DNS lookup count information with detailed breakdown
    """
    if not parsed:
        return {
            "total": 0, 
            "mechanisms": {}, 
            "includes_breakdown": [],
            "errors": [],
            "description": "This counts DNS lookups used during SPF evaluation (max 10 allowed)"
        }
        
    if visited is None:
        visited = set()
        
    # Prevent loops
    if domain in visited:
        return {
            "total": 0, 
            "mechanisms": {},
            "includes_breakdown": [],
            "errors": [f"Loop detected with domain {domain}"],
            "description": "A loop was detected in SPF includes, which is an error"
        }
        
    visited.add(domain)
    
    # Count direct lookups in this record
    lookups = 0
    mechanism_counts = {}
    errors = []
    includes_breakdown = []
    
    # Count lookups for each included domain
    for include_domain in parsed.get("includes", []):
        # Initial lookup count for the include directive itself
        initial_lookup = 1
        lookups += initial_lookup
        mechanism_counts["include"] = mechanism_counts.get("include", 0) + initial_lookup
        
        include_result = {
            "domain": include_domain,
            "direct_lookups": initial_lookup,
            "recursive_lookups": 0,
            "total_lookups": initial_lookup,
            "record": None,
            "mechanisms": {},
            "nested_includes": [],
            "errors": []
        }
        
        # Recursive lookup for included domain
        try:
            include_spf = get_spf_record(include_domain)
            if include_spf.get("record"):
                include_result["record"] = include_spf.get("record")
                
            if include_spf.get("parsed"):
                # Count nested lookups
                include_counts = count_dns_lookups(
                    include_spf["parsed"], 
                    include_domain, 
                    visited.copy()  # Create a copy to avoid modifying the current path
                )
                
                recursive_lookups = include_counts.get("total", 0)
                include_result["recursive_lookups"] = recursive_lookups
                include_result["total_lookups"] += recursive_lookups
                include_result["mechanisms"] = include_counts.get("mechanisms", {})
                include_result["nested_includes"] = include_counts.get("includes_breakdown", [])
                include_result["errors"] = include_counts.get("errors", [])
                
                lookups += recursive_lookups
                
                # Merge mechanism counts
                for mech, count in include_counts.get("mechanisms", {}).items():
                    mechanism_counts[mech] = mechanism_counts.get(mech, 0) + count
                
                # Merge errors
                errors.extend(include_counts.get("errors", []))
        except Exception as e:
            error_msg = f"Error processing include {include_domain}: {str(e)}"
            include_result["errors"].append(error_msg)
            errors.append(error_msg)
        
        includes_breakdown.append(include_result)
    
    # Count redirect lookups
    redirect_breakdown = None
    if parsed.get("redirect"):
        redirect_domain = parsed.get("redirect")
        redirect_initial_lookup = 1
        lookups += redirect_initial_lookup
        mechanism_counts["redirect"] = redirect_initial_lookup
        
        redirect_result = {
            "domain": redirect_domain,
            "direct_lookups": redirect_initial_lookup,
            "recursive_lookups": 0,
            "total_lookups": redirect_initial_lookup,
            "record": None,
            "mechanisms": {},
            "nested_includes": [],
            "errors": []
        }
        
        # Recursive lookup for redirect domain
        try:
            redirect_spf = get_spf_record(redirect_domain)
            if redirect_spf.get("record"):
                redirect_result["record"] = redirect_spf.get("record")
                
            if redirect_spf.get("parsed"):
                # Count nested lookups
                redirect_counts = count_dns_lookups(
                    redirect_spf["parsed"], 
                    redirect_domain, 
                    visited.copy()  # Create a copy to avoid modifying the current path
                )
                
                recursive_lookups = redirect_counts.get("total", 0)
                redirect_result["recursive_lookups"] = recursive_lookups
                redirect_result["total_lookups"] += recursive_lookups
                redirect_result["mechanisms"] = redirect_counts.get("mechanisms", {})
                redirect_result["nested_includes"] = redirect_counts.get("includes_breakdown", [])
                redirect_result["errors"] = redirect_counts.get("errors", [])
                
                lookups += recursive_lookups
                
                # Merge mechanism counts
                for mech, count in redirect_counts.get("mechanisms", {}).items():
                    mechanism_counts[mech] = mechanism_counts.get(mech, 0) + count
                
                # Merge errors
                errors.extend(redirect_counts.get("errors", []))
        except Exception as e:
            error_msg = f"Error processing redirect {redirect_domain}: {str(e)}"
            redirect_result["errors"].append(error_msg)
            errors.append(error_msg)
        
        redirect_breakdown = redirect_result
    
    # Count a, mx, exists lookups
    for mechanism in ["a", "mx", "exists"]:
        count = len(parsed.get(f"{mechanism}s", []))
        if count > 0:
            lookups += count
            mechanism_counts[mechanism] = count
    
    result = {
        "total": lookups,
        "mechanisms": mechanism_counts,
        "includes_breakdown": includes_breakdown,
        "errors": errors,
        "description": "This counts DNS lookups used during SPF evaluation (max 10 allowed)"
    }
    
    # Add redirect breakdown if present
    if redirect_breakdown:
        result["redirect_breakdown"] = redirect_breakdown
    
    return result

def get_spf_record(domain: str) -> Dict[str, Any]:
    """
    Retrieves and parses the SPF record for a domain using authoritative nameserver.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing the SPF record data and analysis
    """
    results = {
        "record": None,
        "parsed": None,
        "record_count": 0,
        "lookup_count": None,
        "authoritative_nameserver": None,
        "errors": [],
        "warnings": [],
        "recommendations": []
    }
    
    try:
        # Get authoritative resolver
        resolver = create_auth_resolver(domain)
        
        # Store the authoritative nameserver info if available
        auth_ns = get_authoritative_nameserver(domain)
        if auth_ns:
            results["authoritative_nameserver"] = auth_ns
        
        # Look for TXT records
        try:
            answers = resolver.resolve(domain, 'TXT')
            
            # Count all TXT records
            results["record_count"] = len(answers)
            
            # Find SPF record
            for rdata in answers:
                txt_value = "".join(s.decode() for s in rdata.strings)
                
                if txt_value.startswith('v=spf1'):
                    if results["record"]:
                        # Found multiple SPF records - this is invalid
                        results["errors"].append("Multiple SPF records found - this is invalid")
                        results["recommendations"].append("Remove duplicate SPF records and keep only one")
                    
                    results["record"] = txt_value
                    
            # No SPF record found
            if not results["record"]:
                results["errors"].append("No SPF record found")
                results["recommendations"].append("Implement an SPF record to protect against email spoofing")
                return results
                
            # Parse the SPF record
            results["parsed"] = parse_spf_record(results["record"])
            
            # Check if parsing was successful
            if not results["parsed"]:
                results["errors"].append("Failed to parse SPF record")
                results["recommendations"].append("Verify SPF record syntax")
                return results
                
            # Count DNS lookups
            results["lookup_count"] = count_dns_lookups(results["parsed"], domain)
            
            # --- Validations and Recommendations ---
            
            # Check DNS lookup limit
            total_lookups = results["lookup_count"].get("total", 0)
            if total_lookups > 10:
                results["errors"].append(f"SPF record exceeds 10 DNS lookup limit ({total_lookups})")
                results["recommendations"].append("Reduce the number of DNS lookups by consolidating includes or using ip4/ip6")
            elif total_lookups > 8:
                results["warnings"].append(f"SPF record has {total_lookups} DNS lookups (approaching the limit of 10)")
                results["recommendations"].append("Consider optimizing SPF record to reduce DNS lookups")
            
            # Check 'all' mechanism
            if not results["parsed"].get("all_mechanism"):
                results["warnings"].append("No 'all' mechanism found - this is required")
                results["recommendations"].append("Add '-all' at the end of your SPF record")
            elif results["parsed"].get("all_qualifier") not in ["fail", "softfail"]:
                results["warnings"].append(f"'all' qualifier is set to '{results['parsed'].get('all_qualifier')}' - this is weak")
                results["recommendations"].append("Use '-all' (hard fail) for stronger protection")
            
            # Check for 'redirect' and 'all' together (invalid)
            if results["parsed"].get("redirect") and results["parsed"].get("all_mechanism"):
                results["warnings"].append("Having both 'redirect' and 'all' in the same record may cause issues")
                results["recommendations"].append("Remove 'all' directive when using 'redirect'")
            
            # Check for potentially risky mechanisms
            for mechanism in results["parsed"].get("mechanisms", []):
                # Check for overly permissive mechanisms
                if mechanism["type"] in ["ip4", "ip6"] and mechanism["value"] == "0.0.0.0/0":
                    results["warnings"].append(f"Overly permissive IP range {mechanism['value']}")
                    results["recommendations"].append("Specify exact IP ranges instead of allowing all IPs")
                
                # Check for external includes that might not be under your control
                if mechanism["type"] == "include" and any(ext in mechanism["value"] for ext in [
                    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com"
                ]):
                    results["warnings"].append(f"Including policy from external provider: {mechanism['value']}")
                    
            # Check for include loops
            if results["lookup_count"].get("errors"):
                for error in results["lookup_count"].get("errors", []):
                    if "Loop detected" in error:
                        results["errors"].append(error)
                        results["recommendations"].append("Fix circular 'include' references in SPF record")
                
        except dns.resolver.NoAnswer:
            results["errors"].append("No TXT records found")
            results["recommendations"].append("Implement an SPF record to protect against email spoofing")
            
        except dns.resolver.NXDOMAIN:
            results["errors"].append("Domain does not exist")
            
        except dns.resolver.Timeout:
            results["errors"].append("DNS timeout")
            
        except Exception as e:
            logger.error(f"Error resolving TXT records: {str(e)}")
            results["errors"].append(f"Error resolving TXT records: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error retrieving SPF record for {domain}: {str(e)}")
        results["errors"].append(f"Error retrieving SPF record: {str(e)}")
    
    # Ensure the result is JSON serializable
    try:
        json.dumps(results)
    except (TypeError, OverflowError) as e:
        logger.error(f"JSON serialization error: {str(e)}")
        # Return a simplified version that will serialize
        return {
            "record": results.get("record"),
            "errors": results.get("errors", []) + ["JSON serialization error"],
            "warnings": results.get("warnings", []),
            "recommendations": results.get("recommendations", [])
        }
    
    return results

def analyze_spf_policy(spf_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyzes the SPF policy strength and provides recommendations.
    
    Args:
        spf_record (Dict): The parsed SPF record
        
    Returns:
        Dict: Analysis results and recommendations
    """
    if not spf_record or not spf_record.get("parsed"):
        return {
            "policy_strength": "none",
            "recommendations": ["Implement an SPF record to protect against email spoofing"],
            "errors": ["No valid SPF record found"]
        }
    
    parsed = spf_record["parsed"]
    lookup_count = spf_record.get("lookup_count", {})
    result = {
        "policy_strength": "unknown",
        "enforcement": None,
        "scope": "unknown",
        "recommendations": [],
        "errors": []
    }
    
    # Check enforcement level
    all_qualifier = parsed.get("all_qualifier")
    if all_qualifier == "fail":
        result["policy_strength"] = "strong"
        result["enforcement"] = "hard_fail"
    elif all_qualifier == "softfail":
        result["policy_strength"] = "medium"
        result["enforcement"] = "soft_fail"
        result["recommendations"].append("Consider using -all (hard fail) for stronger protection")
    elif all_qualifier == "neutral":
        result["policy_strength"] = "weak"
        result["enforcement"] = "neutral"
        result["recommendations"].append("Upgrade to ~all or -all for better security")
    elif all_qualifier == "pass":
        result["policy_strength"] = "very_weak"
        result["enforcement"] = "pass"
        result["recommendations"].append("Change +all to -all or ~all as +all allows anyone to send")
    else:
        result["policy_strength"] = "none"
        result["recommendations"].append("Add -all at the end of your SPF record")
    
    # Check scope
    mechanisms = parsed.get("mechanisms", [])
    includes = parsed.get("includes", [])
    ip_count = len(parsed.get("ip4", [])) + len(parsed.get("ip6", []))
    
    if ip_count > 0 and len(includes) == 0:
        result["scope"] = "specific"
    elif len(includes) > 0 and ip_count == 0:
        result["scope"] = "delegated"
    elif len(includes) > 0 and ip_count > 0:
        result["scope"] = "mixed"
    else:
        result["scope"] = "empty"
        if all_qualifier in ["fail", "softfail"]:
            result["recommendations"].append("Add sending sources (ip4, ip6, include, etc.) to your SPF record")
    
    # Check for issues
    total_lookups = lookup_count.get("total", 0)
    if total_lookups > 10:
        result["errors"] = result.get("errors", [])
        result["errors"].append("SPF lookup limit exceeded (max 10 allowed)")
        result["recommendations"].append("Reduce the number of DNS lookups in your SPF record")
    elif total_lookups > 8:
        result["warnings"] = result.get("warnings", [])
        result["warnings"].append(f"SPF record has {total_lookups} DNS lookups (approaching the limit of 10)")
        result["recommendations"].append("Consider optimizing SPF record to reduce DNS lookups")
    
    if len(includes) > 5:
        result["recommendations"].append("Large number of includes may cause SPF evaluation issues and increase lookup count")
    
    # Analyze lookup distribution and create a lookup tree
    includes_breakdown = lookup_count.get("includes_breakdown", [])
    redirect_breakdown = lookup_count.get("redirect_breakdown")
    
    # Sort includes by total lookup count (descending)
    sorted_includes = sorted(
        includes_breakdown, 
        key=lambda x: x.get("total_lookups", 0), 
        reverse=True
    )
    
    # Generate lookup insights with sorted includes
    lookup_insights = {
        "domain_total_lookups": total_lookups,  # Total lookups for the entire domain's SPF record
        "lookup_limit": 10,                     # SPF lookup limit per RFC
        "remaining_lookups": max(0, 10 - total_lookups),  # How many lookups remain before hitting the limit
        "lookup_types": lookup_count.get("mechanisms", {}),  # Breakdown by mechanism type
        "includes_count": len(includes),        # Number of include directives
        "ip_blocks": ip_count,                  # Number of IP blocks specified
        "include_breakdown": []                 # Detailed breakdown by include
    }
    
    # Add detailed include breakdown
    for include in sorted_includes:
        include_domain = include.get("domain")
        direct_lookups = include.get("direct_lookups", 0)      # Initial lookup for the include directive
        recursive_lookups = include.get("recursive_lookups", 0) # Lookups from the included domain's SPF
        total_include_lookups = include.get("total_lookups", 0) # Total cost of this include directive
        
        lookup_insights["include_breakdown"].append({
            "domain": include_domain,
            "total_cost": total_include_lookups,  # Total DNS lookups this include costs
            "direct_lookups": direct_lookups,     # Direct lookup count (usually 1)
            "recursive_lookups": recursive_lookups, # Nested lookups from included domain's SPF
            "percentage_of_total": round((total_include_lookups / total_lookups * 100) if total_lookups > 0 else 0, 1)
        })
    
    # Add redirect if present
    if redirect_breakdown:
        redirect_domain = redirect_breakdown.get("domain")
        redirect_total = redirect_breakdown.get("total_lookups", 0)
        lookup_insights["redirect"] = {
            "domain": redirect_domain,
            "total_cost": redirect_total,
            "direct_lookups": redirect_breakdown.get("direct_lookups", 0),
            "recursive_lookups": redirect_breakdown.get("recursive_lookups", 0),
            "percentage_of_total": round((redirect_total / total_lookups * 100) if total_lookups > 0 else 0, 1)
        }
    
    # Add a summary table for quick understanding of lookup distribution
    lookup_insights["summary"] = {
        "remaining_lookups": max(0, 10 - total_lookups),
        "lookup_status": (
            "critical" if total_lookups > 10 else
            "warning" if total_lookups > 8 else
            "good"
        ),
        "top_consumers": [
            {"domain": inc.get("domain"), "lookups": inc.get("total_lookups", 0)}
            for inc in sorted_includes[:3] if inc.get("total_lookups", 0) > 0
        ]
    }
    
    # Add optimization suggestions if approaching limit
    if total_lookups > 7:
        # Find the includes with the most lookups to optimize
        if lookup_insights["include_breakdown"]:
            top_offender = lookup_insights["include_breakdown"][0]
            if top_offender["total_cost"] > 2:
                result["recommendations"].append(
                    f"Consider replacing include:{top_offender['domain']} with explicit IP addresses to reduce lookups"
                )
    
    result["lookup_insights"] = lookup_insights
    
    return result

def get_spf_record_from_ns(domain: str, nameserver: str) -> Dict[str, Any]:
    """
    Retrieves SPF record from a specific nameserver.
    
    Args:
        domain (str): The domain to query
        nameserver (str): The nameserver to query
        
    Returns:
        Dict: SPF record information
    """
    results = {
        "record": None,
        "nameserver": nameserver,
        "errors": []
    }
    
    try:
        # Get the IP address of the nameserver
        ns_ip = get_nameserver_ip(nameserver)
        if not ns_ip:
            results["errors"].append(f"Could not resolve IP for nameserver {nameserver}")
            return results
            
        # Create a resolver using this nameserver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ns_ip]
        resolver.timeout = 5.0
        resolver.lifetime = 10.0
        
        try:
            # Query TXT records
            answers = resolver.resolve(domain, 'TXT')
            
            # Find SPF record
            for rdata in answers:
                txt_value = "".join(s.decode() for s in rdata.strings)
                
                if txt_value.startswith('v=spf1'):
                    results["record"] = txt_value
                    break
                    
        except dns.resolver.NoAnswer:
            results["errors"].append("No TXT records found")
        except dns.resolver.NXDOMAIN:
            results["errors"].append("Domain does not exist")
        except dns.resolver.Timeout:
            results["errors"].append("DNS query timeout")
        except Exception as e:
            results["errors"].append(f"Error querying TXT records: {str(e)}")
            
    except Exception as e:
        results["errors"].append(f"Error retrieving SPF record: {str(e)}")
        
    return results

def get_spf_record(domain: str) -> Dict[str, Any]:
    """
    Retrieves and parses the SPF record for a domain using authoritative nameserver.

    Args:
        domain (str): The domain to query

    Returns:
        Dict: Dictionary containing the SPF record data and analysis
    """
    results = {
        "record": None,
        "parsed": None,
        "record_count": 0,
        "lookup_count": None,
        "authoritative_nameserver": None,
        "errors": [],
        "warnings": [],
        "recommendations": [],
        "grade": None
    }

    try:
        # Get authoritative resolver
        resolver = create_auth_resolver(domain)

        # Store the authoritative nameserver info if available
        auth_ns = get_authoritative_nameserver(domain)
        if auth_ns:
            results["authoritative_nameserver"] = auth_ns

        # Look for TXT records
        try:
            answers = resolver.resolve(domain, 'TXT')

            # Count all TXT records
            results["record_count"] = len(answers)

            # Find SPF record
            for rdata in answers:
                txt_value = "".join(s.decode() for s in rdata.strings)

                if txt_value.startswith('v=spf1'):
                    if results["record"]:
                        # Found multiple SPF records - this is invalid
                        results["errors"].append("Multiple SPF records found - this is invalid")
                        results["recommendations"].append("Remove duplicate SPF records and keep only one")

                    results["record"] = txt_value

            # No SPF record found
            if not results["record"]:
                results["errors"].append("No SPF record found")
                results["recommendations"].append("Implement an SPF record to protect against email spoofing")

                # Grade missing SPF record
                results["grade"] = {
                    "grade": "F",
                    "score": 0,
                    "description": "No SPF record found"
                }

                return results

            # Parse the SPF record
            results["parsed"] = parse_spf_record(results["record"])

            # Check if parsing was successful
            if not results["parsed"]:
                results["errors"].append("Failed to parse SPF record")
                results["recommendations"].append("Verify SPF record syntax")

                # Grade unparseable SPF record
                results["grade"] = {
                    "grade": "F",
                    "score": 0,
                    "description": "Invalid SPF record syntax"
                }

                return results

            # Count DNS lookups
            results["lookup_count"] = count_dns_lookups(results["parsed"], domain)

            # Add analysis
            spf_analysis = analyze_spf_policy(results)
            results["analysis"] = spf_analysis

            # Grade the SPF configuration
            results["grade"] = grade_spf_policy(results)

            # --- Validations and Recommendations ---

            # Check DNS lookup limit
            total_lookups = results["lookup_count"].get("total", 0)
            if total_lookups > 10:
                results["errors"].append(f"SPF record exceeds 10 DNS lookup limit ({total_lookups})")
                results["recommendations"].append("Reduce the number of DNS lookups by consolidating includes or using ip4/ip6")
            elif total_lookups > 8:
                results["warnings"].append(f"SPF record has {total_lookups} DNS lookups (approaching the limit of 10)")
                results["recommendations"].append("Consider optimizing SPF record to reduce DNS lookups")

            # Check 'all' mechanism
            if not results["parsed"].get("all_mechanism"):
                results["warnings"].append("No 'all' mechanism found - this is required")
                results["recommendations"].append("Add '-all' at the end of your SPF record")
            elif results["parsed"].get("all_qualifier") not in ["fail", "softfail"]:
                results["warnings"].append(f"'all' qualifier is set to '{results['parsed'].get('all_qualifier')}' - this is weak")
                results["recommendations"].append("Use '-all' (hard fail) for stronger protection")

            # Check for 'redirect' and 'all' together (invalid)
            if results["parsed"].get("redirect") and results["parsed"].get("all_mechanism"):
                results["warnings"].append("Having both 'redirect' and 'all' in the same record may cause issues")
                results["recommendations"].append("Remove 'all' directive when using 'redirect'")

            # Check for potentially risky mechanisms
            for mechanism in results["parsed"].get("mechanisms", []):
                # Check for overly permissive mechanisms
                if mechanism["type"] in ["ip4", "ip6"] and mechanism["value"] == "0.0.0.0/0":
                    results["warnings"].append(f"Overly permissive IP range {mechanism['value']}")
                    results["recommendations"].append("Specify exact IP ranges instead of allowing all IPs")

                # Check for external includes that might not be under your control
                if mechanism["type"] == "include" and any(ext in mechanism["value"] for ext in [
                    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com"
                ]):
                    results["warnings"].append(f"Including policy from external provider: {mechanism['value']}")

            # Check for include loops
            if results["lookup_count"].get("errors"):
                for error in results["lookup_count"].get("errors", []):
                    if "Loop detected" in error:
                        results["errors"].append(error)
                        results["recommendations"].append("Fix circular 'include' references in SPF record")

        except dns.resolver.NoAnswer:
            results["errors"].append("No TXT records found")
            results["recommendations"].append("Implement an SPF record to protect against email spoofing")

            # Grade missing SPF record
            results["grade"] = {
                "grade": "F",
                "score": 0,
                "description": "No SPF record found"
            }

        except dns.resolver.NXDOMAIN:
            results["errors"].append("Domain does not exist")

            # Grade non-existent domain
            results["grade"] = {
                "grade": "F",
                "score": 0,
                "description": "Domain does not exist"
            }

        except dns.resolver.Timeout:
            results["errors"].append("DNS timeout")

        except Exception as e:
            logger.error(f"Error resolving TXT records: {str(e)}")
            results["errors"].append(f"Error resolving TXT records: {str(e)}")

    except Exception as e:
        logger.error(f"Error retrieving SPF record for {domain}: {str(e)}")
        results["errors"].append(f"Error retrieving SPF record: {str(e)}")

    # Ensure the result is JSON serializable
    try:
        json.dumps(results)
    except (TypeError, OverflowError) as e:
        logger.error(f"JSON serialization error: {str(e)}")
        # Return a simplified version that will serialize
        return {
            "record": results.get("record"),
            "errors": results.get("errors", []) + ["JSON serialization error"],
            "warnings": results.get("warnings", []),
            "recommendations": results.get("recommendations", []),
            "grade": results.get("grade", {"grade": "F", "description": "Error processing SPF record"})
        }

    return results
