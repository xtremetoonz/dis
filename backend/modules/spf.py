import dns.resolver
from dns.exception import DNSException
from typing import Dict, List, Any
import re
import logging

# Configure module logger
logger = logging.getLogger(__name__)

def parse_spf_record(spf_text: str) -> Dict[str, Any]:
    """
    Parses an SPF record to extract its components without analysis.
    
    Args:
        spf_text (str): The SPF record text
        
    Returns:
        Dict: The parsed SPF components
    """
    components = spf_text.split()
    
    # Initialize result structure
    parsed = {
        "version": None,
        "mechanisms": [],
        "modifiers": [],
        "includes": [],
        "all_mechanism": None,
        "redirect": None,
        "ip4": [],
        "ip6": [],
        "a": [],
        "mx": [],
        "exists": []
    }
    
    # Extract components
    for component in components:
        component = component.strip()
        
        # Version should be the first component
        if component.startswith('v='):
            parsed["version"] = component
            continue
            
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
                
            continue
            
        # Check if this is the 'all' mechanism
        if component in ['all', '+all', '-all', '~all', '?all']:
            parsed["all_mechanism"] = component
            parsed["mechanisms"].append({
                "type": "all",
                "qualifier": component[0] if component[0] in ['+', '-', '~', '?'] else '+'
            })
            continue
            
        # Parse mechanisms with qualifiers
        qualifier = '+'  # Default qualifier is '+'
        if component[0] in ['+', '-', '~', '?']:
            qualifier = component[0]
            component = component[1:]
            
        # Extract mechanism type and value
        mechanism_type = component.split(':', 1)[0] if ':' in component else component
        mechanism_value = component.split(':', 1)[1] if ':' in component else None
        
        mechanism = {
            "type": mechanism_type,
            "qualifier": qualifier,
            "value": mechanism_value
        }
        
        parsed["mechanisms"].append(mechanism)
        
        # Special handling for specific mechanism types
        if mechanism_type == 'include':
            parsed["includes"].append(mechanism_value)
        elif mechanism_type == 'ip4':
            parsed["ip4"].append(mechanism_value)
        elif mechanism_type == 'ip6':
            parsed["ip6"].append(mechanism_value)
        elif mechanism_type == 'a':
            parsed["a"].append(mechanism_value or "")
        elif mechanism_type == 'mx':
            parsed["mx"].append(mechanism_value or "")
        elif mechanism_type == 'exists':
            parsed["exists"].append(mechanism_value)
    
    return parsed

def get_spf_record(domain: str) -> Dict[str, Any]:
    """
    Retrieves and parses the SPF record for a domain without analysis.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing the SPF record data
    """
    results = {
        "record": None,
        "parsed": None,
        "record_count": 0,
        "errors": []
    }
    
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, 'TXT')
        
        # Count all TXT records
        results["record_count"] = len(answers)
        
        # Find SPF record
        for record in answers:
            # Join TXT record chunks and decode
            txt_value = "".join(s.decode() for s in record.strings)
            
            if txt_value.startswith('v=spf1'):
                results["record"] = txt_value
                results["parsed"] = parse_spf_record(txt_value)
                break
                
        if not results["record"]:
            results["errors"].append("No SPF record found")
            
    except dns.resolver.NoAnswer:
        results["errors"].append("No TXT records found")
        
    except dns.resolver.NXDOMAIN:
        results["errors"].append("Domain does not exist")
        
    except dns.resolver.Timeout:
        results["errors"].append("DNS timeout")
        
    except Exception as e:
        logger.error(f"Error retrieving SPF record for {domain}: {str(e)}")
        results["errors"].append(f"Error retrieving SPF record: {str(e)}")
    
    return results

def count_dns_lookups(spf_parsed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Counts the number of potential DNS lookups in an SPF record without analysis.
    
    Args:
        spf_parsed (Dict): The parsed SPF record
        
    Returns:
        Dict: Dictionary with lookup counts
    """
    if not spf_parsed:
        return {"total": 0, "mechanisms": {}}
    
    # These mechanisms require DNS lookups
    lookup_mechanisms = {
        "a": 1,
        "mx": 1,
        "include": 1,
        "exists": 1,
        "redirect": 1
    }
    
    total_lookups = 0
    mechanism_counts = {}
    
    # Count lookups for each mechanism type
    for mechanism_type in lookup_mechanisms:
        if mechanism_type == "redirect":
            # Redirect is a modifier
            if spf_parsed.get("redirect"):
                total_lookups += 1
                mechanism_counts["redirect"] = 1
        else:
            # Others are in the lists
            count = len(spf_parsed.get(mechanism_type + "s", []))
            if count > 0:
                total_lookups += count
                mechanism_counts[mechanism_type] = count
    
    # Count lookups for include mechanisms (these cause additional lookups)
    include_count = len(spf_parsed.get("includes", []))
    
    return {
        "total": total_lookups,
        "mechanisms": mechanism_counts,
        "includes": include_count
    }
