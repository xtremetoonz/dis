import dns.resolver
import dns.query
import dns.zone
import dns.name
import dns.message
import dns.rdatatype
import dns.flags
import dns.dnssec
import socket
import ipaddress
from dns.exception import DNSException
from typing import Dict, List, Any, Optional, Set
import logging
import json

# Configure module logger
logger = logging.getLogger(__name__)

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

def get_nameserver_ips(nameserver: str) -> List[str]:
    """
    Get IPv4 addresses for a nameserver.
    
    Args:
        nameserver (str): Nameserver hostname
        
    Returns:
        List[str]: List of IPv4 addresses
    """
    ips = []
    try:
        # Only try IPv4 addresses
        a_records = dns.resolver.resolve(nameserver, 'A')
        for record in a_records:
            ips.append(str(record))
    except Exception as e:
        logger.debug(f"Error resolving IPv4 for nameserver {nameserver}: {str(e)}")
        # Ignore errors
        pass
        
    return ips

def query_authoritative_ns(domain: str, rdtype: str) -> List[Any]:
    """
    Query records directly from the authoritative nameserver.
    
    Args:
        domain (str): The domain to query
        rdtype (str): Record type to query
        
    Returns:
        List[Any]: List of records
    """
    primary_ns = get_authoritative_nameserver(domain)
    if not primary_ns:
        logger.warning(f"Could not find authoritative nameserver for {domain}")
        return []
        
    ns_ips = get_nameserver_ips(primary_ns)
    if not ns_ips:
        logger.warning(f"Could not resolve IP for nameserver {primary_ns}")
        return []
        
    # Create a resolver using the authoritative nameserver
    custom_resolver = dns.resolver.Resolver()
    custom_resolver.nameservers = [ns_ips[0]]  # Use the first IP
    custom_resolver.timeout = 5.0
    custom_resolver.lifetime = 10.0
    
    try:
        answers = custom_resolver.resolve(domain, rdtype)
        return list(answers)
    except Exception as e:
        logger.error(f"Error querying {rdtype} from authoritative NS for {domain}: {str(e)}")
        return []

def check_zone_transfer(domain: str) -> Dict[str, Any]:
    """
    Attempt a zone transfer (AXFR) request.
    
    Args:
        domain (str): The domain to test
        
    Returns:
        Dict: Results of the zone transfer attempt
    """
    results = {
        "allowed": False,
        "records": [],
        "error": None
    }
    
    # Get nameservers
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
    except Exception as e:
        results["error"] = f"Error resolving nameservers: {str(e)}"
        return results
        
    # Try zone transfer with each nameserver
    for ns in ns_records:
        ns_name = str(ns).rstrip('.')
        ns_ips = get_nameserver_ips(ns_name)
        
        if not ns_ips:
            continue
            
        try:
            # Attempt zone transfer
            xfr = dns.query.xfr(ns_ips[0], domain, timeout=5)
            zone = dns.zone.from_xfr(xfr)
            
            # If we got here, zone transfer was successful
            results["allowed"] = True
            
            # Extract records
            for name, node in zone.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        results["records"].append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "ttl": rdataset.ttl,
                            "data": str(rdata)
                        })
                        
            # No need to try other nameservers
            break
            
        except Exception as e:
            # This is expected, zone transfers should be blocked
            pass
            
    return results

def check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Checks DNSSEC configuration for the domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: DNSSEC status and details
    """
    result = {
        "enabled": False,
        "validated": False,
        "dnskey_records": [],
        "ds_records": [],
        "nsec_records": [],
        "algorithms": [],
        "errors": []
    }
    
    try:
        # Check for DNSKEY records
        try:
            dnskey_records = dns.resolver.resolve(domain, 'DNSKEY')
            result["enabled"] = True
            
            # Process DNSKEY records
            for record in dnskey_records:
                key_info = {
                    "flags": record.flags,
                    "protocol": record.protocol,
                    "algorithm": dns.dnssec.algorithm_to_text(record.algorithm),
                }
                
                # Only add key_tag if we can calculate it (avoids serialization issues)
                try:
                    key_info["key_tag"] = dns.dnssec.key_tag(record)
                except Exception:
                    pass
                    
                result["dnskey_records"].append(key_info)
                
                # Record algorithm
                algo_text = dns.dnssec.algorithm_to_text(record.algorithm)
                if algo_text not in result["algorithms"]:
                    result["algorithms"].append(algo_text)
                    
        except dns.resolver.NoAnswer:
            result["errors"].append("No DNSKEY records found")
            
        # Check for DS records
        try:
            parent_domain = '.'.join(domain.split('.')[1:]) if '.' in domain else ''
            if parent_domain:
                # Get DS records from parent zone
                ds_records = dns.resolver.resolve(domain, 'DS')
                
                # Process DS records
                for record in ds_records:
                    result["ds_records"].append({
                        "key_tag": record.key_tag,
                        "algorithm": dns.dnssec.algorithm_to_text(record.algorithm),
                        "digest_type": record.digest_type,
                        "digest": record.digest.hex()
                    })
                    
        except dns.resolver.NoAnswer:
            result["errors"].append("No DS records found in parent zone")
            
        # Check for NSEC/NSEC3 records (signs of DNSSEC)
        try:
            # Query for a non-existent subdomain
            import random
            import string
            random_label = ''.join(random.choices(string.ascii_lowercase, k=12))
            random_domain = f"{random_label}.{domain}"
            
            # Set up a resolver with DNSSEC enabled
            resolver = dns.resolver.Resolver()
            resolver.use_dnssec = True
            
            try:
                # This should fail with NXDOMAIN, but might return NSEC/NSEC3
                resolver.resolve(random_domain, 'A')
            except dns.resolver.NXDOMAIN as nx:
                # Check response for NSEC or NSEC3 records
                if hasattr(nx, 'response') and nx.response:
                    for rrset in nx.response.authority:
                        if rrset.rdtype == dns.rdatatype.NSEC:
                            result["nsec_records"].append("NSEC")
                            break
                        elif rrset.rdtype == dns.rdatatype.NSEC3:
                            result["nsec_records"].append("NSEC3")
                            break
                        
        except Exception:
            # Ignore errors in NSEC detection
            pass
            
        # Validation status
        result["validated"] = (
            result["enabled"] and 
            len(result["dnskey_records"]) > 0 and 
            len(result["ds_records"]) > 0
        )
        
        # Check for weak algorithms
        weak_algorithms = ["RSAMD5", "DSA", "RSASHA1", "DSA-NSEC3-SHA1"]
        for algorithm in result["algorithms"]:
            if algorithm in weak_algorithms:
                result["errors"].append(f"Weak DNSSEC algorithm detected: {algorithm}")
                
    except Exception as e:
        result["errors"].append(f"Error checking DNSSEC: {str(e)}")
        
    return result

def check_open_resolver(domain: str) -> Dict[str, Any]:
    """
    Checks if the domain's nameservers are configured as open resolvers
    using the test.openresolver.com test domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: Open resolver status and details
    """
    results = {
        "ns_checked": [],
        "open_resolvers": [],
        "errors": [],
        "warnings": [],
        "recommendations": []
    }
    
    try:
        # Get nameservers for the domain
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
        except Exception as e:
            results["errors"].append(f"Could not resolve nameservers: {str(e)}")
            return results
        
        # Test each nameserver using test.openresolver.com
        test_domain = "test.openresolver.com"
        
        for ns in ns_records:
            ns_name = str(ns).rstrip('.')
            
            # Get IPv4 addresses for the nameserver
            try:
                a_records = dns.resolver.resolve(ns_name, 'A')
                ipv4_addresses = [str(rdata) for rdata in a_records]
            except Exception as e:
                results["errors"].append(f"Could not resolve IPv4 address for nameserver {ns_name}: {str(e)}")
                ipv4_addresses = []
            
            if not ipv4_addresses:
                results["errors"].append(f"No IPv4 addresses found for nameserver {ns_name}")
                continue
                
            for ip in ipv4_addresses:
                ns_result = {
                    "nameserver": ns_name,
                    "ip": ip,
                    "is_open": False,
                    "response": None,
                    "error": None
                }
                
                # Create a custom resolver using this nameserver
                custom_resolver = dns.resolver.Resolver()
                custom_resolver.nameservers = [ip]
                custom_resolver.timeout = 3.0  # Short timeout
                custom_resolver.lifetime = 3.0
                
                try:
                    # Query test.openresolver.com TXT record
                    # If the nameserver responds with a valid answer, it's an open resolver
                    txt_answers = custom_resolver.resolve(test_domain, 'TXT')
                    
                    # Parse the response
                    if txt_answers:
                        txt_records = []
                        for rdata in txt_answers:
                            for txt_string in rdata.strings:
                                txt_records.append(txt_string.decode('utf-8'))
                        
                        # If we got TXT records, this is definitely an open resolver
                        ns_result["is_open"] = True
                        ns_result["response"] = txt_records
                        results["open_resolvers"].append(ns_result)
                        
                        # Add a warning
                        results["warnings"].append(
                            f"Nameserver {ns_name} ({ip}) is an open resolver - "
                            f"successfully resolved test.openresolver.com"
                        )
                    
                except dns.resolver.NXDOMAIN:
                    # NXDOMAIN response means the nameserver tried to resolve it
                    # but didn't find the domain - still an open resolver
                    ns_result["is_open"] = True
                    ns_result["response"] = "NXDOMAIN"
                    results["open_resolvers"].append(ns_result)
                    results["warnings"].append(
                        f"Nameserver {ns_name} ({ip}) may be an open resolver - "
                        f"returned NXDOMAIN for test.openresolver.com"
                    )
                    
                except dns.resolver.NoAnswer:
                    # No answer could mean various things - we'll consider it not open
                    ns_result["response"] = "NO_ANSWER"
                    
                except dns.resolver.NoNameservers:
                    # The nameserver refused to perform recursive resolution - good!
                    ns_result["response"] = "REFUSED"
                    
                except dns.exception.Timeout:
                    # Timeout typically means the nameserver is not open for recursion - good!
                    ns_result["response"] = "TIMEOUT"
                    ns_result["error"] = "Query timed out"
                    
                except Exception as e:
                    # Other errors - likely means not an open resolver
                    ns_result["error"] = str(e)
                    
                    # Check specific error messages
                    error_str = str(e).lower()
                    if "refused" in error_str:
                        ns_result["response"] = "REFUSED"
                    elif "timeout" in error_str:
                        ns_result["response"] = "TIMEOUT"
                    else:
                        ns_result["response"] = "ERROR"
                
                # Add result to checked list
                results["ns_checked"].append(ns_result)
        
        # Add recommendations if open resolvers found
        if results["open_resolvers"]:
            results["warnings"].append(
                "Open DNS resolvers can be abused for DNS amplification attacks and should be disabled"
            )
            results["recommendations"] = [
                "Configure your nameservers to only provide recursive service to authorized clients",
                "Add ACLs (Access Control Lists) to your DNS server configuration",
                "For BIND: add 'allow-recursion { localnets; };' to your named.conf",
                "For other DNS servers: consult documentation on restricting recursive queries"
            ]
        
    except Exception as e:
        results["errors"].append(f"Error checking open resolvers: {str(e)}")
    
    return results

def check_nameserver_diversity(domain: str) -> Dict[str, Any]:
    """
    Checks the diversity of nameservers (IP, ASN, etc.).
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: Nameserver diversity assessment
    """
    results = {
        "nameservers": [],
        "unique_ips": [],
        "unique_prefixes": [],
        "unique_asns": [],  # Would require external API or database
        "same_subnet_count": 0,
        "errors": []
    }
    
    # Use sets for tracking unique values then convert to lists at the end
    unique_ips = set()
    unique_prefixes = set()
    
    try:
        # Get nameservers
        ns_records = dns.resolver.resolve(domain, 'NS')
        
        for ns in ns_records:
            ns_name = str(ns).rstrip('.')
            ns_ips = get_nameserver_ips(ns_name)
            
            if not ns_ips:
                results["errors"].append(f"Could not resolve IP for nameserver {ns_name}")
                continue
                
            ns_info = {
                "nameserver": ns_name,
                "ips": ns_ips,
                "prefixes": []
            }
            
            # Analyze IP diversity
            for ip in ns_ips:
                unique_ips.add(ip)
                
                try:
                    # Get subnet prefix (/24 for IPv4, /48 for IPv6)
                    ip_obj = ipaddress.ip_address(ip)
                    if isinstance(ip_obj, ipaddress.IPv4Address):
                        prefix = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                        ns_info["prefixes"].append(prefix)
                        unique_prefixes.add(prefix)
                    elif isinstance(ip_obj, ipaddress.IPv6Address):
                        prefix = str(ipaddress.IPv6Network(f"{ip}/48", strict=False))
                        ns_info["prefixes"].append(prefix)
                        unique_prefixes.add(prefix)
                except Exception as e:
                    results["errors"].append(f"Error processing IP {ip}: {str(e)}")
                    
            results["nameservers"].append(ns_info)
            
        # Check for nameservers in the same subnet
        prefix_counts = {}
        for prefix in unique_prefixes:
            prefix_counts[prefix] = 0
            
        for ns_info in results["nameservers"]:
            for prefix in ns_info["prefixes"]:
                prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
                
        # Count nameservers in the same subnet
        for prefix, count in prefix_counts.items():
            if count > 1:
                results["same_subnet_count"] += 1
                
        # Convert sets to lists for JSON serialization
        results["unique_ips"] = list(unique_ips)
        results["unique_prefixes"] = list(unique_prefixes)
        
    except Exception as e:
        results["errors"].append(f"Error checking nameserver diversity: {str(e)}")
        
    return results

def check_common_subdomains(domain: str) -> Dict[str, Any]:
    """
    Checks common subdomains for the domain.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: Subdomain check results
    """
    common_subdomains = [
        "www", "mail", "smtp", "pop", "pop3", "imap", "ns1", "ns2", 
        "autodiscover", "autoconfig", "webmail", "cpanel", "whm", "ftp", 
        "sftp", "blog", "shop", "api", "dev", "staging", "test", "admin",
        "cdn", "secure", "vpn", "remote", "m", "mobile", "app", "portal"
    ]
    
    results = {
        "found": [],
        "errors": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0  # Short timeout for efficiency
    
    for subdomain in common_subdomains:
        fqdn = f"{subdomain}.{domain}"
        subdomain_result = {
            "subdomain": subdomain,
            "fqdn": fqdn,
            "a_records": [],
            "cname_records": [],
            "other_records": []
        }
        
        # Check for A records
        try:
            answers = resolver.resolve(fqdn, 'A')
            for rdata in answers:
                subdomain_result["a_records"].append(str(rdata))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            continue  # Subdomain doesn't exist
        except Exception as e:
            # Some other error, log and continue
            logger.debug(f"Error checking A record for {fqdn}: {str(e)}")
            continue
            
        # If we're here, the subdomain exists, check for CNAME
        try:
            answers = resolver.resolve(fqdn, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata).rstrip('.')
                subdomain_result["cname_records"].append(cname_target)
                
                # Try to resolve the CNAME target
                try:
                    target_ips = resolver.resolve(cname_target, 'A')
                    subdomain_result["other_records"].append({
                        "type": "CNAME_TARGET_A",
                        "target": cname_target,
                        "data": [str(ip) for ip in target_ips]
                    })
                except Exception:
                    pass
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            logger.debug(f"Error checking CNAME record for {fqdn}: {str(e)}")
            
        # Only add to results if something was found
        if subdomain_result["a_records"] or subdomain_result["cname_records"]:
            results["found"].append(subdomain_result)
            
    return results

def check_wildcard_dns(domain: str) -> Dict[str, Any]:
    """
    Checks if the domain has wildcard DNS configured.
    
    Args:
        domain (str): The domain to check
        
    Returns:
        Dict: Wildcard DNS check results
    """
    results = {
        "has_wildcard": False,
        "wildcard_records": {
            "a": [],
            "aaaa": [],
            "mx": [],
            "txt": []
        },
        "errors": []
    }
    
    # Generate a random subdomain
    import random
    import string
    random_label = ''.join(random.choices(string.ascii_lowercase, k=12))
    random_domain = f"{random_label}.{domain}"
    
    resolver = dns.resolver.Resolver()
    
    # Check for various record types
    for rdtype in ['A', 'AAAA', 'MX', 'TXT']:
        try:
            answers = resolver.resolve(random_domain, rdtype)
            results["has_wildcard"] = True
            
            # Record the wildcard records
            if rdtype == 'A':
                for rdata in answers:
                    results["wildcard_records"]["a"].append(str(rdata))
            elif rdtype == 'AAAA':
                for rdata in answers:
                    results["wildcard_records"]["aaaa"].append(str(rdata))
            elif rdtype == 'MX':
                for rdata in answers:
                    results["wildcard_records"]["mx"].append({
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange).rstrip('.')
                    })
            elif rdtype == 'TXT':
                for rdata in answers:
                    txt_value = "".join(s.decode() for s in rdata.strings)
                    results["wildcard_records"]["txt"].append(txt_value)
                    
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Expected - no wildcard
            pass
        except Exception as e:
            results["errors"].append(f"Error checking wildcard {rdtype} records: {str(e)}")
            
    return results

def is_json_serializable(obj):
    """
    Tests if an object can be JSON serialized.
    
    Args:
        obj: Object to test
        
    Returns:
        bool: True if serializable, False otherwise
    """
    try:
        json.dumps(obj)
        return True
    except (TypeError, OverflowError):
        return False

def get_all_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves all relevant DNS records for a domain.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing all retrieved DNS records and security checks
    """
    results = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "soa_record": None,
        "caa_records": [],
        "dmarc_record": None,
        "spf_record": None,
        "authoritative_nameserver": None,
        "errors": [],
        "warnings": [],
        "recommendations": [],
        "grade": None
    }
   
    # First get the SOA record to find the authoritative nameserver
    try:
        auth_ns = get_authoritative_nameserver(domain)
        if auth_ns:
            results["authoritative_nameserver"] = auth_ns

            # Get nameserver IPs
            ns_ips = get_nameserver_ips(auth_ns)
            if ns_ips:
                # Create a resolver using the authoritative nameserver
                auth_resolver = dns.resolver.Resolver()
                auth_resolver.nameservers = [ns_ips[0]]  # Use the first IP
                auth_resolver.timeout = 5.0
                auth_resolver.lifetime = 10.0

                logger.info(f"Using authoritative nameserver {auth_ns} ({ns_ips[0]}) for {domain}")
            else:
                logger.warning(f"Could not resolve IP for nameserver {auth_ns}, using default resolver")
                auth_resolver = dns.resolver.Resolver()
        else:
            logger.warning(f"Could not determine authoritative nameserver for {domain}, using default resolver")
            auth_resolver = dns.resolver.Resolver()
    except Exception as e:
        logger.error(f"Error setting up authoritative resolver: {str(e)}")
        auth_resolver = dns.resolver.Resolver()

    # Regular record types to query
    record_types = {
        'A': "a_records",
        'AAAA': "aaaa_records",
        'MX': "mx_records",
        'NS': "ns_records",
        'TXT': "txt_records",
        'SOA': "soa_record",
        'CAA': "caa_records"
    }
    
    for rdtype, result_key in record_types.items():
        try:
            if rdtype == 'SOA':
                # SOA has special handling (only one record)
                answers = auth_resolver.resolve(domain, rdtype)
                soa = answers[0]
                results["soa_record"] = {
                    "mname": str(soa.mname).rstrip('.'),
                    "rname": str(soa.rname).rstrip('.'),
                    "serial": soa.serial,
                    "refresh": soa.refresh,
                    "retry": soa.retry,
                    "expire": soa.expire,
                    "minimum": soa.minimum
                }
            elif rdtype == 'MX':
                # MX records have special handling
                answers = auth_resolver.resolve(domain, rdtype)
                mx_records = []
                for rdata in answers:
                    mx_records.append({
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange).rstrip('.')
                    })
                results["mx_records"] = sorted(mx_records, key=lambda x: x["preference"])
            elif rdtype == 'TXT':
                # TXT records need special handling
                answers = auth_resolver.resolve(domain, rdtype)
                txt_records = []
                
                for rdata in answers:
                    txt_value = "".join(s.decode() for s in rdata.strings)
                    txt_records.append(txt_value)
                    
                    # Check for SPF record
                    if txt_value.startswith('v=spf1'):
                        results["spf_record"] = txt_value
                        
                results["txt_records"] = txt_records
                
                # Check for DMARC record
                try:
                    dmarc_answers = auth_resolver.resolve(f"_dmarc.{domain}", 'TXT')
                    for rdata in dmarc_answers:
                        dmarc_txt = "".join(s.decode() for s in rdata.strings)
                        if dmarc_txt.startswith('v=DMARC1'):
                            results["dmarc_record"] = dmarc_txt
                            break
                except Exception:
                    # DMARC record not found, which is fine
                    pass
                    
            elif rdtype == 'CAA':
                answers = auth_resolver.resolve(domain, rdtype)
                caa_records = []
                for rdata in answers:
                    caa_records.append({
                        "flags": rdata.flags,
                        "tag": str(rdata.tag),
                        "value": str(rdata.value).strip('"')
                    })
                results["caa_records"] = caa_records
            else:
                # Regular handling for other record types
                answers = auth_resolver.resolve(domain, rdtype)
                results[result_key] = [str(rdata) for rdata in answers]
                
        except dns.resolver.NoAnswer:
            # No records of this type, which is fine
            pass
        except dns.resolver.NXDOMAIN:
            results["errors"].append("Domain does not exist")
            break
        except Exception as e:
            results["errors"].append(f"Error retrieving {rdtype} records: {str(e)}")
    
    # Add enhanced security checks (wrapped in try-except to ensure JSON serialization)
    try:
        security_checks = {
            "dnssec": check_dnssec(domain),
            "nameserver_diversity": check_nameserver_diversity(domain),
            "zone_transfer": check_zone_transfer(domain),
            "open_resolver": check_open_resolver(domain),
            "wildcard_dns": check_wildcard_dns(domain)
        }
        
        # Add security check warnings and recommendations to main results
        for check_name, check_result in security_checks.items():
            if "warnings" in check_result:
                results["warnings"].extend(check_result.get("warnings", []))
            if "recommendations" in check_result:
                results["recommendations"].extend(check_result.get("recommendations", []))
        
        results["security_checks"] = security_checks
        
        # Verify JSON serialization
        try:
            json.dumps(results["security_checks"])
        except Exception as e:
            logger.error(f"JSON serialization error in security_checks: {str(e)}")
            # Provide a simplified version that's guaranteed to serialize
            results["security_checks"] = {
                "error": "Could not serialize security checks results",
                "message": str(e)
            }
    except Exception as e:
        logger.error(f"Error in security checks: {str(e)}")
        results["security_checks"] = {
            "error": "Error performing security checks",
            "message": str(e)
        }
    
    # Add subdomain checks
    try:
        results["common_subdomains"] = check_common_subdomains(domain)
        
        # Verify JSON serialization
        try:
            json.dumps(results["common_subdomains"])
        except Exception as e:
            logger.error(f"JSON serialization error in common_subdomains: {str(e)}")
            results["common_subdomains"] = {
                "error": "Could not serialize subdomain check results",
                "message": str(e)
            }
    except Exception as e:
        logger.error(f"Error in subdomain checks: {str(e)}")
        results["common_subdomains"] = {
            "error": "Error performing subdomain checks",
            "message": str(e)
        }
    
    # Grade DNS configuration
    try:
        results["grade"] = grade_dns_configuration(results)
    except Exception as e:
        logger.error(f"Error grading DNS configuration: {str(e)}")
        results["grade"] = {
            "grade": "F",
            "score": 0,
            "description": "Error grading DNS configuration"
        }
    
    # Final JSON serialization check
    try:
        json.dumps(results)
    except (TypeError, OverflowError) as e:
        logger.error(f"Final JSON serialization error: {str(e)}")
        # Return a simplified version that will serialize
        return {
            "error": "Could not serialize DNS results",
            "message": "The DNS results contain data that cannot be converted to JSON",
            "basic_records": {
                "a_records": results.get("a_records", []),
                "aaaa_records": results.get("aaaa_records", []),
                "mx_records": results.get("mx_records", []),
                "ns_records": results.get("ns_records", []),
                "txt_records": results.get("txt_records", []),
                "errors": results.get("errors", []) + ["JSON serialization error"]
            },
            "grade": results.get("grade", {
                "grade": "F", 
                "score": 0, 
                "description": "Error processing DNS records"
            })
        }
    
    return results

def grade_dns_configuration(dns_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Grade the DNS configuration based on security best practices.

    Args:
        dns_results (Dict): DNS check results

    Returns:
        Dict: Grade information
    """
    grade = {
        "score": 0,
        "grade": "C",
        "description": "Average DNS configuration"
    }

    # Start with a baseline score
    score = 5.0

    # Check for basic DNS records
    if not dns_results.get("ns_records"):
        grade["grade"] = "F"
        grade["description"] = "Missing NS records"
        return grade

    # Check for DNSSEC
    dnssec = dns_results.get("security_checks", {}).get("dnssec", {})
    if dnssec.get("enabled", False) and dnssec.get("validated", False):
        score += 2.0  # Excellent
    elif dnssec.get("enabled", False) and not dnssec.get("validated", False):
        score += 0.5  # Partial implementation

    # Check for weak DNSSEC algorithms
    if dnssec.get("enabled", False) and dnssec.get("errors"):
        for error in dnssec.get("errors", []):
            if "weak" in error.lower() and "algorithm" in error.lower():
                score -= 1.0  # Weak algorithm

    # Check nameserver diversity
    ns_diversity = dns_results.get("security_checks", {}).get("nameserver_diversity", {})
    unique_ips = len(ns_diversity.get("unique_ips", []))
    unique_prefixes = len(ns_diversity.get("unique_prefixes", []))

    if unique_ips >= 4:
        score += 1.5  # Excellent
    elif unique_ips >= 3:
        score += 1.0  # Good
    elif unique_ips < 2:
        score -= 1.0  # Poor

    # Check for nameservers in the same subnet
    same_subnet_count = ns_diversity.get("same_subnet_count", 0)
    if same_subnet_count > 0:
        score -= 1.0  # Not diverse

    # Check for zone transfers
    zone_transfer = dns_results.get("security_checks", {}).get("zone_transfer", {})
    if zone_transfer.get("allowed", False):
        score -= 3.0  # Critical issue

    # Check for open resolvers
    open_resolver = dns_results.get("security_checks", {}).get("open_resolver", {})
    if open_resolver.get("open_resolvers", []):
        score -= 2.5  # Serious issue

    # Check for wildcard DNS
    wildcard_dns = dns_results.get("security_checks", {}).get("wildcard_dns", {})
    if wildcard_dns.get("has_wildcard", False):
        score -= 0.5  # Potential issue

    # Check for CAA records
    has_caa = False
    for record_type, records in dns_results.items():
        if record_type == "caa_records" and records:
            has_caa = True
            score += 1.0  # Good security practice

    # Calculate grade
    grade["score"] = round(score, 1)

    if score >= 8.0:
        grade["grade"] = "A+"
        grade["description"] = "Excellent DNS configuration"
    elif score >= 7.0:
        grade["grade"] = "A"
        grade["description"] = "Very good DNS configuration"
    elif score >= 6.0:
        grade["grade"] = "B+"
        grade["description"] = "Good DNS configuration"
    elif score >= 5.0:
        grade["grade"] = "B"
        grade["description"] = "Above average DNS configuration"
    elif score >= 4.0:
        grade["grade"] = "C+"
        grade["description"] = "Decent DNS configuration"
    elif score >= 3.0:
        grade["grade"] = "C"
        grade["description"] = "Average DNS configuration"
    elif score >= 2.0:
        grade["grade"] = "D"
        grade["description"] = "Below average DNS configuration"
    else:
        grade["grade"] = "F"
        grade["description"] = "Poor DNS configuration"

    return grade

# Alias function to match import in routes.py
get_dns_records = get_all_dns_records
