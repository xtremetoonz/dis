import dns.resolver
from dns.exception import DNSException
from typing import Dict, List, Any
import logging

# Configure module logger
logger = logging.getLogger(__name__)

def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves all basic DNS records for a domain without any analysis.
    
    Args:
        domain (str): The domain to query
        
    Returns:
        Dict: Dictionary containing all retrieved DNS records
    """
    results = {
        "a_records": [],
        "aaaa_records": [],
        "ns_records": [],
        "txt_records": [],
        "soa_record": None,
        "caa_records": [],
        "errors": []
    }
    
    # Record types to query
    record_types = ['A', 'AAAA', 'NS', 'TXT', 'SOA', 'CAA']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0  # 5 second timeout
    resolver.lifetime = 10.0  # 10 second total query time
    
    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            
            if record_type == 'A':
                results["a_records"] = [str(rdata) for rdata in answers]
                
            elif record_type == 'AAAA':
                results["aaaa_records"] = [str(rdata) for rdata in answers]
                
            elif record_type == 'NS':
                ns_records = []
                for rdata in answers:
                    ns_name = str(rdata)
                    # Get IP for each nameserver
                    try:
                        ns_ips = resolver.resolve(ns_name, 'A')
                        ip_list = [str(ip) for ip in ns_ips]
                    except DNSException:
                        ip_list = []
                        
                    ns_records.append({
                        "nameserver": ns_name,
                        "ip_addresses": ip_list
                    })
                results["ns_records"] = ns_records
                
            elif record_type == 'TXT':
                txt_records = []
                for rdata in answers:
                    # Join TXT record chunks and decode
                    txt_value = "".join(s.decode() for s in rdata.strings)
                    txt_records.append(txt_value)
                results["txt_records"] = txt_records
                
            elif record_type == 'SOA':
                # SOA has only one record
                soa = answers[0]
                results["soa_record"] = {
                    "mname": str(soa.mname),
                    "rname": str(soa.rname),
                    "serial": soa.serial,
                    "refresh": soa.refresh,
                    "retry": soa.retry,
                    "expire": soa.expire,
                    "minimum": soa.minimum
                }
                
            elif record_type == 'CAA':
                caa_records = []
                for rdata in answers:
                    caa_records.append({
                        "flags": rdata.flags,
                        "tag": str(rdata.tag),
                        "value": str(rdata.value).strip('"')
                    })
                results["caa_records"] = caa_records
                
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")
            # Not an error, just no records of this type
            pass
            
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {domain} does not exist")
            results["errors"].append("Domain does not exist")
            break  # Stop checking if domain doesn't exist
            
        except dns.resolver.Timeout:
            logger.warning(f"Timeout querying {record_type} records for {domain}")
            results["errors"].append(f"Timeout querying {record_type} records")
            
        except Exception as e:
            logger.error(f"Error querying {record_type} records for {domain}: {str(e)}")
            results["errors"].append(f"Error querying {record_type} records: {str(e)}")
    
    return results
