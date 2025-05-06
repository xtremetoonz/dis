import dns.resolver
import dns.query
import dns.zone
from dns.exception import DNSException
from typing import Dict

def get_all_dns_records(domain: str) -> Dict:
    """
    Retrieves all relevant DNS records for a domain.
    """
    results = {
        "a_records": [],
        "aaaa_records": [],
        "txt_records": [],
        "mx_records": [],
        "ns_records": [],
        "errors": []
    }

    record_types = ['A', 'AAAA', 'TXT', 'MX', 'NS']
    resolver = dns.resolver.Resolver()

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            for rdata in answers:
                if record_type == 'A':
                    results["a_records"].append(str(rdata))
                elif record_type == 'AAAA':
                    results["aaaa_records"].append(str(rdata))
                elif record_type == 'TXT':
                    results["txt_records"].append("".join(s.decode() for s in rdata.strings))
                elif record_type == 'MX':
                    results["mx_records"].append({
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange)
                    })
                elif record_type == 'NS':
                    results["ns_records"].append(str(rdata))
        except dns.resolver.NoAnswer:
            continue
        except Exception as e:
            results["errors"].append(f"Error getting {record_type} records: {str(e)}")

    return results

def check_dnssec(domain: str) -> Dict:
    """
    Checks DNSSEC configuration for the domain.
    """
    result = {
        "enabled": False,
        "valid": False,
        "errors": []
    }

    try:
        dnskey = dns.resolver.resolve(domain, 'DNSKEY')
        ds = dns.resolver.resolve(domain, 'DS')
        
        result["enabled"] = True
        result["valid"] = bool(dnskey and ds)
        
    except dns.resolver.NoAnswer:
        result["errors"].append("No DNSSEC records found")
    except Exception as e:
        result["errors"].append(f"Error checking DNSSEC: {str(e)}")

    return result
