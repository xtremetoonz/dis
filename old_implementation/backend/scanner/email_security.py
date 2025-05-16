import dns.resolver
from typing import Dict
import re

class EmailSecurityChecker:
    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()

    def check_spf(self) -> Dict:
        """
        Checks SPF record configuration.
        """
        result = {
            "record": None,
            "valid": False,
            "mechanisms": [],
            "all_directive": None,
            "includes": [],
            "errors": [],
            "recommendations": []
        }

        try:
            txt_records = self.resolver.resolve(self.domain, 'TXT')
            for record in txt_records:
                spf_record = "".join(s.decode() for s in record.strings)
                if spf_record.startswith('v=spf1'):
                    result["record"] = spf_record
                    result["valid"] = True
                    
                    # Parse mechanisms
                    mechanisms = spf_record.split()[1:]
                    for mechanism in mechanisms:
                        if mechanism.startswith('include:'):
                            result["includes"].append(mechanism[8:])
                        elif mechanism in ['~all', '-all', '?all', '+all']:
                            result["all_directive"] = mechanism
                        result["mechanisms"].append(mechanism)

                    # Validate configuration
                    if not result["all_directive"]:
                        result["recommendations"].append("Add -all or ~all directive")
                    elif result["all_directive"] == '+all':
                        result["recommendations"].append("Change +all to -all or ~all for security")

        except dns.resolver.NoAnswer:
            result["errors"].append("No SPF record found")
            result["recommendations"].append("Implement SPF record")
        except Exception as e:
            result["errors"].append(f"Error checking SPF: {str(e)}")

        return result

    def check_dkim(self) -> Dict:
        """
        Checks DKIM configuration.
        """
        result = {
            "records": {},
            "valid": False,
            "selectors_found": [],
            "errors": [],
            "recommendations": []
        }

        selectors = ['default', 'google', 'mail', 'key1', 'selector1']
        
        for selector in selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                dkim_records = self.resolver.resolve(dkim_domain, 'TXT')
                
                for record in dkim_records:
                    dkim_record = "".join(s.decode() for s in record.strings)
                    if 'v=DKIM1' in dkim_record:
                        result["records"][selector] = dkim_record
                        result["selectors_found"].append(selector)
                        result["valid"] = True

            except dns.resolver.NXDOMAIN:
                continue
            except Exception as e:
                result["errors"].append(f"Error checking DKIM for selector {selector}: {str(e)}")

        if not result["valid"]:
            result["recommendations"].append("Implement DKIM with at least one selector")

        return result

    def check_dmarc(self) -> Dict:
        """
        Checks DMARC configuration.
        """
        result = {
            "record": None,
            "valid": False,
            "policy": None,
            "pct": None,
            "rua": [],
            "errors": [],
            "recommendations": []
        }

        try:
            dmarc_records = self.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            
            for record in dmarc_records:
                dmarc_record = "".join(s.decode() for s in record.strings)
                if dmarc_record.startswith('v=DMARC1'):
                    result["record"] = dmarc_record
                    result["valid"] = True
                    
                    # Parse DMARC record
                    for tag in dmarc_record.split(';'):
                        tag = tag.strip()
                        if '=' in tag:
                            key, value = tag.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            if key == 'p':
                                result["policy"] = value
                            elif key == 'pct':
                                result["pct"] = value
                            elif key == 'rua':
                                result["rua"] = value.split(',')

                    # Add recommendations based on policy
                    if result["policy"] == "none":
                        result["recommendations"].append("Consider stronger DMARC policy (quarantine/reject)")
                    if not result["rua"]:
                        result["recommendations"].append("Add aggregate report URI (rua tag)")

        except dns.resolver.NoAnswer:
            result["errors"].append("No DMARC record found")
            result["recommendations"].append("Implement DMARC record")
        except Exception as e:
            result["errors"].append(f"Error checking DMARC: {str(e)}")

        return result

    def run_all_checks(self) -> Dict:
        """
        Runs all email security checks.
        """
        return {
            "spf_checks": self.check_spf(),
            "dkim_checks": self.check_dkim(),
            "dmarc_checks": self.check_dmarc()
        }
