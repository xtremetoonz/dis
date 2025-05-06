import requests
from typing import Dict
import dns.resolver
import ssl
import socket

class TLSSecurityChecker:
    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()

    def check_mta_sts(self) -> Dict:
        """
        Checks MTA-STS configuration.
        """
        result = {
            "valid": False,
            "policy": {
                "version": None,
                "mode": None,
                "max_age": None,
                "mx": []
            },
            "dns_record": None,
            "errors": [],
            "recommendations": []
        }

        try:
            # Check DNS record
            txt_records = self.resolver.resolve(f"_mta-sts.{self.domain}", 'TXT')
            for record in txt_records:
                txt_record = "".join(s.decode() for s in record.strings)
                if txt_record.startswith('v=STSv1'):
                    result["dns_record"] = txt_record
                    result["valid"] = True

            # Check policy file
            if result["valid"]:
                response = requests.get(
                    f"https://mta-sts.{self.domain}/.well-known/mta-sts.txt",
                    timeout=10
                )
                if response.status_code == 200:
                    for line in response.text.splitlines():
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower()
                            value = value.strip()
                            if key in result["policy"]:
                                result["policy"][key] = value

        except requests.exceptions.RequestException as e:
            result["errors"].append(f"Error fetching MTA-STS policy: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Error checking MTA-STS: {str(e)}")

        return result

    def check_tls_rpt(self) -> Dict:
        """
        Checks TLS-RPT configuration.
        """
        result = {
            "valid": False,
            "record": None,
            "rua": [],
            "errors": [],
            "recommendations": []
        }

        try:
            txt_records = self.resolver.resolve(f"_smtp._tls.{self.domain}", 'TXT')
            for record in txt_records:
                txt_record = "".join(s.decode() for s in record.strings)
                if txt_record.startswith('v=TLSRPTv1'):
                    result["record"] = txt_record
                    result["valid"] = True
                    
                    # Parse reporting URIs
                    if 'rua=' in txt_record:
                        uris = txt_record.split('rua=')[1].split(';')[0]
                        result["rua"] = [uri.strip() for uri in uris.split(',')]

        except dns.resolver.NoAnswer:
            result["recommendations"].append("Implement TLS-RPT record")
        except Exception as e:
            result["errors"].append(f"Error checking TLS-RPT: {str(e)}")

        return result

    def check_ssl_tls(self) -> Dict:
        """
        Checks SSL/TLS configuration.
        """
        result = {
            "valid": False,
            "protocol_versions": [],
            "cipher_suites": [],
            "errors": [],
            "recommendations": []
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    result["valid"] = True
                    result["protocol_versions"].append(ssock.version())
                    result["cipher_suites"].append(ssock.cipher())

        except ssl.SSLError as e:
            result["errors"].append(f"SSL Error: {str(e)}")
            result["recommendations"].append("Fix SSL configuration")
        except Exception as e:
            result["errors"].append(f"Error checking SSL/TLS: {str(e)}")

        return result

    def run_all_checks(self) -> Dict:
        """
        Runs all TLS security checks.
        """
        return {
            "mta_sts_checks": self.check_mta_sts(),
            "tls_rpt_checks": self.check_tls_rpt(),
            "ssl_tls_checks": self.check_ssl_tls()
        }
