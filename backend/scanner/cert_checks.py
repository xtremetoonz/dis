import dns.resolver
import requests
from typing import Dict, List, Optional
from datetime import datetime
import ssl
import socket

class CertificateChecker:
    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.timestamp = "2025-05-02 21:29:24"

    def check_caa_records(self) -> Dict:
        """
        Checks CAA (Certificate Authority Authorization) records.
        """
        result = {
            "found": False,
            "records": [],
            "valid": False,
            "authorized_cas": [],
            "wildcard_allowed": False,
            "errors": [],
            "recommendations": []
        }

        try:
            caa_records = self.resolver.resolve(self.domain, 'CAA')
            result["found"] = True

            for record in caa_records:
                caa_entry = {
                    "flags": record.flags,
                    "tag": str(record.tag),
                    "value": str(record.value).strip('"')
                }
                result["records"].append(caa_entry)

                if caa_entry["tag"] == "issue":
                    result["authorized_cas"].append(caa_entry["value"])
                    result["valid"] = True
                elif caa_entry["tag"] == "issuewild":
                    result["wildcard_allowed"] = True
                    result["authorized_cas"].append(f"wildcard:{caa_entry['value']}")

            if not result["authorized_cas"]:
                result["recommendations"].append(
                    "No authorized CAs specified in CAA records"
                )

        except dns.resolver.NoAnswer:
            result["recommendations"].append("Consider implementing CAA records")
        except Exception as e:
            result["errors"].append(f"Error checking CAA records: {str(e)}")

        return result

    def check_certificate(self) -> Dict:
        """
        Checks SSL/TLS certificate details.
        """
        result = {
            "valid": False,
            "issuer": None,
            "subject": None,
            "sans": [],
            "not_before": None,
            "not_after": None,
            "signature_algorithm": None,
            "key_size": None,
            "errors": [],
            "recommendations": []
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    result["valid"] = True
                    result["issuer"] = dict(x[0] for x in cert['issuer'])
                    result["subject"] = dict(x[0] for x in cert['subject'])
                    result["not_before"] = cert['notBefore']
                    result["not_after"] = cert['notAfter']
                    
                    if 'subjectAltName' in cert:
                        result["sans"] = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']

                    # Check certificate expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    current_date = datetime.strptime(self.timestamp, '%Y-%m-%d %H:%M:%S')
                    days_to_expiry = (expiry_date - current_date).days

                    if days_to_expiry < 30:
                        result["recommendations"].append(
                            f"Certificate expires in {days_to_expiry} days. Plan renewal."
                        )

        except ssl.SSLError as e:
            result["errors"].append(f"SSL Error: {str(e)}")
            result["recommendations"].append("Fix SSL certificate configuration")
        except Exception as e:
            result["errors"].append(f"Error checking certificate: {str(e)}")

        return result

    def check_ct_logs(self) -> Dict:
        """
        Checks Certificate Transparency logs.
        """
        result = {
            "logs_checked": [],
            "certificates_found": [],
            "errors": [],
            "recommendations": []
        }

        ct_endpoints = [
            "https://ct.googleapis.com/logs/argon2025/",
            "https://ct.cloudflare.com/logs/nimbus2025/"
        ]

        for endpoint in ct_endpoints:
            try:
                response = requests.get(
                    f"{endpoint}ct/v1/get-entries",
                    params={"domain": self.domain},
                    timeout=10
                )
                
                if response.status_code == 200:
                    result["logs_checked"].append(endpoint)
                    log_data = response.json()
                    
                    if "entries" in log_data:
                        for entry in log_data["entries"]:
                            if isinstance(entry, dict) and "leaf_input" in entry:
                                result["certificates_found"].append({
                                    "log": endpoint,
                                    "timestamp": entry.get("timestamp"),
                                    "sequence": entry.get("sequence_number")
                                })

            except requests.exceptions.RequestException as e:
                result["errors"].append(f"Error checking CT log {endpoint}: {str(e)}")

        if not result["logs_checked"]:
            result["recommendations"].append(
                "Unable to check Certificate Transparency logs"
            )

        return result

    def validate_cert_chain(self) -> Dict:
        """
        Validates the certificate chain.
        """
        result = {
            "valid": False,
            "chain_length": 0,
            "intermediate_certs": [],
            "errors": [],
            "recommendations": []
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert_chain = context.get_ca_certs()
                    result["valid"] = True
                    result["chain_length"] = len(cert_chain) + 1

                    for cert in cert_chain:
                        result["intermediate_certs"].append({
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer'])
                        })

        except ssl.SSLError as e:
            result["errors"].append(f"SSL chain validation error: {str(e)}")
            result["recommendations"].append("Fix certificate chain configuration")
        except Exception as e:
            result["errors"].append(f"Error validating certificate chain: {str(e)}")

        return result

    def run_all_checks(self) -> Dict:
        """
        Runs all certificate-related security checks.
        """
        return {
            "caa_records": self.check_caa_records(),
            "certificate": self.check_certificate(),
            "ct_logs": self.check_ct_logs(),
            "cert_chain": self.validate_cert_chain()
        }
