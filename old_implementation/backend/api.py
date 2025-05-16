from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import uuid
from backend.scanner.dns_checks import get_all_dns_records, check_dnssec
from backend.scanner.email_security import EmailSecurityChecker
from backend.scanner.tls_checks import TLSSecurityChecker
from backend.scanner.cert_checks import CertificateChecker

app = Flask(__name__)
CORS(app)

@app.route('/api/scan', methods=['POST'])
def scan_domain():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    scan_id = str(uuid.uuid4())
    
    results = {
        "scan_metadata": {
            "scan_id": scan_id,
            "domain": domain,
            "timestamp": "2025-05-02 21:50:09"
        }
    }

    try:
        # Run DNS checks
        results["dns_checks"] = {
            "records": get_all_dns_records(domain),
            "dnssec": check_dnssec(domain)
        }

        # Run Email Security checks
        email_checker = EmailSecurityChecker(domain)
        email_results = email_checker.run_all_checks()
        results.update({
            "spf_checks": email_results["spf_checks"],
            "dkim_checks": email_results["dkim_checks"],
            "dmarc_checks": email_results["dmarc_checks"]
        })

        # Run TLS checks
        tls_checker = TLSSecurityChecker(domain)
        tls_results = tls_checker.run_all_checks()
        results.update({
            "mta_sts_checks": tls_results["mta_sts_checks"],
            "tls_rpt_checks": tls_results["tls_rpt_checks"],
            "ssl_tls_checks": tls_results["ssl_tls_checks"]
        })

        # Run Certificate checks
        cert_checker = CertificateChecker(domain)
        cert_results = cert_checker.run_all_checks()
        results.update({
            "caa_records": cert_results["caa_records"],
            "ct_logs": cert_results["ct_logs"],
            "cert_chain": cert_results["cert_chain"],  # Changed from ca_validation to cert_chain
            "certificate": cert_results["certificate"]  # Added certificate details
        })

        return jsonify(results), 200

    except Exception as e:
        return jsonify({
            "error": "Scan failed",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
