from flask import Flask, request, jsonify
import uuid
from scanner.whois_checks import run_whois, parse_whois
from scanner.dns_checks import check_mx_records, check_dnssec
import mysql.connector

app = Flask(__name__)

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="dis_user",
        password="tv6LhpUq_ytcU9@o2g93",
        database="dis_database"
    )

# Helper: Execute Linux commands
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return result
    except subprocess.CalledProcessError as e:
        return e.output

@app.route('/api/scan', methods=['POST'])
def scan_domain():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    scan_id = str(uuid.uuid4())
    results = {}

    # Perform WHOIS checks
    whois_raw = run_whois(domain)
    if whois_raw["status"] == "success":
        results["whois"] = parse_whois(whois_raw["data"])
    else:
        results["whois"] = {"status": "error", "message": whois_raw["message"]}

    # Perform DNS checks
    results["mx_records"] = check_mx_records(domain)
    results["dnssec"] = check_dnssec(domain)

    # Save results to MySQL database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (id, domain, results) VALUES (%s, %s, %s)",
                   (scan_id, domain, str(results)))
    conn.commit()
    conn.close()

    return jsonify({"scan_id": scan_id, "results": results}), 200

@app.route('/api/results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT results FROM scans WHERE id = %s", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({"scan_id": scan_id, "results": eval(row[0])})
    else:
        return jsonify({"error": "Scan ID not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
