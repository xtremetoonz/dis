# dkim_utils.py - Version 4.4.0

import subprocess
from typing import List

def run_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,  # 10 second timeout
            check=False  # Don't raise on non-zero exit
        )
        if result.returncode != 0 and result.stderr:
            return f"Command error: {result.stderr.strip()}"
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "Command timed out after 10 seconds"
    except FileNotFoundError as e:
        return f"Required command not found: {command[0]}"
    except Exception as e:
        return f"Error running command: {str(e)}"

# Full set of DKIM selectors to test
SELECTORS = [
    "spop1024", "dk", "mandrill", "mailchimp", "mailgun", "mailjet", "mailkit",
    "mailpoet", "mailup", "mapp1", "pm", "20210112", "emsd1", "k1", "selector1",
    "selector2", "s1", "s2", "default", "sendgrid", "amazonses", "mail", "mailsec",
    "scph0418", "_domainkey"
]

PROVIDER_GROUPS = {
    "Microsoft": ["selector1", "selector2"],
    "Google": ["s1", "s2"],
    "Amazon SES": ["amazonses"],
    "Mailchimp": ["k2", "k3", "mte1", "mte2"],
    "Mandrill": ["mandrill"],
    "SendGrid": ["sendgrid"],
    "Others": [s for s in SELECTORS if s not in [s for grp in [
        ["selector1", "selector2"], ["s1", "s2"], ["amazonses"],
        ["k2", "k3", "mte1", "mte2"], ["mandrill"], ["sendgrid"]] for s in grp]]
}

def get_authoritative_ns(domain: str) -> str:
    output = run_command(["dig", "SOA", domain, "+short"])
    return output.split()[0] if output and not output.startswith(("Command error:", "Error running")) else ""

def check_dkim(domain: str) -> str:
    results = ["🔍 DKIM Selector Check:"]
    found_selectors = set()

    for selector in SELECTORS:
        query = f"{selector}._domainkey.{domain}"
        cname = run_command(["dig", "CNAME", query, "+short"])

        # Check if we got an error
        if cname.startswith(("Command error:", "Error running")):
            results.append(f"⚠️ Error checking {selector}: {cname}")
            continue

        if cname:
            txt = run_command(["dig", "TXT", cname.strip(), "+short"])
            if txt and not txt.startswith(("Command error:", "Error running")):
                results.append(f"✅ {selector} found via CNAME {cname.strip()} -> TXT: {txt.strip()}")
                found_selectors.add(selector)
            else:
                results.append(f"⚠️ {selector} CNAME found ({cname.strip()}), but TXT record is missing")
        else:
            txt = run_command(["dig", "TXT", query, "+short"])
            if txt and not txt.startswith(("Command error:", "Error running")):
                results.append(f"✅ {selector} TXT record found: {txt.strip()}")
                found_selectors.add(selector)
            else:
                results.append(f"ℹ️ {selector} selector tested but no record found")

    return "\n".join(results)

def warn_if_expected_dkim_missing(mx_result: str, dkim_output: str) -> List[str]:
    warnings = []
    found = set([line.split()[1] for line in dkim_output.splitlines()
                if line.startswith("✅")])

    if "outlook.com" in mx_result.lower() or "protection.outlook.com" in mx_result.lower():
        for sel in PROVIDER_GROUPS["Microsoft"]:
            if sel not in found:
                warnings.append(f"❌ Missing expected Microsoft DKIM selector: {sel}")

    if "google.com" in mx_result.lower():
        for sel in PROVIDER_GROUPS["Google"]:
            if sel not in found:
                warnings.append(f"❌ Missing expected Google DKIM selector: {sel}")

    return warnings
