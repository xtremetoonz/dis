# Domain Intel Scanner (DIS) Requirements

_Last Updated: 2025-03-28_

## 1. General Overview

DIS is a DNS monitoring and domain intelligence tool that:
- Accepts a single domain name
- Runs multiple DNS, WHOIS, and email-related security checks
- Displays informative and actionable output for administrators
- Uses the SOA nameserver to avoid cache for relevant DNS queries
- Supports modular development and individual file version tracking

---

## 2. WHOIS Checks

### 2.1 Basic Info
- Registrar
- WHOIS Server
- Registration Date
- Expiration Date
- Updated Date

### 2.2 Contact Info
- Registrant Name
- Registrant Organization
- Registrant Email
- Tech Name
- Tech Organization
- Tech Email

### 2.3 Privacy Tag
- Flag WHOIS output as "Privacy Protected" if using known masking values

### 2.4 Timeouts and Fallback
- Primary WHOIS server timeout set to 12 seconds
- Retry with fallback server on timeout

---

## 3. DNS Checks

### 3.1 Name Server Inspection
- List all NS with IPs and ASNs
- Ensure each NS returns the same SOA serial number
- Warn if NS are on the same /24 CIDR
- Warn if NS are on the same ASN

### 3.2 Zone Transfer (AXFR)
- Test against all SOA nameservers
- Output dig response under result
- ✅ if denied, ⚠️ if allowed or ambiguous

### 3.3 Open Resolver
- Use SOA NS to check
- ✅ if not open, ⚠️ if test indicates recursion

### 3.4 DNSSEC
- Check for DNSKEY records
- ⚠️ if not present
- Include DNSKEY algorithm strength
- ⚠️ if RSA/SHA-1 is used

### 3.5 A/AAAA Records
- A record returned as part of MX, CNAME, or host checks
- ✅ if resolved, ℹ️ if missing
- AAAA check is ℹ️ informational only

### 3.6 Common Subdomain Hostnames
- Check: www, mail, ftp, smtp, imap, pop, pop3, webmail, api, app, portal, login, support, docs, cdn, blog, shop, status, dashboard, vpn, autodiscover
- If CNAME: show target and resolved IP
- If A: show IP

### 3.7 MX Record
- ⚠️ if not found
- Suggest non-sending domain

### 3.8 SPF Record
- Show record and count total DNS queries
- ✅ if "-all", ⚠️ otherwise
- ⚠️ if lookup count exceeds 10

### 3.9 DMARC Record
- Show policy
- ⚠️ if missing or p=none

### 3.10 DKIM Record
- Test against known selectors:
  - spop1024, dk, mandrill, mailchimp (k2, k3, mte1, mte2), mailgun, mailjet, mailkit, mailpoet, mailup, mapp1, pm, 20210112, emsd1, k1, selector1, selector2, s1, s2, default, sendgrid, amazonses, mail, mailsec, scph0418, _domainkey
- Group by provider
- Show TXT result or note selector tested
- CNAME → TXT failure is a ⚠️
- If MX is Google or Microsoft and their selectors missing → ❌

### 3.11 BIMI
- Only check if DMARC is enforced (quarantine or reject)
- ⚠️ if missing

### 3.12 TXT Records
- ✅ if found, ⚠️ if not

### 3.13 MTA-STS
- ✅ if found, ⚠️ if not

### 3.14 TLS-RPT
- ✅ if found, ⚠️ if not

### 3.15 CAA Records
- ✅ if found
- If not: query Cert Spotter CT API for issued certs

### 3.16 Wildcard DNS
- Test using random non-existent subdomain
- ⚠️ if A record returned

---

## 4. Output Conventions

- ⚠️ Warning
- ✅ Success
- ❌ Critical Failure
- ℹ️ Informational
- ✋ High-five emoji at end if no warnings

## 5. Development Conventions

- Versioned files (e.g., `main.py v4.5.0`)
- Update changelog with each revision
- Tests use dig, whois, and curl via subprocess
- Use SOA NS for primary domain queries
- Do NOT use SOA for external CNAME TXT queries (e.g., DKIM, DMARC)
