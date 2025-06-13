# Domain Intel Scanner API Documentation

## Overview

The Domain Intel Scanner API provides comprehensive domain security analysis including DNS records, email security configurations, SSL/TLS information, and WHOIS data.

**Base URL:** `http://api.domainintelscanner.com:5000`

## Authentication

All API endpoints require authentication via an API key passed in the request header.

**Header Required:**
```
X-API-Key: your-api-key-here
```

**Error Response (401 Unauthorized):**
```json
{
  "status": "error",
  "message": "Unauthorized - Valid API key required"
}
```

## Rate Limiting

- **Default Limits:** 200 requests per day, 50 requests per hour
- **Rate Limit Exceeded (429):**
```json
{
  "status": "error",
  "message": "Rate limit exceeded",
  "details": "50 per 1 hour"
}
```

## Response Format

All successful responses follow this standardized format:

```json
{
  "status": "success",
  "timestamp": "2025-06-13T14:30:00.000Z",
  "domain": "example.com",
  "endpoint": "dns",
  "data": {
    // Endpoint-specific data
  }
}
```

**Error Response Format:**
```json
{
  "status": "error",
  "timestamp": "2025-06-13T14:30:00.000Z",
  "domain": "example.com",
  "data": {
    "message": "Error description"
  }
}
```

## Endpoints

### Health Check

**GET** `/health`

Check API service status (no authentication required).

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-06-13T14:30:00.000Z",
  "version": "1.0.0",
  "environment": "production"
}
```

### Authentication Verification

**GET** `/api/v1/auth/verify`

Verify your API key and view client information.

**Response:**
```json
{
  "status": "success",
  "authenticated": true,
  "client_id": "client-uuid",
  "client_name": "your-client-name",
  "message": "Authentication successful for your-client-name"
}
```

### DNS Records Analysis

**GET** `/api/v1/dns?domain={domain}`

Comprehensive DNS analysis including security checks and grading.

**Parameters:**
- `domain` (required): The domain to analyze

**Response Data Includes:**
- A, AAAA, MX, NS, TXT, CAA records
- SOA record details
- SPF and DMARC records
- Subdomain discovery
- Security checks (DNSSEC, nameserver diversity, open resolvers, wildcard DNS, zone transfers)
- DNS configuration grade (A+ to F)

**Example Request:**
```bash
curl -H "X-API-Key: your-key" \
     "http://api.domainintelscanner.com:5000/api/v1/dns?domain=example.com"
```

### MX Records

**GET** `/api/v1/mx?domain={domain}`

Mail server configuration analysis.

**Response Data:**
- MX records with preferences
- Mail server hostnames
- Priority ordering

### SPF Records

**GET** `/api/v1/spf?domain={domain}`

SPF (Sender Policy Framework) analysis with enhanced insights.

**Response Data:**
- SPF record content
- Policy analysis
- DNS lookup count (with 10-lookup limit tracking)
- Security recommendations

### DKIM Analysis

**GET** `/api/v1/dkim?domain={domain}`

DKIM selector discovery and validation.

**Parameters:**
- `domain` (required): The domain to analyze
- `selectors` (optional): Comma-separated list of specific selectors to check

**Example:**
```bash
curl -H "X-API-Key: your-key" \
     "http://api.domainintelscanner.com:5000/api/v1/dkim?domain=example.com&selectors=default,google,microsoft"
```

**Response Data:**
- Found DKIM selectors
- Public key information
- Key strength analysis

### DMARC Policy

**GET** `/api/v1/dmarc?domain={domain}`

DMARC policy analysis and recommendations.

**Response Data:**
- DMARC record content
- Policy settings (p=, sp=, etc.)
- Reporting configuration
- Alignment settings

### SSL/TLS Information

**GET** `/api/v1/ssl?domain={domain}`

SSL certificate and TLS configuration analysis.

**Response Data:**
- Certificate details
- Validity dates
- Certificate chain
- TLS version support
- Security grade

### WHOIS Information

**GET** `/api/v1/whois?domain={domain}`

Domain registration and ownership information.

**Response Data:**
- Registrar information
- Registration dates
- Contact information (if not privacy-protected)
- Nameserver details
- Domain status

### BIMI Records

**GET** `/api/v1/bimi?domain={domain}`

BIMI (Brand Indicators for Message Identification) configuration check.

**Response Data:**
- BIMI record presence
- Logo URL validation
- VMC (Verified Mark Certificate) information

### Comprehensive Scan

**GET** `/api/v1/scan?domain={domain}`

Runs all available checks in a single request.

**Response Data:**
```json
{
  "status": "success",
  "timestamp": "2025-06-13T14:30:00.000Z",
  "domain": "example.com",
  "endpoint": "scan",
  "data": {
    "scan_id": "unique-scan-identifier",
    "checks": {
      "dns": { /* DNS analysis results */ },
      "mx": { /* MX analysis results */ },
      "spf": { /* SPF analysis results */ },
      "dkim": { /* DKIM analysis results */ },
      "dmarc": { /* DMARC analysis results */ },
      "ssl": { /* SSL analysis results */ },
      "whois": { /* WHOIS analysis results */ },
      "bimi": { /* BIMI analysis results */ }
    },
    "summary": {
      "total_checks": 8,
      "complete_checks": 8,
      "success_rate": "100.0%"
    },
    "errors": []
  }
}
```

**Alternative Endpoint:** `/api/v1/all` (alias for `/api/v1/scan`)

## Error Handling

### Common Error Codes

- **400 Bad Request:** Invalid domain format or missing parameters
- **401 Unauthorized:** Missing or invalid API key
- **429 Too Many Requests:** Rate limit exceeded
- **500 Internal Server Error:** Server-side processing error

### Domain Validation

Domains must match the pattern: `^[a-z0-9.-]+\.[a-z]{2,}$`

**Invalid Domain Examples:**
- `invalid-domain` (no TLD)
- `http://example.com` (includes protocol)
- `example.com/path` (includes path)

## Usage Examples

### Basic Domain Analysis

```bash
# Get DNS information
curl -H "X-API-Key: your-key" \
     "http://api.domainintelscanner.com:5000/api/v1/dns?domain=google.com"

# Get email security configuration
curl -H "X-API-Key: your-key" \
     "http://api.domainintelscanner.com:5000/api/v1/spf?domain=google.com"
```

### Comprehensive Analysis

```bash
# Full domain scan
curl -H "X-API-Key: your-key" \
     "http://api.domainintelscanner.com:5000/api/v1/scan?domain=google.com" | jq
```

### Pretty JSON Output

Use `jq` for formatted JSON output:

```bash
curl -H "X-API-Key: your-key" \
     "http://api.domainintelscanner.com:5000/api/v1/dns?domain=example.com" | jq
```

## Security Features

### Data Cleaning
- Binary string representations are automatically cleaned
- Internal error messages are filtered for security
- Sensitive debugging information is not exposed

### Input Validation
- Domain format validation
- Parameter sanitization
- Request size limits

### Logging
- All API requests are logged
- Failed authentication attempts are tracked
- Error conditions are monitored

## Support

For API key requests or technical support, contact the API administrators.

**API Version:** 1.0  
**Last Updated:** June 2025
