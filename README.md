# Domain Intel Scanner (DIS)

A comprehensive DNS and domain security scanning tool that provides raw data through modular API endpoints.

## Overview

Domain Intel Scanner (DIS) is a DNS, WHOIS, and email-related security scanning tool that:

- Provides modular API endpoints for different security checks
- Returns raw data without analysis, enabling flexible frontend implementation
- Supports comprehensive domain security scanning
- Uses SOA nameservers to avoid cache for relevant DNS queries
- Follows modular development principles for maintainability

## Key Features

- **DNS Checks**: A, AAAA, NS, MX, TXT, SOA, CAA records
- **WHOIS Information**: Registration, expiration, registrar details
- **Email Security**: SPF, DKIM, DMARC configurations
- **TLS Security**: MTA-STS, TLS-RPT, SSL/TLS configuration
- **Certificate Checks**: CAA records, certificate details, CT logs

## Project Structure

The project follows a modular architecture:

- `backend/modules/`: Core functionality modules for different check types
- `backend/api/`: API routes and validation
- `backend/utils/`: Shared utility functions
- `tests/`: Unit and integration tests

## Installation

### Prerequisites

- Python 3.10+
- pip
- virtualenv (recommended)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/domain-intel-scanner.git
cd domain-intel-scanner
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create a `.env` file:

```bash
cp .env.example .env
```

5. Edit the `.env` file with your configuration:

```
# API Keys
CERTSPOTTER_API_KEY=your_key_here

# Application Settings
DNS_TIMEOUT=5.0
HTTP_TIMEOUT=10.0
LOG_LEVEL=INFO
FLASK_ENV=development  # Use 'production' for production
```

## Usage

### Starting the API Server

```bash
python app.py
```

The API will be available at http://localhost:5000/

### API Endpoints

- `GET /api/v1/dns?domain=example.com` - Basic DNS records
- `GET /api/v1/mx?domain=example.com` - MX records
- `GET /api/v1/spf?domain=example.com` - SPF record
- `GET /api/v1/dkim?domain=example.com` - DKIM selectors and records
- `GET /api/v1/dmarc?domain=example.com` - DMARC policy
- `GET /api/v1/ssl?domain=example.com` - SSL/TLS configuration
- `GET /api/v1/whois?domain=example.com` - WHOIS information

### Example API Response

```json
{
  "status": "success",
  "domain": "example.com",
  "data": {
    "a_records": ["93.184.216.34"],
    "aaaa_records": ["2606:2800:220:1:248:1893:25c8:1946"],
    "ns_records": [
      {
        "nameserver": "a.iana-servers.net.",
        "ip_addresses": ["199.43.135.53"]
      },
      {
        "nameserver": "b.iana-servers.net.",
        "ip_addresses": ["199.43.133.53"]
      }
    ],
    "txt_records": ["v=spf1 -all"],
    "soa_record": {
      "mname": "a.iana-servers.net.",
      "rname": "nstld.iana.org.",
      "serial": 2023080123,
      "refresh": 1800,
      "retry": 900,
      "expire": 604800,
      "minimum": 86400
    },
    "errors": []
  }
}
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=backend

# Run specific test file
pytest tests/unit/test_dns.py
```

### Code Formatting

```bash
# Format code
black backend tests

# Sort imports
isort backend tests

# Lint code
flake8 backend tests
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
