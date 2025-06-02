API Security Implementation Guide
This guide explains how to use the API security features implemented in this application. The security system supports API keys, request signing, and rate limiting to ensure that your API is secure while remaining accessible to authorized clients.
API Security Overview
The security system provides:

API Key Authentication - Each client gets a unique API key
Request Signing (optional) - For high-security applications
Rate Limiting - Prevents abuse of the API
Secure Credential Management - Easy to generate and manage client credentials

Setting Up Security
Step 1: Initialize Security
The security system is automatically initialized when the application starts. The init_security function in backend/utils/security.py loads API keys from:

Environment variables (format: API_KEY_NAME=key:client_id:client_name:secret_key)
Application configuration
Generates a development key if in debug mode and no keys are configured

Step 2: Create API Clients
Generate new API client credentials using the CLI:
bash# Using Flask CLI
flask create-api-client CLIENT_NAME

# Using manage.py directly
python manage.py create-api-client CLIENT_NAME
This will output the client's API key, secret key, and other details. Store these securely.
Step 3: Apply Security to Routes
The API routes are automatically secured by the api_security.require_api_key decorator. This can be applied:

To individual routes:
python@app.route('/api/resource')
@api_security.require_api_key
def protected_resource():
    # Only accessible with valid API key
    return {"status": "success"}

To all routes in a blueprint:
python# Secure all routes in the blueprint
secure_routes(api_bp)


Using API Keys
Client Implementation
Clients must include their API key in every request:
GET /api/v1/dns?domain=example.com HTTP/1.1
Host: your-api-server.com
X-API-Key: your-api-key-here
Python Client Example
pythonimport requests

API_KEY = "your-api-key-here"
BASE_URL = "https://your-api-server.com/api/v1"

def check_domain(domain):
    headers = {
        "X-API-Key": API_KEY
    }
    
    response = requests.get(
        f"{BASE_URL}/dns",
        headers=headers,
        params={"domain": domain}
    )
    
    return response.json()
Request Signing (Advanced)
For applications requiring higher security, enable request signing:

Set API_SIGNING_REQUIRED=True in your environment or config
Clients must include these additional headers:

X-API-Timestamp: Current Unix timestamp
X-API-Nonce: Random string to prevent replay attacks
X-API-Signature: HMAC-SHA256 signature of request details



Python Signed Request Example
pythonimport requests
import time
import uuid
import hmac
import hashlib

API_KEY = "your-api-key-here"
SECRET_KEY = "your-secret-key-here"
BASE_URL = "https://your-api-server.com/api/v1"

def signed_request(method, path, params=None):
    # Create signature components
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    
    # Build query string
    query_items = sorted((params or {}).items())
    query_string = '&'.join(f"{k}={v}" for k, v in query_items)
    
    # Create message to sign
    msg = f"{timestamp}{nonce}{API_KEY}{method}{path}{query_string}"
    
    # Calculate signature
    signature = hmac.new(
        SECRET_KEY.encode(),
        msg.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Prepare headers
    headers = {
        "X-API-Key": API_KEY,
        "X-API-Timestamp": timestamp,
        "X-API-Nonce": nonce,
        "X-API-Signature": signature,
    }
    
    # Make request
    url = f"{BASE_URL}{path}"
    response = requests.request(method, url, headers=headers, params=params)
    
    return response.json()

# Example usage
def check_domain(domain):
    return signed_request("GET", "/dns", {"domain": domain})
Testing and Management
Use the built-in commands to manage your API security:
bash# Test API security configuration
flask test-api-security

# Test a specific API key
flask test-api-security --api-key YOUR_KEY

# Check if a client has valid credentials
flask test-api-security --client CLIENT_NAME

# Reset rate limiting data
flask purge-rate-limits
Security Best Practices

Store API keys securely - Never commit API keys to version control
Use HTTPS - Always use HTTPS in production
Rotate keys regularly - Generate new keys periodically
Monitor usage - Keep an eye on API usage patterns for suspicious activity
Implement IP filtering - Consider additional IP filtering for sensitive operations

Troubleshooting
Common issues:

401 Unauthorized: The API key is missing or invalid
429 Too Many Requests: The client has exceeded rate limits
400 Bad Request: Request signature is missing required components
403 Forbidden: API key is valid but doesn't have permission for the requested resource
