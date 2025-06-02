Creating an API Client Authentication Example
This guide demonstrates how to create and use API client authentication with your Domain Analysis API.
1. Create a new API client
First, create a new API client using the CLI tool:
bashpython manage.py create-api-client acme_corp
This will output API credentials similar to:
=== New API Client Credentials ===
Client Name: acme_corp
Client ID: 54721e8a-ff32-43b1-a8c2-1f4a96e5d2e0
API Key: 8c48743a-1234-5678-90ab-cdef01234567
Secret Key: 97a12fc3-abcd-efgh-ijkl-mnopqrstuv12
===================================

Environment Variable Format:
API_KEY_ACME_CORP=8c48743a-1234-5678-90ab-cdef01234567:54721e8a-ff32-43b1-a8c2-1f4a96e5d2e0:acme_corp:97a12fc3-abcd-efgh-ijkl-mnopqrstuv12
2. Configure the API client
Option A: Using environment variables
Add the API client to your server's environment variables:
bashexport API_KEY_ACME_CORP=8c48743a-1234-5678-90ab-cdef01234567:54721e8a-ff32-43b1-a8c2-1f4a96e5d2e0:acme_corp:97a12fc3-abcd-efgh-ijkl-mnopqrstuv12
For persistence, add to your .env file or server environment configuration.
Option B: Adding to configuration file
Alternatively, add the client to your configuration file:
python# In config.py
class Config:
    # ... other config settings
    API_KEYS = {
        "8c48743a-1234-5678-90ab-cdef01234567": {
            "id": "54721e8a-ff32-43b1-a8c2-1f4a96e5d2e0",
            "name": "acme_corp",
            "secret_key": "97a12fc3-abcd-efgh-ijkl-mnopqrstuv12"
        }
    }
3. Test the API client authentication
Verify the API client is properly configured:
bashpython manage.py test-api-security --client acme_corp
You should see output confirming the client exists and has a valid API key.
4. Make authenticated API requests
Now you can make authenticated requests to your API:
Using curl
bashcurl -H "X-API-Key: 8c48743a-1234-5678-90ab-cdef01234567" \
     https://your-api.com/api/v1/dns?domain=example.com
Using Python requests
pythonimport requests

API_KEY = "8c48743a-1234-5678-90ab-cdef01234567"
API_URL = "https://your-api.com/api/v1"

def check_domain(domain):
    headers = {"X-API-Key": API_KEY}
    response = requests.get(
        f"{API_URL}/dns", 
        headers=headers, 
        params={"domain": domain}
    )
    return response.json()

# Example usage
result = check_domain("example.com")
print(result)
Using JavaScript/Fetch API
javascriptconst API_KEY = "8c48743a-1234-5678-90ab-cdef01234567";
const API_URL = "https://your-api.com/api/v1";

async function checkDomain(domain) {
    const response = await fetch(`${API_URL}/dns?domain=${domain}`, {
        headers: {
            "X-API-Key": API_KEY
        }
    });
    
    return await response.json();
}

// Example usage
checkDomain("example.com")
    .then(result => console.log(result))
    .catch(error => console.error("Error:", error));
5. Using advanced request signing (optional)
If you've enabled API_SIGNING_REQUIRED=True, clients will need to sign their requests:
pythonimport requests
import time
import uuid
import hmac
import hashlib

API_KEY = "8c48743a-1234-5678-90ab-cdef01234567"
SECRET_KEY = "97a12fc3-abcd-efgh-ijkl-mnopqrstuv12"
API_URL = "https://your-api.com/api/v1"

def signed_request(method, path, params=None):
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
    url = f"{API_URL}{path}"
    response = requests.request(method, url, headers=headers, params=params)
    
    return response.json()

# Example usage
result = signed_request("GET", "/dns", {"domain": "example.com"})
print(result)
6. Managing API clients
Creating additional clients
bashpython manage.py create-api-client another_client
Listing all clients
bashpython manage.py test-api-security
Revoking access
To revoke access, simply remove the API key from your environment variables or configuration file and restart the application.
Best Practices

Secure storage - Store API keys securely and never commit them to version control
Client-specific keys - Create separate API keys for each client
Key rotation - Periodically generate new API keys and phase out old ones
Monitor usage - Keep logs of API key usage to detect suspicious activity
Rate limiting - Enforce appropriate rate limits for each client
