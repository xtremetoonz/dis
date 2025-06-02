#!/usr/bin/env python3
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api_security import ApiSecurity

def create_api_client(name):
    """Generate API client credentials"""
    api_security = ApiSecurity()
    credentials = api_security.generate_client_credentials(name)
    
    print("\n=== New API Client Credentials ===")
    print(f"Client Name: {credentials['client_name']}")
    print(f"Client ID: {credentials['client_id']}")
    print(f"API Key: {credentials['api_key']}")
    print(f"Secret Key: {credentials['secret_key']}")
    print("===================================")
    print("\nEnvironment Variable Format:")
    print(f"API_KEY_{name.upper()}={credentials['api_key']}:{credentials['client_id']}:{credentials['client_name']}:{credentials['secret_key']}")
    print("\nTo use this API key, clients should include the following header:")
    print(f"X-API-Key: {credentials['api_key']}")
    
    return credentials

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage_api.py CLIENT_NAME")
        print("Example: python manage_api.py my_client")
        sys.exit(1)
    
    client_name = sys.argv[1]
    create_api_client(client_name)
