from flask import Flask, Blueprint, current_app
from .api_security import ApiSecurity
import os

# Create the security module
api_security = ApiSecurity()

def init_security(app):
    """
    Initialize API security for the application
    
    Args:
        app: Flask application instance
    """
    # Load API keys from environment or config
    api_keys = {}
    
    # Method 1: Load from environment variables
    # Format: API_KEY_NAME=key:client_id:client_name:secret_key
    for env_var, value in os.environ.items():
        if env_var.startswith('API_KEY_'):
            try:
                parts = value.split(':')
                if len(parts) >= 4:
                    key, client_id, client_name, secret_key = parts[:4]
                    api_keys[key] = {
                        'id': client_id,
                        'name': client_name,
                        'secret_key': secret_key
                    }
            except Exception as e:
                app.logger.error(f"Error parsing API key from environment: {e}")
    
    # Method 2: Load from config file (if available)
    config_keys = app.config.get('API_KEYS', {})
    api_keys.update(config_keys)
    
    # If no keys defined, create a development key if in debug mode
    if not api_keys and app.debug:
        app.logger.warning("No API keys defined. Creating a development key.")
        dev_credentials = api_security.generate_client_credentials("development")
        api_keys[dev_credentials["api_key"]] = {
            'id': dev_credentials["client_id"],
            'name': dev_credentials["client_name"],
            'secret_key': dev_credentials["secret_key"]
        }
        app.logger.info(f"Development API Key: {dev_credentials['api_key']}")
        app.logger.info(f"Development Secret Key: {dev_credentials['secret_key']}")
    
    # Store the keys in config
    app.config['API_KEYS'] = api_keys
    
    # Initialize security with the app
    api_security.init_app(app)
    
    # Log the number of loaded keys
    app.logger.info(f"Loaded {len(api_keys)} API keys")

def secure_routes(blueprint):
    """
    Apply API key security to all routes in a blueprint
    
    Args:
        blueprint: Flask Blueprint to secure
    """
    for endpoint, view_func in blueprint.deferred_functions:
        # Wrap the view function with the api_key requirement
        if hasattr(view_func, 'view_class'):
            # Class-based views
            for method in view_func.view_class.methods:
                if method in view_func.view_class.__dict__:
                    view_func.view_class.__dict__[method] = api_security.require_api_key(
                        view_func.view_class.__dict__[method]
                    )
        else:
            # Function-based views
            blueprint.view_functions[endpoint] = api_security.require_api_key(view_func)
    
    return blueprint

def generate_api_client(name):
    """
    Generate new API client credentials and print them.
    Useful for development and adding new clients.
    
    Args:
        name: Client name
    """
    credentials = api_security.generate_client_credentials(name)
    
    print("\n=== New API Client Credentials ===")
    print(f"Client Name: {credentials['client_name']}")
    print(f"Client ID: {credentials['client_id']}")
    print(f"API Key: {credentials['api_key']}")
    print(f"Secret Key: {credentials['secret_key']}")
    print("===================================")
    print("\nEnvironment Variable Format:")
    print(f"API_KEY_{name.upper()}={credentials['api_key']}:{credentials['client_id']}:{credentials['client_name']}:{credentials['secret_key']}")
    print("\nTo use, add the X-API-Key header to your requests with the API Key value.")
    
    return credentials
