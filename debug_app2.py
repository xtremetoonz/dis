from flask import Flask, jsonify, request
import os
from api_security import ApiSecurity

app = Flask(__name__)

# Debug: Print the EXACT environment variable
print("=== DEBUG: Exact Environment Variable ===")
api_key_var = os.environ.get('API_KEY_PRODUCTION_CLIENT', 'NOT_SET')
print(f"API_KEY_PRODUCTION_CLIENT={api_key_var}")

# Parse it manually
if api_key_var != 'NOT_SET':
    parts = api_key_var.split(':')
    print(f"DEBUG: Split into {len(parts)} parts:")
    for i, part in enumerate(parts):
        print(f"  Part {i}: {part}")
    
    if len(parts) >= 4:
        actual_api_key = parts[0]
        print(f"DEBUG: The actual API key to use is: {actual_api_key}")

# Load API keys the same way the original app does
api_keys = {}
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
                print(f"DEBUG: Added to api_keys dictionary: key='{key}' name='{client_name}'")
        except Exception as e:
            print(f"DEBUG: Error parsing {env_var}: {e}")

print(f"DEBUG: Final api_keys dictionary keys: {list(api_keys.keys())}")

# Store in config
app.config['API_KEYS'] = api_keys

# Initialize security
api_security = ApiSecurity()
api_security.init_app(app)

@app.route('/debug')
def debug_keys():
    return jsonify({
        "env_var": os.environ.get('API_KEY_PRODUCTION_CLIENT', 'NOT_SET'),
        "loaded_keys": list(app.config.get('API_KEYS', {}).keys()),
        "total_keys": len(app.config.get('API_KEYS', {}))
    })

@app.route('/api/v1/auth/verify')
@api_security.require_api_key
def verify_auth():
    return jsonify({
        "status": "success",
        "authenticated": True,
        "client_id": request.client_id,
        "client_name": request.client_name
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
