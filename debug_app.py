from flask import Flask, jsonify, request
import os
from api_security import ApiSecurity

app = Flask(__name__)

# Debug: Print all environment variables starting with API_KEY
print("=== DEBUG: Environment Variables ===")
for key, value in os.environ.items():
    if key.startswith('API_KEY'):
        print(f"{key}={value}")

# Load API keys from environment
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
                print(f"DEBUG: Loaded API key: {key[:8]}... for client: {client_name}")
        except Exception as e:
            print(f"DEBUG: Error parsing {env_var}: {e}")

print(f"DEBUG: Total API keys loaded: {len(api_keys)}")
print(f"DEBUG: API keys: {list(api_keys.keys())}")

# Store in config
app.config['API_KEYS'] = api_keys

# Initialize security
api_security = ApiSecurity()
api_security.init_app(app)

@app.route('/health')
def health():
    return jsonify({"status": "ok", "loaded_keys": len(app.config.get('API_KEYS', {}))})

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
