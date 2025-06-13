"""
API Security module for handling authentication and authorization
"""

from flask import request, abort, current_app
from functools import wraps
import logging
import time
import hmac
import hashlib
import uuid

# Configure module logger - FORCE it to show
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add a console handler to make sure we see output
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class ApiSecurity:
    """
    API security module for authentication and access control.
    Provides mechanisms for API key validation, request signing, and rate limiting.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.api_keys = {}
        self.signing_required = False
        self.signature_ttl = 300  # 5 minutes
        
        if app is not None:
            self.init_app(app)
            
    def init_app(self, app):
        """Initialize the security module with the Flask app"""
        self.app = app
        
        # Load API keys from config
        self.api_keys = app.config.get('API_KEYS', {})
        self.signing_required = app.config.get('API_SIGNING_REQUIRED', False)
        self.signature_ttl = app.config.get('API_SIGNATURE_TTL', 300)  # 5 minutes
        
        # Register error handlers
        @app.errorhandler(401)
        def unauthorized(error):
            return {
                "status": "error", 
                "message": "Unauthorized - Valid API key required",
                "error": str(error)
            }, 401
            
        @app.errorhandler(403)
        def forbidden(error):
            return {
                "status": "error", 
                "message": "Forbidden - Insufficient permissions",
                "error": str(error)
            }, 403
            
        logger.info("API security initialized")
    
    def require_api_key(self, f):
        """
        Decorator that requires a valid API key for access.
        The API key must be provided in the X-API-Key header.
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
        
            # DEBUG: Log what we're checking
            logger.info(f"🔍 Checking API key: {api_key[:8] if api_key else 'None'}...")
            logger.info(f"🔍 Available keys: {list(self.api_keys.keys())}")
            logger.info(f"🔍 Number of keys in memory: {len(self.api_keys)}")

            # Check if API key is provided
            if not api_key:
                logger.warning("API request without API key")
                abort(401, "API key required")
            
                   # Check if API key is valid
            if api_key not in self.api_keys:
                logger.warning(f"Invalid API key: {api_key[:8]}...")
                logger.warning(f"Available keys: {[k[:8] + '...' for k in self.api_keys.keys()]}")
                abort(401, "Invalid API key")

            # Add client info to request context
            client_info = self.api_keys[api_key]
            request.client_id = client_info.get('id')
            request.client_name = client_info.get('name')
            
            # Optionally check for request signing
            if self.signing_required:
                self._validate_signature(api_key, client_info)
            
            # Log the authenticated request
            logger.info(f"API request authenticated for client: {request.client_name}")
            
            return f(*args, **kwargs)
        return decorated
    
    def _validate_signature(self, api_key, client_info):
        """
        Validates the request signature for authenticated requests.
        This provides an additional layer of security beyond API keys.
        """
        # Get signature details from headers
        signature = request.headers.get('X-API-Signature')
        timestamp = request.headers.get('X-API-Timestamp')
        nonce = request.headers.get('X-API-Nonce')
        
        # Check if all required headers are present
        if not all([signature, timestamp, nonce]):
            logger.warning("Missing signature headers")
            abort(401, "Request signature required")
        
        # Check timestamp freshness (prevent replay attacks)
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            if abs(current_time - request_time) > self.signature_ttl:
                logger.warning(f"Request timestamp expired: {request_time}")
                abort(401, "Request timestamp expired")
        except ValueError:
            logger.warning(f"Invalid timestamp: {timestamp}")
            abort(401, "Invalid timestamp format")
        
        # Get the client's secret key
        secret_key = client_info.get('secret_key')
        if not secret_key:
            logger.error(f"No secret key configured for API key: {api_key[:8]}...")
            abort(500, "API configuration error")
        
        # Recreate the signature
        # The signature is a HMAC of the concatenated timestamp, nonce, API key,
        # request method, path, and sorted query string
        path = request.path
        method = request.method
        
        # Sort query parameters for consistent signatures
        query_items = sorted(request.args.items())
        query_string = '&'.join(f"{k}={v}" for k, v in query_items)
        
        # Create the message to sign
        msg = f"{timestamp}{nonce}{api_key}{method}{path}{query_string}"
        
        # Calculate expected signature
        expected_signature = hmac.new(
            secret_key.encode(), 
            msg.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures (constant time comparison to prevent timing attacks)
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("Invalid request signature")
            abort(401, "Invalid request signature")
            
    def generate_client_credentials(self, client_name):
        """
        Generate new API credentials for a client.
        Returns API key, secret key, and client ID.
        """
        client_id = str(uuid.uuid4())
        api_key = str(uuid.uuid4())
        secret_key = str(uuid.uuid4())
        
        credentials = {
            "client_id": client_id,
            "client_name": client_name,
            "api_key": api_key,
            "secret_key": secret_key,
            "created_at": int(time.time())
        }
        
        return credentials
