from dotenv import load_dotenv
import os
from flask import Flask, Blueprint, jsonify, request
from flask_cors import CORS
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
import uuid

# Load environment variables from .env file
load_dotenv()

# Import utility modules
try:
    from errors import register_error_handlers, APIError
except ImportError:
    try:
        from backend.modules.errors import register_error_handlers, APIError
    except ImportError:
        # Fallback error handling
        from werkzeug.exceptions import HTTPException
        
        class APIError(Exception):
            """Base class for API errors"""
            status_code = 500
            
            def __init__(self, message, status_code=None, payload=None):
                super().__init__()
                self.message = message
                if status_code is not None:
                    self.status_code = status_code
                self.payload = payload
                
            def to_dict(self):
                rv = dict(self.payload or ())
                rv['status'] = 'error'
                rv['message'] = self.message
                return rv
        
        def register_error_handlers(app):
            """Register error handlers for the Flask app"""
            
            @app.errorhandler(APIError)
            def handle_api_error(error):
                response = jsonify(error.to_dict())
                response.status_code = error.status_code
                return response
            
            @app.errorhandler(404)
            def not_found(error):
                return jsonify({
                    'status': 'error',
                    'message': 'Resource not found'
                }), 404
            
            @app.errorhandler(500)
            def server_error(error):
                app.logger.error(f"Server error: {str(error)}")
                return jsonify({
                    'status': 'error',
                    'message': 'Internal server error'
                }), 500
            
            @app.errorhandler(Exception)
            def handle_unexpected_error(error):
                app.logger.error(f"Unexpected error: {str(error)}", exc_info=True)
                return jsonify({
                    'status': 'error',
                    'message': 'An unexpected error occurred'
                }), 500

# Import API security components
from api_security import ApiSecurity

# Global security instance
api_security = None

def load_api_keys_from_file(file_path):
    """Load API keys from a dedicated file"""
    api_keys = {}

    if not os.path.exists(file_path):
        return api_keys

    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse CLIENT_NAME=key:client_id:client_name:secret_key
                if '=' in line:
                    client_name, key_data = line.split('=', 1)
                    parts = key_data.split(':')

                    if len(parts) >= 4:
                        key, client_id, name, secret_key = parts[:4]
                        api_keys[key] = {
                            'id': client_id,
                            'name': name,
                            'secret_key': secret_key
                        }
                    else:
                        print(f"Warning: Invalid key format on line {line_num}")
    except Exception as e:
        print(f"Error loading API keys from file: {e}")

    return api_keys

def init_security(app):
    """
    Initialize API security for the application
    
    Args:
        app: Flask application instance
    """
    global api_security
    
    # Load API keys from environment or config
    api_keys = {}

        # Method 1: Load from dedicated keys file
    keys_file = os.environ.get('API_KEYS_FILE', '/srv/git/dis/api_keys.conf')
    file_keys = load_api_keys_from_file(keys_file)
    api_keys.update(file_keys)

    for key, info in file_keys.items():
        app.logger.info(f"✅ Loaded API key for {info['name']} from keys file")

    
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
                    app.logger.info(f"✅ Loaded API key for {client_name}")
            except Exception as e:
                app.logger.error(f"Error parsing API key from environment: {e}")
    
    # Method 2: Load from config file (if available)
    config_keys = app.config.get('API_KEYS', {})
    api_keys.update(config_keys)
    
    # Store the keys in config
    app.config['API_KEYS'] = api_keys
    
    # Initialize security instance
    if api_security is None:
        api_security = ApiSecurity()
    api_security.init_app(app)

    # Log the number of loaded keys
    app.logger.info(f"Loaded {len(api_keys)} API keys")
    
    # Log available keys (for debugging)
    for key, info in api_keys.items():
        app.logger.info(f"Available API key: {key[:8]}... -> {info['name']}")

def configure_limiter(app):
    """
    Configure rate limiting for the application
    
    Args:
        app: Flask application instance
    """
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        global limiter
        limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://",
        )
        
        app.logger.info("Rate limiter configured")
        
        @app.errorhandler(429)
        def ratelimit_handler(e):
            app.logger.warning(f"Rate limit exceeded: {e.description}")
            return {
                "status": "error",
                "message": "Rate limit exceeded",
                "details": e.description
            }, 429
    except ImportError:
        app.logger.warning("Flask-Limiter not installed, rate limiting disabled")

def configure_logging(app):
    """
    Configure application logging
    
    Args:
        app: Flask application instance
        
    Returns:
        Logger instance
    """
    log_level_name = app.config.get('LOG_LEVEL', 'INFO')
    log_level = getattr(logging, log_level_name.upper(), logging.INFO)
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    
    app.logger.setLevel(log_level)
    
    for logger in [
        logging.getLogger('werkzeug'),
        logging.getLogger('flask'),
    ]:
        logger.setLevel(log_level)
        
    return app.logger

# ============================================================================
# ROUTES IMPORT SECTION
# ============================================================================
try:
    from backend.api.routes import api_bp
except ImportError as e:
    # Fallback blueprint if routes import fails
    app.logger.error(f"Failed to import routes: {e}")
    api_bp = Blueprint('api', __name__, url_prefix='/api/v1')
    
    @api_bp.route('/health')
    def api_health():
        return jsonify({"status": "ok"})
# ============================================================================

def create_app(config=None):
    """
    Create and configure the Flask application
    
    Args:
        config: Configuration object or dictionary
        
    Returns:
        Flask application instance
    """
    # Create Flask app
    app = Flask(__name__)
    
    # Fix for running behind proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    
    # Basic configuration
    app.config.update({
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'dev-key'),
        'LOG_LEVEL': os.environ.get('LOG_LEVEL', 'INFO'),
        'API_SIGNING_REQUIRED': os.environ.get('API_SIGNING_REQUIRED', 'False').lower() in ('true', '1', 't'),
        'RATE_LIMIT_DEFAULT': os.environ.get('RATE_LIMIT_DEFAULT', "200 per day, 50 per hour"),
        'DEBUG': os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't'),
    })
    
    # Try loading configuration from a Config class if available
    try:
        from config import Config
        app.config.from_object(Config)
    except ImportError:
        pass  # No config module, use defaults
    
    # Apply any provided configuration override
    if config:
        if isinstance(config, dict):
            app.config.update(config)
        else:
            app.config.from_object(config)
    
    # Set up logging
    logger = configure_logging(app)
    
    # Initialize security
    init_security(app)
    
    # Configure rate limiter
    configure_limiter(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Set up CORS
    cors_origins = os.environ.get('CORS_ORIGINS', '*')
    CORS(app, resources={r"/api/*": {"origins": cors_origins.split(',')}})
    
    # Register blueprints
    app.register_blueprint(api_bp)
    
    # Add health check endpoint (NO AUTHENTICATION REQUIRED)
    @app.route('/health')
    def health_check():
        return jsonify({
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "version": app.config.get('VERSION', '1.0.0'),
            "environment": app.config.get('ENV', 'production')
        })
    
    # Add API key verification endpoint (AUTHENTICATION REQUIRED)
    @app.route('/api/v1/auth/verify', methods=['GET'])
    def verify_auth():
        # Import at runtime to avoid circular imports
        from flask import current_app
        
        # Get API key from header
        api_key = request.headers.get('X-API-Key')
        
        # Get API keys from Flask config
        api_keys = current_app.config.get('API_KEYS', {})
        
        # Check if API key is provided and valid
        if not api_key or api_key not in api_keys:
            return jsonify({
                "status": "error",
                "message": "Unauthorized - Valid API key required"
            }), 401
        
        # Get client info
        client_info = api_keys[api_key]
        
        return jsonify({
            "status": "success",
            "authenticated": True,
            "client_id": client_info.get('id'),
            "client_name": client_info.get('name'),
            "message": f"Authentication successful for {client_info.get('name')}"
        })
    
    # Add startup log entry
    logger.info(f"Application started in {app.config.get('ENV', 'production')} mode")
    
    return app

# For directly running the application
if __name__ == '__main__':
    # Create the application
    app = create_app()
  
    # ========================================================================
    # TEMPORARY DEBUG SECTION - Remove this entire block once routes are working
    print("\n=== DEBUG: REGISTERED ROUTES ===")
    for rule in app.url_map.iter_rules():
        print(f"{rule.methods} {rule.rule}")
    print("=================================\n")
    # ========================================================================

    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    app.run(host='0.0.0.0', port=port, debug=app.config.get('DEBUG', False))

# Add this for Gunicorn - create app at module level
app = create_app()
