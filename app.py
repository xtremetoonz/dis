from dotenv import load_dotenv
import os
from flask import Flask, Blueprint, jsonify, request
from flask_cors import CORS
import sys
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
import uuid

# Load environment variables from .env file
load_dotenv()

# Import utility modules - adjust these imports to match your project structure
# Use relative imports or absolute imports based on your project layout
try:
    # Try your existing error handling module first
    from errors import register_error_handlers, APIError
except ImportError:
    # Fallback - your existing errors module might be at a different path
    try:
        from backend.modules.errors import register_error_handlers, APIError
    except ImportError:
        # If we can't find it, use a simple version
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

# Import API security components - create these files in your project structure
from api_security import ApiSecurity

# Create the security module
api_security = None

def get_api_security():
    """Get the initialized API security instance"""
    global api_security
    return api_security

def init_security(app):
    """
    Initialize API security for the application
    
    Args:
        app: Flask application instance
    """
    global api_security
    
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
                    app.logger.info(f"✅ Loaded API key for {client_name}")
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
    
    # Store the keys in config
    app.config['API_KEYS'] = api_keys
    
    if api_security is None:
        api_security = ApiSecurity()
    api_security.init_app(app)

    # Log the number of loaded keys
    app.logger.info(f"Loaded {len(api_keys)} API keys")
    
    # Debug: Show what keys are actually stored
    for key, info in api_keys.items():
        app.logger.info(f"Available API key: {key[:8]}... -> {info['name']}")

# Simplified limiter implementation
limiter = None
def configure_limiter(app):
    """
    Configure rate limiting for the application
    
    Args:
        app: Flask application instance
    """
    try:
        # Try to import flask-limiter
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        
        # Create a new limiter instance
        global limiter
        limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://",
        )
        
        # Log that it was configured successfully
        app.logger.info("Rate limiter configured")
        
        # Register error handler for rate limit exceeded
        @app.errorhandler(429)
        def ratelimit_handler(e):
            app.logger.warning(f"Rate limit exceeded: {e.description}")
            return {
                "status": "error",
                "message": "Rate limit exceeded",
                "details": e.description
            }, 429
    except ImportError:
        # Flask-Limiter might not be installed, just log a warning
        app.logger.warning("Flask-Limiter not installed, rate limiting disabled")

def configure_logging(app):
    """
    Configure application logging
    
    Args:
        app: Flask application instance
        
    Returns:
        Logger instance
    """
    # Get log level from config or env
    log_level_name = app.config.get('LOG_LEVEL', 'INFO')
    log_level = getattr(logging, log_level_name.upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    
    # Configure Flask logger
    app.logger.setLevel(log_level)
    
    # Ensure all Flask's loggers are properly set
    for logger in [
        logging.getLogger('werkzeug'),
        logging.getLogger('flask'),
    ]:
        logger.setLevel(log_level)
        
    return app.logger

# Import your routes
# Adapt this import to match your existing routes
try:
    from backend.api.routes import api_bp
except ImportError as e:
    # Create a minimal blueprint if your routes are elsewhere
    api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

    @api_bp.route('/health')
    def api_health():
        return jsonify({"status": "ok"})

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
    
    # Basic configuration - adjust for your project structure
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
        app.logger.warning("Config module not found, using default configuration")
    
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
    
    # Add health check endpoint
    @app.route('/health')
    @api_security.require_api_key
    def health_check():
        return jsonify({
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "version": app.config.get('VERSION', '1.0.0'),
            "environment": app.config.get('ENV', 'production')
        })
    
    # Add API key info endpoint (protected)
    @app.route('/api/v1/auth/verify', methods=['GET'])
    @api_security.require_api_key
    def verify_auth():
        return jsonify({
            "status": "success",
            "authenticated": True,
            "client_id": request.client_id,
            "client_name": request.client_name,
            "message": f"Authentication successful for {request.client_name}"
        })
    
    # Add startup log entry
    logger.info(f"Application started in {app.config.get('ENV', 'production')} mode")
    
    return app

# For directly running the application
if __name__ == '__main__':
    # Create the application
    app = create_app()
   
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    app.run(host='0.0.0.0', port=port, debug=app.config.get('DEBUG', False))

# Add this for Gunicorn - create app at module level
app = create_app()
