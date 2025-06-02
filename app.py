from flask import Flask, Blueprint, jsonify, request
from flask_cors import CORS
import os
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
import uuid

# Import utility modules
from backend.utils.errors import register_error_handlers, APIError
from backend.utils.limiter import limiter, configure_limiter
from backend.utils.logging import configure_logging
from backend.utils.security import init_security, api_security

# Import route modules
from backend.routes import api_bp

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
    
    # Load configuration
    app.config.from_object('backend.config.Config')
    
    # Override with environment variable config
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', app.config.get('SECRET_KEY', 'dev-key'))
    app.config['LOG_LEVEL'] = os.environ.get('LOG_LEVEL', app.config.get('LOG_LEVEL', 'INFO'))
    app.config['API_SIGNING_REQUIRED'] = os.environ.get('API_SIGNING_REQUIRED', 'False').lower() in ('true', '1', 't')
    app.config['RATE_LIMIT_DEFAULT'] = os.environ.get('RATE_LIMIT_DEFAULT', "200 per day, 50 per hour")
    
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
    
    # Log the application configuration (excluding sensitive values)
    safe_config = {
        key: value for key, value in app.config.items() 
        if not any(sensitive in key.lower() for sensitive in ['key', 'password', 'secret', 'token'])
    }
    logger.debug(f"Application configuration: {safe_config}")
    
    return app

def init_db(app):
    """
    Initialize database for the application
    This is a placeholder for future database integration
    
    Args:
        app: Flask application instance
    """
    # This function would initialize database connections, 
    # create tables if needed, and perform other database setup
    pass

# Request ID middleware for tracking requests
class RequestIDMiddleware:
    """Middleware that assigns a unique ID to each request"""
    
    def __init__(self, app):
        self.app = app
        
    def __call__(self, environ, start_response):
        request_id = str(uuid.uuid4())
        environ['REQUEST_ID'] = request_id
        
        def custom_start_response(status, headers, exc_info=None):
            headers.append(('X-Request-ID', request_id))
            return start_response(status, headers, exc_info)
            
        return self.app(environ, custom_start_response)

# For directly running the application
if __name__ == '__main__':
    # Create the application
    app = create_app()
    
    # Add the request ID middleware
    app.wsgi_app = RequestIDMiddleware(app.wsgi_app)
    
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    app.run(host='0.0.0.0', port=port, debug=app.config.get('DEBUG', False))
