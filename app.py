import os
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
import logging
from backend.utils.logging import configure_logging
from backend.api.limiter import configure_limiter

# Load environment variables
load_dotenv()

# Configure logging
logging_level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, logging_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def create_app(test_config=None):
    """
    Application factory function.
    
    Args:
        test_config (dict, optional): Test configuration to override defaults
        
    Returns:
        Flask: Configured Flask application
    """
    # Create Flask app
    app = Flask(__name__, instance_relative_config=True)
    
    # Enable CORS
    CORS(app)
    
    # Configure logging
    configure_logging(app, os.getenv('LOG_LEVEL', 'INFO'))

    # Load configuration
    app.config.from_mapping(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev"),
        API_VERSION="v1",
        DNS_TIMEOUT=float(os.getenv("DNS_TIMEOUT", "5.0")),
        HTTP_TIMEOUT=float(os.getenv("HTTP_TIMEOUT", "10.0")),
        CERT_SPOTTER_API_KEY=os.getenv("CERTSPOTTER_API_KEY", ""),
        ENVIRONMENT=os.getenv("FLASK_ENV", "production")
    )
    
    # Override config with test config if provided
    if test_config:
        app.config.update(test_config)
    
    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # Register blueprints
    from backend.api.routes import api_bp
    app.register_blueprint(api_bp)

    # configure rate limiting
    configure_limiter(app)

    # Register error handlers
    @app.errorhandler(404)
    def not_found(e):
        logger.info(f"404 error: {request.path}")
        return jsonify({
            "status": "error",
            "message": "Resource not found"
        }), 404
    
    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"500 error: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Internal server error"
        }), 500
    
    # Debug route
    @app.route('/health')
    def health_check():
        """Simple health check endpoint"""
        return jsonify({
            "status": "ok",
            "message": "API is operational"
        })
    
    logger.info(f"Application initialized in {app.config['ENVIRONMENT']} mode")
    return app

# Simple CLI for running the app directly
if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    
    app.run(host='0.0.0.0', port=port, debug=debug)
