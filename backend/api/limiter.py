from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

logger = logging.getLogger(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

def configure_limiter(app):
    """Configure the rate limiter for the application"""
    limiter.init_app(app)
    logger.info("Rate limiter configured")
    
    # Log when rate limit is exceeded
    @app.errorhandler(429)
    def ratelimit_handler(e):
        logger.warning(f"Rate limit exceeded: {e.description}")
        return {
            "status": "error",
            "message": "Rate limit exceeded",
            "details": e.description
        }, 429
