from flask import jsonify
import logging

# Configure module logger
logger = logging.getLogger(__name__)

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

class BadRequestError(APIError):
    """Exception raised for invalid request parameters"""
    status_code = 400
    
class NotFoundError(APIError):
    """Exception raised for resource not found"""
    status_code = 404
    
class ServerError(APIError):
    """Exception raised for server-side errors"""
    status_code = 500
    
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
        logger.error(f"Server error: {str(error)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        logger.error(f"Unexpected error: {str(error)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred'
        }), 500
