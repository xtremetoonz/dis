from flask import Flask, Blueprint, jsonify, request
from flask_cors import CORS
import re
import logging
from werkzeug.exceptions import BadRequest

# Import module functions (we'll create these soon)
from backend.modules.dns import get_dns_records
from backend.modules.mx import get_mx_records
from backend.modules.spf import get_spf_record
from backend.modules.dkim import check_dkim_selectors
from backend.modules.dmarc import get_dmarc_policy
from backend.modules.ssl import get_ssl_info
from backend.modules.whois import get_whois_info

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api/v1')

# Domain validation regex pattern
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$',
    re.IGNORECASE
)

def validate_domain(domain):
    """Validates domain format"""
    if not domain or not isinstance(domain, str):
        return False
    return bool(DOMAIN_PATTERN.match(domain))

def get_domain_param():
    """Extract and validate domain from request"""
    domain = request.args.get('domain')
    if not domain:
        raise BadRequest("Missing domain parameter")
    if not validate_domain(domain):
        raise BadRequest("Invalid domain format")
    return domain

@api_bp.route('/dns', methods=['GET'])
def dns_endpoint():
    """Get DNS records for a domain"""
    domain = get_domain_param()
    logger.info(f"DNS check requested for domain: {domain}")
    
    try:
        results = get_dns_records(domain)
        return jsonify({
            "status": "success",
            "domain": domain,
            "data": results
        })
    except Exception as e:
        logger.error(f"Error in DNS check for {domain}: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "domain": domain,
            "message": "Failed to retrieve DNS records"
        }), 500

@api_bp.route('/mx', methods=['GET'])
def mx_endpoint():
    """Get MX records for a domain"""
    domain = get_domain_param()
    logger.info(f"MX check requested for domain: {domain}")
    
    try:
        results = get_mx_records(domain)
        return jsonify({
            "status": "success",
            "domain": domain,
            "data": results
        })
    except Exception as e:
        logger.error(f"Error in MX check for {domain}: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "domain": domain,
            "message": "Failed to retrieve MX records"
        }), 500

@api_bp.route('/spf', methods=['GET'])
def spf_endpoint():
    """Get SPF record for a domain"""
    domain = get_domain_param()
    logger.info(f"SPF check requested for domain: {domain}")
    
    try:
        results = get_spf_record(domain)
        return jsonify({
            "status": "success",
            "domain": domain,
            "data": results
        })
    except Exception as e:
        logger.error(f"Error in SPF check for {domain}: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "domain": domain,
            "message": "Failed to retrieve SPF record"
        }), 500

@api_bp.route('/dkim', methods=['GET'])
def dkim_endpoint():
    """Check DKIM selectors for a domain"""
    domain = get_domain_param()
    
    # Optional parameter for specific selectors
    selectors = request.args.get('selectors')
    selector_list = selectors.split(',') if selectors else None
    
    logger.info(f"DKIM check requested for domain: {domain}, selectors: {selector_list}")
    
    try:
        results = check_dkim_selectors(domain, selector_list)
        return jsonify({
            "status": "success",
            "domain": domain,
            "data": results
        })
    except Exception as e:
        logger.error(f"Error in DKIM check for {domain}: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "domain": domain,
            "message": "Failed to check DKIM selectors"
        }), 500

@api_bp.route('/dmarc', methods=['GET'])
def dmarc_endpoint():
    """Get DMARC policy for a domain"""
    domain = get_domain_param()
    logger.info(f"DMARC check requested for domain: {domain}")
    
    try:
        results = get_dmarc_policy(domain)
        return jsonify({
            "status": "success",
            "domain": domain,
            "data": results
        })
    except Exception as e:
        logger.error(f"Error in DMARC check for {domain}: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "domain": domain,
            "message": "Failed to retrieve DMARC policy"
        }), 500

@api_bp.route('/ssl', methods=['GET'])
def ssl_endpoint():
    """Get SSL/TLS information for a domain"""
    domain = get_domain_param()
    logger.info(f"SSL check requested for domain: {domain}")
    
    try:
        results = get_ssl_info(domain)
        return jsonify({
            "status": "success",
            "domain": domain,
            "data": results
        })
    except Exception as e:
        logger.error(f"Error in SSL check for {domain}: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "domain": domain,
            "message": "Failed to retrieve SSL information"
        }), 500

@api_bp.route('/whois', methods=['GET'])
def whois_endpoint():
    """Get WHOIS information for a domain"""
    domain = get_domain_param()
    logger.info(f"WHOIS check requested for domain: {domain}")
    
    try:
        results = get_whois_info(domain)
        return jsonify({
            "status": "success",
            "domain": domain,
            "data": results
        })
    except Exception as e:
        logger.error(f"Error in WHOIS check for {domain}: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error",
            "domain": domain,
            "message": "Failed to retrieve WHOIS information"
        }), 500

# Error handlers
@api_bp.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify({
        "status": "error",
        "message": str(e)
    }), 400

@api_bp.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return jsonify({
        "status": "error",
        "message": "An unexpected error occurred"
    }), 500

# Create and configure app
def create_app():
    app = Flask(__name__)
    CORS(app)
    
    # Register blueprint
    app.register_blueprint(api_bp)
    
    # Generic error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Endpoint not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"status": "error", "message": "Method not allowed"}), 405
    
    return app

# Run app if executed directly
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
