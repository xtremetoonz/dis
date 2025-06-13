from flask import Blueprint, jsonify, request, current_app
import re
import logging
import json
from datetime import datetime
import uuid
from werkzeug.exceptions import BadRequest
from functools import wraps

# Import module functions 
from backend.modules.dns import get_dns_records
from backend.modules.mx import get_mx_records
from backend.modules.spf import get_spf_record, analyze_spf_policy
from backend.modules.dkim import check_dkim_selectors
from backend.modules.dmarc import get_dmarc_policy
from backend.modules.ssl import get_ssl_info
from backend.modules.whois import get_whois_info
from backend.modules.bimi import check_bimi

# Configure logging
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

def clean_json_data(data):
    """
    Recursively clean JSON data to fix common formatting issues
    """
    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            cleaned[key] = clean_json_data(value)
        return cleaned
    elif isinstance(data, list):
        return [clean_json_data(item) for item in data]
    elif isinstance(data, str):
        # Fix binary string representations
        if data.startswith("b'") and data.endswith("'"):
            return data[2:-1]  # Remove b' and '
        return data
    elif isinstance(data, bytes):
        # Convert bytes to string
        return data.decode('utf-8', errors='ignore')
    else:
        return data

def format_api_response(status, data=None, domain=None, endpoint=None, errors=None):
    """
    Create a standardized API response format
    """
    response = {
        "status": status,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if domain:
        response["domain"] = domain
    
    if endpoint:
        response["endpoint"] = endpoint
    
    if data is not None:
        # Clean the data before adding to response
        cleaned_data = clean_json_data(data)
        response["data"] = cleaned_data
    
    if errors:
        # Filter out internal errors and make them user-friendly
        filtered_errors = []
        for error in errors if isinstance(errors, list) else [errors]:
            error_str = str(error)
            # Don't expose internal Python errors
            if "module" in error_str and "has no attribute" in error_str:
                filtered_errors.append("Service temporarily unavailable")
            elif "Error checking" in error_str:
                filtered_errors.append("Unable to complete security check")
            else:
                filtered_errors.append(error_str)
        
        if filtered_errors:
            response["errors"] = filtered_errors
    
    return response

def format_error_response(message, status_code=500, domain=None):
    """
    Create a standardized error response
    """
    response = format_api_response(
        status="error",
        data={"message": message},
        domain=domain
    )
    return jsonify(response), status_code

def require_api_key(f):
    """
    Simple authentication decorator that gets api_security at runtime
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        
        # Get API key from header
        api_key = request.headers.get('X-API-Key')
        
        # Get API keys from Flask config
        api_keys = current_app.config.get('API_KEYS', {})
        
        # Check if API key is provided
        if not api_key:
            logger.warning("API request without API key")
            return jsonify({
                "status": "error", 
                "message": "Unauthorized - Valid API key required"
            }), 401
        
        # Check if API key is valid
        if api_key not in api_keys:
            logger.warning(f"Invalid API key attempt: {api_key[:8]}...")
            return jsonify({
                "status": "error", 
                "message": "Unauthorized - Valid API key required"
            }), 401
        
        # Add client info to request context
        client_info = api_keys[api_key]
        request.client_id = client_info.get('id')
        request.client_name = client_info.get('name')
        
        logger.info(f"API request authenticated for client: {request.client_name}")
        
        return f(*args, **kwargs)
    return decorated_function

def format_response(endpoint_name):
    """
    Decorator to automatically format responses for all endpoints
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                domain = request.args.get('domain')
                result = f(*args, **kwargs)
                
                # If the function already returned a formatted response, pass it through
                if isinstance(result, tuple):
                    return result
                
                # If it's already a Response object, pass it through
                if hasattr(result, 'status_code'):
                    return result
                
                # Otherwise, it should be the raw data to format
                response = format_api_response(
                    status="success",
                    data=result,
                    domain=domain,
                    endpoint=endpoint_name
                )
                return jsonify(response)
                
            except BadRequest as e:
                return format_error_response(str(e), 400, domain)
            except Exception as e:
                logger.error(f"Error in {endpoint_name} endpoint: {str(e)}", exc_info=True)
                return format_error_response(
                    f"Failed to complete {endpoint_name} operation",
                    domain=domain
                )
        return wrapper
    return decorator

@api_bp.route('/dns', methods=['GET'])
@require_api_key
@format_response('dns')
def dns_endpoint():
    """Get DNS records for a domain"""
    domain = get_domain_param()
    logger.info(f"DNS check requested for domain: {domain}")
    
    return get_dns_records(domain)

@api_bp.route('/mx', methods=['GET'])
@require_api_key
@format_response('mx')
def mx_endpoint():
    """Get MX records for a domain"""
    domain = get_domain_param()
    logger.info(f"MX check requested for domain: {domain}")

    return get_mx_records(domain)

@api_bp.route('/spf', methods=['GET'])
@require_api_key
@format_response('spf')
def spf_endpoint():
    """Get SPF record for a domain with enhanced analysis"""
    domain = get_domain_param()
    logger.info(f"SPF check requested for domain: {domain}")

    # Get basic SPF record data
    results = get_spf_record(domain)

    # Add enhanced analysis
    if results.get("record"):
        analysis = analyze_spf_policy(results)
        results["analysis"] = analysis

        # Add a clear explanation about lookup counting
        lookup_count = results.get("lookup_count", {})
        total_lookups = lookup_count.get("total", 0)

        results["lookup_summary"] = {
            "explanation": "SPF has a limit of 10 DNS lookups per evaluation",
            "total_lookups_used": total_lookups,
            "remaining_lookups": max(0, 10 - total_lookups),
            "status": (
                "critical - exceeds limit" if total_lookups > 10 else
                "warning - approaching limit" if total_lookups > 8 else
                "good - within limit"
            )
        }

    return results

@api_bp.route('/dkim', methods=['GET'])
@require_api_key
@format_response('dkim')
def dkim_endpoint():
    """Check DKIM selectors for a domain"""
    domain = get_domain_param()

    # Optional parameter for specific selectors
    selectors = request.args.get('selectors')
    selector_list = selectors.split(',') if selectors else None

    logger.info(f"DKIM check requested for domain: {domain}, selectors: {selector_list}")

    return check_dkim_selectors(domain, selector_list)

@api_bp.route('/dmarc', methods=['GET'])
@require_api_key
@format_response('dmarc')
def dmarc_endpoint():
    """Get DMARC policy for a domain"""
    domain = get_domain_param()
    logger.info(f"DMARC check requested for domain: {domain}")

    return get_dmarc_policy(domain)

@api_bp.route('/ssl', methods=['GET'])
@require_api_key
@format_response('ssl')
def ssl_endpoint():
    """Get SSL/TLS information for a domain"""
    domain = get_domain_param()
    logger.info(f"SSL check requested for domain: {domain}")

    return get_ssl_info(domain)

@api_bp.route('/whois', methods=['GET'])
@require_api_key
@format_response('whois')
def whois_endpoint():
    """Get WHOIS information for a domain"""
    domain = get_domain_param()
    logger.info(f"WHOIS check requested for domain: {domain}")

    return get_whois_info(domain)

@api_bp.route('/bimi', methods=['GET'])
@require_api_key
@format_response('bimi')
def bimi_endpoint():
    """Check BIMI configuration for a domain"""
    domain = get_domain_param()
    logger.info(f"BIMI check requested for domain: {domain}")

    return check_bimi(domain)

@api_bp.route('/scan', methods=['GET'])
@require_api_key
@format_response('scan')
def scan_all_endpoint():
    """
    Run all checks for a domain in one request
    """
    domain = get_domain_param()
    logger.info(f"Full scan requested for domain: {domain}")

    results = {
        "scan_id": str(uuid.uuid4()),
        "checks": {},
        "errors": []
    }

    # List of all checks to run
    checks = [
        {"name": "dns", "function": get_dns_records, "complete": False},
        {"name": "mx", "function": get_mx_records, "complete": False},
        {"name": "spf", "function": get_spf_record, "complete": False},
        {"name": "dkim", "function": check_dkim_selectors, "complete": False},
        {"name": "dmarc", "function": get_dmarc_policy, "complete": False},
        {"name": "ssl", "function": get_ssl_info, "complete": False},
        {"name": "whois", "function": get_whois_info, "complete": False},
        {"name": "bimi", "function": check_bimi, "complete": False}
    ]

    # Run each check
    for check in checks:
        check_name = check["name"]
        check_function = check["function"]

        try:
            logger.info(f"Running {check_name} check for {domain}")
            check_result = check_function(domain)
            results["checks"][check_name] = check_result
            check["complete"] = True
            logger.info(f"Completed {check_name} check for {domain}")
        except Exception as e:
            error_msg = f"Error in {check_name} check: {str(e)}"
            logger.error(error_msg, exc_info=True)
            results["errors"].append(error_msg)
            # Add a placeholder for the failed check
            results["checks"][check_name] = {
                "error": f"Check failed: {str(e)}",
                "complete": False
            }

    # Add summary information
    complete_checks = sum(1 for check in checks if check["complete"])
    results["summary"] = {
        "total_checks": len(checks),
        "complete_checks": complete_checks,
        "success_rate": f"{(complete_checks / len(checks)) * 100:.1f}%"
    }

    return results

@api_bp.route('/all', methods=['GET'])
@require_api_key
@format_response('all')
def all_checks_endpoint():
    """
    Alias for scan_all_endpoint
    """
    return scan_all_endpoint()

# Error handlers
@api_bp.errorhandler(BadRequest)
def handle_bad_request(e):
    return format_error_response(str(e), 400)

@api_bp.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    return format_error_response("An unexpected error occurred", 500)
