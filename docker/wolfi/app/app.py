"""
Wolfi Web Server - Production Flask Application ..(beta)..
================================================
A secure, production-ready web server with:
- Comprehensive logging
- Health checks
- Prometheus metrics
- API endpoints
- Error handling
- Security headers
"""

from flask import Flask, jsonify, request, make_response
from prometheus_flask_exporter import PrometheusMetrics
from functools import wraps
import os
import logging
import sys
from datetime import datetime
import socket

# ==============================================================================
# Application Configuration
# ==============================================================================

app = Flask(__name__)

# Get configuration from environment variables
APP_PORT = int(os.getenv('APP_PORT', 6699))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
FLASK_ENV = os.getenv('FLASK_ENV', 'production')
APP_VERSION = os.getenv('APP_VERSION', '1.0.0')

# ==============================================================================
# Logging Configuration
# ==============================================================================

# Configure structured logging with JSON format for production
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)
logger.info(f"Starting Wolfi Web Server v{APP_VERSION} on port {APP_PORT}")
logger.info(f"Environment: {FLASK_ENV}, Log Level: {LOG_LEVEL}")

# ==============================================================================
# Metrics Configuration
# ==============================================================================

# Setup Prometheus metrics with custom configuration
metrics = PrometheusMetrics(
    app,
    group_by='endpoint',  # Group metrics by endpoint
    default_labels={'version': APP_VERSION, 'service': 'wolfi-webserver'}
)

# Add custom metric info
metrics.info('app_info', 'Application information', version=APP_VERSION)

# ==============================================================================
# Security Middleware
# ==============================================================================

@app.after_request
def add_security_headers(response):
    """
    Add security headers to all responses
    Protects against common web vulnerabilities
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# ==============================================================================
# Request Logging Middleware
# ==============================================================================

@app.before_request
def log_request_info():
    """Log incoming request details"""
    logger.info(
        f"Request: {request.method} {request.path} | "
        f"IP: {request.remote_addr} | "
        f"User-Agent: {request.headers.get('User-Agent', 'Unknown')}"
    )

@app.after_request
def log_response_info(response):
    """Log response details"""
    logger.info(
        f"Response: {request.method} {request.path} | "
        f"Status: {response.status_code}"
    )
    return response

# ==============================================================================
# Utility Functions
# ==============================================================================

def get_system_info():
    """Gather system information for diagnostics"""
    return {
        'hostname': socket.gethostname(),
        'python_version': sys.version.split()[0],
        'environment': FLASK_ENV,
        'port': APP_PORT,
        'workers': os.getenv('GUNICORN_WORKERS', '4'),
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }

def validate_json_content_type(f):
    """Decorator to ensure JSON content type for POST/PUT requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT']:
            if not request.is_json:
                logger.warning(
                    f"Invalid content type: {request.content_type}"
                )
                return jsonify({
                    'error': 'Content-Type must be application/json',
                    'status': 415
                }), 415
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# Root Endpoint
# ==============================================================================

@app.route('/')
def home():
    """
    Root endpoint - Service information and available routes
    Returns: JSON with service metadata and endpoint list
    """
    logger.debug("Root endpoint accessed")
    
    return jsonify({
        'service': 'Wolfi Web Server',
        'version': APP_VERSION,
        'status': 'running',
        'environment': FLASK_ENV,
        'port': APP_PORT,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'endpoints': {
            'health': {
                'path': '/health',
                'method': 'GET',
                'description': 'Health check endpoint'
            },
            'ready': {
                'path': '/ready',
                'method': 'GET',
                'description': 'Readiness probe endpoint'
            },
            'metrics': {
                'path': '/metrics',
                'method': 'GET',
                'description': 'Prometheus metrics'
            },
            'info': {
                'path': '/api/info',
                'method': 'GET',
                'description': 'System information'
            },
            'data': {
                'path': '/api/data',
                'methods': ['GET', 'POST'],
                'description': 'Data operations endpoint'
            },
            'echo': {
                'path': '/api/echo',
                'method': 'POST',
                'description': 'Echo back request data'
            },
            'status': {
                'path': '/api/status',
                'method': 'GET',
                'description': 'Detailed application status'
            }
        }
    }), 200

# ==============================================================================
# Health Check Endpoints
# ==============================================================================

@app.route('/health')
def health():
    """
    Liveness probe - Basic health check
    Used by Docker/Kubernetes to determine if container is alive
    Returns: 200 if healthy, 503 if unhealthy
    """
    try:
        # Add your health checks here (database, cache, etc.)
        checks = {
            'application': 'ok',
            'database': 'not_configured',
            'cache': 'not_configured'
        }
        
        # Determine overall health
        is_healthy = all(
            status in ['ok', 'not_configured'] 
            for status in checks.values()
        )
        
        status_code = 200 if is_healthy else 503
        
        return jsonify({
            'status': 'healthy' if is_healthy else 'unhealthy',
            'checks': checks,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), status_code
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 503

@app.route('/ready')
def ready():
    """
    Readiness probe - Check if app is ready to accept traffic
    Used by Kubernetes to determine if pod should receive traffic
    Returns: 200 if ready, 503 if not ready
    """
    try:
        # Add readiness checks here (can service connect to dependencies?)
        is_ready = True
        
        if is_ready:
            return jsonify({
                'status': 'ready',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 200
        else:
            return jsonify({
                'status': 'not_ready',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 503
            
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        return jsonify({
            'status': 'not_ready',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 503

# ==============================================================================
# API Endpoints
# ==============================================================================

@app.route('/api/info')
def api_info():
    """
    System information endpoint
    Returns: System and runtime information
    """
    logger.debug("System info requested")
    
    info = get_system_info()
    info.update({
        'version': APP_VERSION,
        'status': 'operational'
    })
    
    return jsonify(info), 200

@app.route('/api/status')
def api_status():
    """
    Detailed application status
    Returns: Comprehensive status information
    """
    logger.debug("Detailed status requested")
    
    return jsonify({
        'service': 'Wolfi Web Server',
        'version': APP_VERSION,
        'status': 'operational',
        'system': get_system_info(),
        'configuration': {
            'log_level': LOG_LEVEL,
            'environment': FLASK_ENV,
            'port': APP_PORT
        },
        'uptime': 'metrics available at /metrics'
    }), 200

@app.route('/api/data', methods=['GET', 'POST'])
@validate_json_content_type
def api_data():
    """
    Data operations endpoint
    GET: Returns usage instructions
    POST: Accepts and processes JSON data
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Log the received data
            logger.info(f"Received data: {data}")
            
            # Validate data (basic example)
            if not data:
                return jsonify({
                    'error': 'Empty data received',
                    'status': 'error'
                }), 400
            
            # Process data (placeholder for actual business logic)
            response_data = {
                'received': data,
                'status': 'success',
                'message': 'Data processed successfully',
                'processed_at': datetime.utcnow().isoformat() + 'Z',
                'items_count': len(data) if isinstance(data, (list, dict)) else 1
            }
            
            logger.info(f"Data processed successfully: {len(str(data))} bytes")
            return jsonify(response_data), 201
            
        except Exception as e:
            logger.error(f"Error processing data: {str(e)}")
            return jsonify({
                'error': 'Failed to process data',
                'details': str(e),
                'status': 'error'
            }), 500
    
    # GET request - return instructions
    return jsonify({
        'message': 'Send POST request with JSON data',
        'endpoint': '/api/data',
        'method': 'POST',
        'content_type': 'application/json',
        'example': {
            'name': 'example',
            'value': 123,
            'tags': ['tag1', 'tag2']
        }
    }), 200

@app.route('/api/echo', methods=['POST'])
@validate_json_content_type
def api_echo():
    """
    Echo endpoint - Returns the same data sent to it
    Useful for testing and debugging
    """
    try:
        data = request.get_json()
        logger.debug(f"Echo request: {data}")
        
        return jsonify({
            'echo': data,
            'received_at': datetime.utcnow().isoformat() + 'Z',
            'headers': dict(request.headers),
            'method': request.method,
            'endpoint': request.path
        }), 200
        
    except Exception as e:
        logger.error(f"Echo endpoint error: {str(e)}")
        return jsonify({
            'error': 'Failed to echo data',
            'details': str(e)
        }), 500

# ==============================================================================
# Error Handlers
# ==============================================================================

@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors"""
    logger.warning(f"Bad request: {error}")
    return jsonify({
        'error': 'Bad request',
        'status': 400,
        'message': str(error),
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 400

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors"""
    logger.warning(f"Resource not found: {request.path}")
    return jsonify({
        'error': 'Resource not found',
        'status': 404,
        'path': request.path,
        'message': 'The requested resource does not exist',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 Method Not Allowed errors"""
    logger.warning(
        f"Method not allowed: {request.method} on {request.path}"
    )
    return jsonify({
        'error': 'Method not allowed',
        'status': 405,
        'method': request.method,
        'path': request.path,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 405

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server Error"""
    logger.error(f"Internal server error: {error}", exc_info=True)
    return jsonify({
        'error': 'Internal server error',
        'status': 500,
        'message': 'An unexpected error occurred',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 500

@app.errorhandler(503)
def service_unavailable(error):
    """Handle 503 Service Unavailable errors"""
    logger.error(f"Service unavailable: {error}")
    return jsonify({
        'error': 'Service unavailable',
        'status': 503,
        'message': 'The service is temporarily unavailable',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 503

# ==============================================================================
# Application Entry Point (Development Only)
# ==============================================================================

if __name__ == '__main__':
    # This is only used for development
    # In production, Gunicorn is used as the WSGI server
    logger.warning(
        "Running in development mode. Use Gunicorn for production!"
    )
    app.run(
        host='0.0.0.0',
        port=APP_PORT,
        debug=(FLASK_ENV == 'development')
    )
