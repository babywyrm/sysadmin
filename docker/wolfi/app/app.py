"""
Wolfi Web Server - Production Flask Application ..testing..
================================================
A secure, production-ready web server with:
- Comprehensive logging
- Health checks & Readiness probes
- Prometheus metrics
- API endpoints & Security headers
"""

from flask import Flask, jsonify, request
from prometheus_flask_exporter import PrometheusMetrics
from functools import wraps
import os
import logging
import sys
from datetime import datetime, UTC
import socket

# ==============================================================================
# Application Configuration
# ==============================================================================

app = Flask(__name__)

# Configuration from environment
APP_PORT = int(os.getenv('APP_PORT', 6699))
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
FLASK_ENV = os.getenv('FLASK_ENV', 'production')
APP_VERSION = os.getenv('APP_VERSION', '1.0.0')

# ==============================================================================
# Logging Configuration
# ==============================================================================

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)
logger.info(f"Starting Wolfi Web Server v{APP_VERSION} on port {APP_PORT}")

# ==============================================================================
# Metrics Configuration
# ==============================================================================

metrics = PrometheusMetrics(
    app,
    group_by='endpoint',
    default_labels={'version': APP_VERSION, 'service': 'wolfi-webserver'}
)
metrics.info('app_info', 'Application information', version=APP_VERSION)

# ==============================================================================
# Security & Logging Middleware
# ==============================================================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.before_request
def log_request_info():
    """Log incoming request details"""
    logger.info(f"Request: {request.method} {request.path} | IP: {request.remote_addr}")

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
        'timestamp': datetime.now(UTC).isoformat()
    }

def validate_json_content_type(f):
    """Decorator to ensure JSON content type for POST/PUT requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT'] and not request.is_json:
            logger.warning(f"Invalid content type: {request.content_type}")
            return jsonify({
                'error': 'Content-Type must be application/json',
                'status': 415
            }), 415
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# Routes
# ==============================================================================

@app.route('/')
def home():
    """Root endpoint - Service metadata and available routes"""
    return jsonify({
        'service': 'Wolfi Web Server',
        'version': APP_VERSION,
        'status': 'running',
        'environment': FLASK_ENV,
        'port': APP_PORT,
        'timestamp': datetime.now(UTC).isoformat(),
        'endpoints': {
            'health': '/health',
            'ready': '/ready',
            'metrics': '/metrics',
            'info': '/api/info',
            'status': '/api/status',
            'data': '/api/data'
        }
    }), 200

@app.route('/health')
def health():
    """Liveness probe - Basic health check"""
    try:
        checks = {'application': 'ok', 'database': 'not_configured'}
        return jsonify({
            'status': 'healthy',
            'checks': checks,
            'timestamp': datetime.now(UTC).isoformat()
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503

@app.route('/ready')
def ready():
    """Readiness probe - Check if app is ready to accept traffic"""
    return jsonify({
        'status': 'ready',
        'timestamp': datetime.now(UTC).isoformat()
    }), 200

@app.route('/api/info')
@app.route('/api/status')
def api_status():
    """Detailed application and system status"""
    return jsonify({
        'service': 'Wolfi Web Server',
        'version': APP_VERSION,
        'status': 'operational',
        'system': get_system_info(),
        'configuration': {
            'log_level': LOG_LEVEL,
            'environment': FLASK_ENV,
            'port': APP_PORT
        }
    }), 200

@app.route('/api/data', methods=['GET', 'POST'])
@validate_json_content_type
def api_data():
    """Data operations endpoint"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            logger.info(f"Received data: {data}")
            return jsonify({
                'status': 'success',
                'received': data,
                'message': 'Data processed successfully',
                'processed_at': datetime.now(UTC).isoformat()
            }), 201
        except Exception as e:
            logger.error(f"Error processing data: {str(e)}")
            return jsonify({'error': 'Failed to process data', 'status': 'error'}), 500
    
    return jsonify({
        'message': 'Send POST request with JSON data',
        'example': {'name': 'example', 'value': 123}
    }), 200

@app.route('/api/echo', methods=['POST'])
@validate_json_content_type
def api_echo():
    """Echo endpoint - Returns the sent data"""
    return jsonify({
        'echo': request.get_json(),
        'received_at': datetime.now(UTC).isoformat(),
        'method': request.method
    }), 200

# ==============================================================================
# Error Handlers
# ==============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Resource not found',
        'status': 404,
        'path': request.path,
        'timestamp': datetime.now(UTC).isoformat()
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'error': 'Method not allowed',
        'status': 405,
        'method': request.method,
        'timestamp': datetime.now(UTC).isoformat()
    }), 405

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}", exc_info=True)
    return jsonify({
        'error': 'Internal server error',
        'status': 500,
        'timestamp': datetime.now(UTC).isoformat()
    }), 500

if __name__ == '__main__':
    # Used for local development only
    app.run(host='0.0.0.0', port=APP_PORT, debug=(FLASK_ENV == 'development'))
