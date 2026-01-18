"""Consolidated test suite for Wolfi Web Server"""
import json
import pytest

# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def sample_data():
    """Sample data for testing"""
    return {'name': 'test', 'value': 42, 'tags': ['demo']}

# ============================================================================
# Core Endpoint Tests
# ============================================================================

def test_root_endpoint(client):
    """Test root endpoint"""
    response = client.get('/')
    assert response.status_code == 200
    data = response.get_json()
    assert data['service'] == 'Wolfi Web Server'
    assert data['status'] == 'running'
    assert 'endpoints' in data

def test_health_endpoint(client):
    """Test health check"""
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert 'checks' in data

def test_ready_endpoint(client):
    """Test readiness probe"""
    response = client.get('/ready')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'ready'

def test_api_info(client):
    """Test API info endpoint for system data"""
    response = client.get('/api/info')
    assert response.status_code == 200
    data = response.get_json()
    
    # Check for nested system info
    assert 'system' in data
    assert 'hostname' in data['system']
    assert 'python_version' in data['system']
    assert data['service'] == 'Wolfi Web Server'

def test_api_status(client):
    """Test API status endpoint for configuration data"""
    response = client.get('/api/status')
    assert response.status_code == 200
    data = response.get_json()
    
    assert 'configuration' in data
    assert 'log_level' in data['configuration']
    assert data['status'] == 'operational'

# ============================================================================
# Data Endpoint Tests
# ============================================================================

def test_data_get(client):
    """Test GET /api/data"""
    response = client.get('/api/data')
    assert response.status_code == 200
    data = response.get_json()
    assert 'example' in data

def test_data_post(client, sample_data):
    """Test POST /api/data"""
    response = client.post(
        '/api/data',
        data=json.dumps(sample_data),
        content_type='application/json'
    )
    assert response.status_code == 201
    data = response.get_json()
    assert data['status'] == 'success'
    assert data['received'] == sample_data
    assert 'processed_at' in data

def test_data_post_invalid_content_type(client, sample_data):
    """Test POST without JSON content type fails"""
    response = client.post(
        '/api/data',
        data=json.dumps(sample_data),
        content_type='text/plain'
    )
    assert response.status_code == 415

def test_echo_endpoint(client, sample_data):
    """Test echo endpoint"""
    response = client.post(
        '/api/echo',
        data=json.dumps(sample_data),
        content_type='application/json'
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data['echo'] == sample_data

# ============================================================================
# Error Handling Tests
# ============================================================================

def test_404_error(client):
    """Test 404 handler"""
    response = client.get('/nonexistent')
    assert response.status_code == 404
    data = response.get_json()
    assert data['error'] == 'Resource not found'

def test_405_error(client):
    """Test 405 handler"""
    response = client.post('/health')
    assert response.status_code == 405
    data = response.get_json()
    assert data['error'] == 'Method not allowed'

# ============================================================================
# Security & Monitoring Tests
# ============================================================================

def test_security_headers(client):
    """Test security headers are present"""
    response = client.get('/')
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'

def test_metrics_endpoint(client):
    """Test Prometheus metrics"""
    response = client.get('/metrics')
    assert response.status_code == 200
    assert 'text/plain' in response.content_type

def test_full_workflow(client, sample_data):
    """Test complete workflow integration"""
    # 1. Health check
    assert client.get('/health').status_code == 200
    
    # 2. API Submission
    response = client.post(
        '/api/data',
        json=sample_data
    )
    assert response.status_code == 201
    
    # 3. Verify metrics
    assert client.get('/metrics').status_code == 200
