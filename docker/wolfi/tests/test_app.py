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
    data = json.loads(response.data)
    assert data['service'] == 'Wolfi Web Server'
    assert data['status'] == 'running'
    assert 'endpoints' in data


def test_health_endpoint(client):
    """Test health check"""
    response = client.get('/health')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'healthy'
    assert 'checks' in data


def test_ready_endpoint(client):
    """Test readiness probe"""
    response = client.get('/ready')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'ready'


def test_api_info(client):
    """Test API info endpoint"""
    response = client.get('/api/info')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'hostname' in data
    assert 'version' in data


def test_api_status(client):
    """Test API status endpoint"""
    response = client.get('/api/status')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'service' in data
    assert 'system' in data


# ============================================================================
# Data Endpoint Tests
# ============================================================================

def test_data_get(client):
    """Test GET /api/data"""
    response = client.get('/api/data')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'example' in data


def test_data_post(client, sample_data):
    """Test POST /api/data"""
    response = client.post(
        '/api/data',
        data=json.dumps(sample_data),
        content_type='application/json'
    )
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert data['received'] == sample_data


def test_data_post_invalid_content_type(client, sample_data):
    """Test POST without JSON content type"""
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
    data = json.loads(response.data)
    assert data['echo'] == sample_data


# ============================================================================
# Error Handling Tests
# ============================================================================

def test_404_error(client):
    """Test 404 handler"""
    response = client.get('/nonexistent')
    assert response.status_code == 404
    data = json.loads(response.data)
    assert data['error'] == 'Resource not found'


def test_405_error(client):
    """Test 405 handler"""
    response = client.post('/health')
    assert response.status_code == 405
    data = json.loads(response.data)
    assert data['error'] == 'Method not allowed'


# ============================================================================
# Security Tests
# ============================================================================

def test_security_headers(client):
    """Test security headers are present"""
    response = client.get('/')
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert 'Strict-Transport-Security' in response.headers


# ============================================================================
# Metrics Tests
# ============================================================================

def test_metrics_endpoint(client):
    """Test Prometheus metrics"""
    response = client.get('/metrics')
    assert response.status_code == 200
    assert 'text/plain' in response.content_type


# ============================================================================
# Integration Tests
# ============================================================================

def test_full_workflow(client, sample_data):
    """Test complete workflow"""
    # Check health
    assert client.get('/health').status_code == 200
    
    # Post data
    response = client.post(
        '/api/data',
        data=json.dumps(sample_data),
        content_type='application/json'
    )
    assert response.status_code == 201
    
    # Check metrics updated
    assert client.get('/metrics').status_code == 200
