"""
Pytest configuration and fixtures
"""
import pytest
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from app import app as flask_app


@pytest.fixture
def app():
    """Create application instance for testing"""
    flask_app.config.update({
        'TESTING': True,
        'DEBUG': True,
    })
    yield flask_app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create test CLI runner"""
    return app.test_cli_runner()


@pytest.fixture
def sample_data():
    """Sample data for testing"""
    return {
        'name': 'test_item',
        'value': 42,
        'tags': ['test', 'sample'],
        'metadata': {
            'created_by': 'pytest',
            'environment': 'testing'
        }
    }
