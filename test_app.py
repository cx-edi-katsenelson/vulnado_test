#!/usr/bin/env python3
"""
Unit tests for Flask REST API endpoints.
Tests both the health check endpoint and the data processing endpoint.
"""

import json
import pytest
from app import app


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestHealthCheckEndpoint:
    """Test cases for the health check endpoint (/)."""

    def test_health_check_get_success(self, client):
        """Test successful GET request to health check endpoint."""
        response = client.get('/')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['message'] == 'Flask REST API is running'
        assert data['version'] == '1.0.0'

    def test_health_check_post_not_allowed(self, client):
        """Test that POST requests to health check endpoint are not allowed."""
        response = client.post('/')
        
        assert response.status_code == 405
        
        data = json.loads(response.data)
        assert 'error' in data
        assert data['error'] == 'Method not allowed'

    def test_health_check_put_not_allowed(self, client):
        """Test that PUT requests to health check endpoint are not allowed."""
        response = client.put('/')
        
        assert response.status_code == 405

    def test_health_check_delete_not_allowed(self, client):
        """Test that DELETE requests to health check endpoint are not allowed."""
        response = client.delete('/')
        
        assert response.status_code == 405


class TestDataEndpoint:
    """Test cases for the data processing endpoint (/data)."""

    def test_data_post_success_normal(self, client):
        """Test successful POST request to data endpoint with normal data."""
        test_data = {
            'name': 'test_user',
            'message': 'Hello, World!'
        }
        
        response = client.post('/data',
                             data=json.dumps(test_data),
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'received' in data
        assert data['received'] == test_data
        assert data['processed'] is True
        assert 'timestamp' in data

    def test_data_post_with_command_vulnerability(self, client):
        """Test POST request with command field (demonstrates vulnerability)."""
        test_data = {
            'command': 'echo "test output"'
        }
        
        response = client.post('/data',
                             data=json.dumps(test_data),
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['message'] == 'Command executed successfully'
        assert 'test output' in data['output']
        assert data['input_data'] == test_data

    def test_data_post_invalid_command(self, client):
        """Test POST request with invalid command."""
        test_data = {
            'command': 'invalid_command_that_does_not_exist'
        }
        
        response = client.post('/data',
                             data=json.dumps(test_data),
                             content_type='application/json')
        
        assert response.status_code == 500
        
        data = json.loads(response.data)
        assert data['error'] == 'Command execution failed'

    def test_data_post_no_json(self, client):
        """Test POST request without JSON data."""
        response = client.post('/data')
        
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['error'] == 'No JSON data provided'

    def test_data_post_empty_json(self, client):
        """Test POST request with empty JSON data."""
        response = client.post('/data',
                             data=json.dumps({}),
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'received' in data
        assert data['received'] == {}
        assert data['processed'] is True

    def test_data_get_not_allowed(self, client):
        """Test that GET requests to data endpoint are not allowed."""
        response = client.get('/data')
        
        assert response.status_code == 405
        
        data = json.loads(response.data)
        assert data['error'] == 'Method not allowed'

    def test_data_put_not_allowed(self, client):
        """Test that PUT requests to data endpoint are not allowed."""
        response = client.put('/data')
        
        assert response.status_code == 405

    def test_data_delete_not_allowed(self, client):
        """Test that DELETE requests to data endpoint are not allowed."""
        response = client.delete('/data')
        
        assert response.status_code == 405


class TestErrorHandling:
    """Test cases for error handling and edge cases."""

    def test_invalid_endpoint_404(self, client):
        """Test request to non-existent endpoint returns 404."""
        response = client.get('/nonexistent')
        
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert data['error'] == 'Endpoint not found'
        assert 'Available endpoints' in data['message']

    def test_invalid_json_format(self, client):
        """Test POST request with malformed JSON."""
        response = client.post('/data',
                             data='{"invalid": json}',
                             content_type='application/json')
        
        assert response.status_code == 400

    def test_content_type_handling(self, client):
        """Test POST request without proper content type."""
        test_data = {'test': 'data'}
        
        response = client.post('/data',
                             data=json.dumps(test_data),
                             content_type='text/plain')
        
        # Should still work as Flask can parse JSON regardless of content type
        assert response.status_code in [200, 400]


class TestSecurityVulnerability:
    """Test cases specifically for the code injection vulnerability."""

    def test_command_injection_ls(self, client):
        """Test command injection with 'ls' command."""
        test_data = {
            'command': 'ls -la'
        }
        
        response = client.post('/data',
                             data=json.dumps(test_data),
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'output' in data
        # The output should contain file listings

    def test_command_injection_whoami(self, client):
        """Test command injection with 'whoami' command."""
        test_data = {
            'command': 'whoami'
        }
        
        response = client.post('/data',
                             data=json.dumps(test_data),
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'output' in data

    def test_command_injection_chaining(self, client):
        """Test command injection with command chaining."""
        test_data = {
            'command': 'echo "first" && echo "second"'
        }
        
        response = client.post('/data',
                             data=json.dumps(test_data),
                             content_type='application/json')
        
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'first' in data['output']
        assert 'second' in data['output']
