#!/usr/bin/env python3
"""
Flask REST API with health check and data endpoints.
Includes a code injection vulnerability in the /data endpoint.
"""

import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/', methods=['GET'])
def health_check():
    """
    Health check endpoint - only accepts GET requests.
    Returns basic status information about the service.
    """
    return jsonify({
        'status': 'healthy',
        'message': 'Flask REST API is running',
        'version': '1.0.0'
    }), 200


@app.route('/data', methods=['POST'])
def process_data():
    """
    Data processing endpoint - only accepts POST requests.
    Processes JSON payload and executes commands based on input.
    
    WARNING: This endpoint contains a code injection vulnerability!
    """
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        # Extract command from the JSON payload
        # VULNERABILITY: Direct execution of user input without sanitization
        if 'command' in data:
            command = data['command']
            # Code injection vulnerability - executing user input directly
            result = subprocess.check_output(command, shell=True, text=True)
            return jsonify({
                'message': 'Command executed successfully',
                'output': result,
                'input_data': data
            }), 200
        
        # Normal data processing path
        processed_data = {
            'received': data,
            'processed': True,
            'timestamp': str(__import__('datetime').datetime.now())
        }
        
        return jsonify(processed_data), 200
        
    except subprocess.CalledProcessError as e:
        return jsonify({
            'error': 'Command execution failed',
            'details': str(e)
        }), 500
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'details': str(e)
        }), 500


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle method not allowed errors."""
    return jsonify({
        'error': 'Method not allowed',
        'message': 'Check the HTTP method and endpoint'
    }), 405


@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'Available endpoints: / (GET), /data (POST)'
    }), 404


if __name__ == '__main__':
    # Development server configuration
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() in ['true', '1', 'yes']
    
    app.run(host='0.0.0.0', port=port, debug=debug)
