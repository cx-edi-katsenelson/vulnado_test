# Flask REST API with Code Injection Vulnerability

A containerized REST web service built with Python, Flask, Docker, and Gunicorn that demonstrates a code injection vulnerability for educational purposes.

## Features

- **Health Check Endpoint**: `GET /` - Returns service status
- **Data Processing Endpoint**: `POST /data` - Processes JSON payloads
- **Code Injection Vulnerability**: Intentional security flaw in `/data` endpoint
- **Containerized**: Docker support with Gunicorn WSGI server
- **Testing**: Comprehensive test suite (not executed)

## Technology Stack

- **Python**: 3.11
- **Flask**: 2.2.3
- **Werkzeug**: 2.2.3
- **Gunicorn**: 21.2.0 (with deprecated `gunicorn_paste()` method)
- **Docker**: Containerization
- **pytest**: Testing framework

## Project Structure

```
.
├── app.py                 # Main Flask application
├── gunicorn_config.py     # Gunicorn configuration with gunicorn_paste()
├── requirements.txt       # Python dependencies
├── Dockerfile            # Container configuration
├── .dockerignore         # Docker ignore file
├── test_app.py           # Unit tests (not executed)
└── README.md             # This file
```

## API Endpoints

### Health Check - `GET /`

Returns the service health status.

**Response:**
```json
{
    "status": "healthy",
    "message": "Flask REST API is running",
    "version": "1.0.0"
}
```

### Data Processing - `POST /data`

Processes JSON payloads. **WARNING**: Contains a code injection vulnerability!

**Normal Usage:**
```bash
curl -X POST http://localhost:8000/data \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "message": "hello"}'
```

**Vulnerable Usage (Code Injection):**
```bash
curl -X POST http://localhost:8000/data \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la"}'
```

## Security Vulnerability

⚠️ **WARNING**: This application contains an intentional code injection vulnerability in the `/data` endpoint.

The vulnerability is located in `app.py` at line ~40:
```python
if 'command' in data:
    command = data['command']
    # VULNERABILITY: Direct execution of user input without sanitization
    result = subprocess.check_output(command, shell=True, text=True)
```

This allows attackers to execute arbitrary system commands by sending JSON payloads with a `command` field.

## Building and Running

### Using Docker (Recommended)

1. **Build the container:**
   ```bash
   docker build -t flask-api .
   ```

2. **Run the container:**
   ```bash
   docker run -p 8000:8000 flask-api
   ```

3. **Test the application:**
   ```bash
   # Health check
   curl http://localhost:8000/
   
   # Data endpoint
   curl -X POST http://localhost:8000/data \
     -H "Content-Type: application/json" \
     -d '{"test": "data"}'
   ```

### Local Development

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run with Gunicorn:**
   ```bash
   gunicorn --config gunicorn_config.py app:app
   ```

3. **Or run Flask development server:**
   ```bash
   python app.py
   ```

## Gunicorn Configuration

The `gunicorn_config.py` file includes usage of the `gunicorn_paste()` method, which:
- Is available in Gunicorn 21.2.0
- Was deprecated in Gunicorn 23.0.0
- Provides PasteDeploy integration capabilities

## Testing

Unit tests are provided in `test_app.py` but are **not executed** as requested. The tests cover:

- Health check endpoint functionality
- Data endpoint normal operation
- Code injection vulnerability scenarios
- Error handling and edge cases
- HTTP method restrictions

To run tests manually:
```bash
pytest test_app.py -v
```

## Environment Variables

- `PORT`: Server port (default: 5000 for development, 8000 for production)
- `DEBUG`: Enable debug mode (default: False)

## Disclaimer

This application is created for educational purposes to demonstrate security vulnerabilities. **DO NOT** deploy this application in a production environment without fixing the security issues.

## License

This project is for educational purposes only.
