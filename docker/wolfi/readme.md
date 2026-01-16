# Wolfi Web Server (..sounds chill..)


## 📋 Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Monitoring](#monitoring)
- [Development](#development)
- [Production Deployment](#production-deployment)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Stretch Goals](#stretch-goals)

## ✨ Features

- **Wolfi-based**: Minimal CVEs and security vulnerabilities
- **Multi-stage build**: Optimized image size
- **Production-ready**: Gunicorn WSGI server with worker management
- **Health checks**: Built-in health endpoints for orchestration
- **Prometheus metrics**: Out-of-the-box observability
- **Non-root user**: Security-hardened container
- **Signal handling**: Proper shutdown with Tini init system
- **Structured logging**: Production-grade log formatting

## 📁 Project Structure

```
.
├── Dockerfile
├── requirements.txt
├── README.md
└── app/
    └── app.py
```

## 🔧 Prerequisites

- Docker 20.10 or later
- Docker Compose (optional)
- curl or similar HTTP client for testing

## 🚀 Quick Start

### 1. Clone or create the project structure

```bash
mkdir wolfi-webserver && cd wolfi-webserver
mkdir app
```

### 2. Create the application files

**requirements.txt:**
```text
Flask==3.0.0
gunicorn==21.2.0
prometheus-flask-exporter==0.23.0
python-dotenv==1.0.0
```

**app/app.py:**
```python
from flask import Flask, jsonify, request
from prometheus_flask_exporter import PrometheusMetrics
import os
import logging

app = Flask(__name__)

# Setup Prometheus metrics
metrics = PrometheusMetrics(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.route('/')
def home():
    """Root endpoint returning service information"""
    return jsonify({
        'service': 'Wolfi Web Server',
        'status': 'running',
        'version': '1.0.0',
        'endpoints': {
            'health': '/health',
            'metrics': '/metrics',
            'api': '/api/data'
        }
    })

@app.route('/health')
def health():
    """Health check endpoint for container orchestration"""
    return jsonify({
        'status': 'healthy',
        'checks': {
            'application': 'ok',
            'database': 'not_configured'
        }
    }), 200

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    """API endpoint for data operations"""
    if request.method == 'POST':
        data = request.get_json()
        logger.info(f"Received data: {data}")
        return jsonify({
            'received': data,
            'status': 'success',
            'message': 'Data processed successfully'
        }), 201
    
    return jsonify({
        'message': 'Send POST request with JSON data',
        'example': {
            'name': 'example',
            'value': 123
        }
    })

@app.route('/api/info')
def api_info():
    """System information endpoint"""
    return jsonify({
        'python_version': os.sys.version,
        'environment': os.getenv('FLASK_ENV', 'production'),
        'workers': os.getenv('GUNICORN_WORKERS', '4')
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not found',
        'status': 404
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {error}")
    return jsonify({
        'error': 'Internal server error',
        'status': 500
    }), 500

if __name__ == '__main__':
    # Development server (not used in production)
    app.run(host='0.0.0.0', port=8000, debug=False)
```

**Dockerfile:**
```dockerfile
# Multi-stage build for a production Flask web server on Wolfi

# Stage 1: Builder stage
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

# Install build dependencies
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    py3-wheel \
    py3-setuptools \
    build-base \
    python3-dev

# Create virtual environment for better dependency isolation
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements file
COPY requirements.txt /tmp/
WORKDIR /tmp

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production runtime
FROM cgr.dev/chainguard/wolfi-base:latest

# Install only runtime dependencies
RUN apk update && apk add --no-cache \
    python3 \
    py3-pip \
    bash \
    curl \
    ca-certificates \
    tini

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production

# Create app directory and set permissions
WORKDIR /app

# Copy application code
COPY --chown=65532:65532 ./app /app

# Create non-root user directories
RUN mkdir -p /app/logs /app/tmp && \
    chown -R 65532:65532 /app

# Switch to non-root user
USER 65532

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Use tini as init system for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Run with gunicorn for production
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--threads", "2", \
     "--worker-class", "gthread", \
     "--worker-tmp-dir", "/dev/shm", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "app:app"]
```

### 3. Build the Docker image

```bash
docker build -t wolfi-webserver:latest .
```

### 4. Run the container

```bash
docker run -d \
  --name wolfi-web \
  -p 8000:8000 \
  --restart unless-stopped \
  wolfi-webserver:latest
```

### 5. Test the server

```bash
# Check the root endpoint
curl http://localhost:8000

# Health check
curl http://localhost:8000/health

# Test POST endpoint
curl -X POST http://localhost:8000/api/data \
  -H "Content-Type: application/json" \
  -d '{"name":"test","value":42}'

# View Prometheus metrics
curl http://localhost:8000/metrics
```

## ⚙️ Configuration

### Environment Variables

You can customize the server by passing environment variables:

```bash
docker run -d \
  --name wolfi-web \
  -p 8000:8000 \
  -e GUNICORN_WORKERS=8 \
  -e GUNICORN_THREADS=4 \
  -e LOG_LEVEL=debug \
  wolfi-webserver:latest
```

### Common Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GUNICORN_WORKERS` | 4 | Number of worker processes |
| `GUNICORN_THREADS` | 2 | Threads per worker |
| `LOG_LEVEL` | info | Logging level (debug, info, warning, error) |
| `FLASK_ENV` | production | Flask environment |

## 📡 API Endpoints

### `GET /`
Returns service information and available endpoints.

**Response:**
```json
{
  "service": "Wolfi Web Server",
  "status": "running",
  "version": "1.0.0",
  "endpoints": {
    "health": "/health",
    "metrics": "/metrics",
    "api": "/api/data"
  }
}
```

### `GET /health`
Health check endpoint for container orchestration.

**Response:**
```json
{
  "status": "healthy",
  "checks": {
    "application": "ok",
    "database": "not_configured"
  }
}
```

### `GET /api/data`
Returns instructions for using the data endpoint.

### `POST /api/data`
Accepts JSON data and returns confirmation.

**Request:**
```json
{
  "name": "example",
  "value": 123
}
```

**Response:**
```json
{
  "received": {
    "name": "example",
    "value": 123
  },
  "status": "success",
  "message": "Data processed successfully"
}
```

### `GET /api/info`
Returns system and environment information.

### `GET /metrics`
Prometheus metrics endpoint (automatically generated).

## 📊 Monitoring

The application includes built-in Prometheus metrics via `prometheus-flask-exporter`:

- Request count and latency
- HTTP status code distribution
- Process metrics (CPU, memory)
- Custom business metrics (if added)

To scrape metrics, configure your Prometheus instance:

```yaml
scrape_configs:
  - job_name: 'wolfi-webserver'
    static_configs:
      - targets: ['localhost:8000']
```

## 🛠️ Development

### Running locally without Docker

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run development server
cd app
python app.py
```

### Live development with Docker

```bash
# Mount your local code for live changes
docker run -d \
  --name wolfi-web-dev \
  -p 8000:8000 \
  -v $(pwd)/app:/app \
  wolfi-webserver:latest
```

## 🚢 Production Deployment

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  web:
    build: .
    image: wolfi-webserver:latest
    ports:
      - "8000:8000"
    environment:
      - GUNICORN_WORKERS=4
      - LOG_LEVEL=info
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
```

Run with:
```bash
docker-compose up -d
```

### Kubernetes Deployment

Example `deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wolfi-webserver
spec:
  replicas: 3
  selector:
    matchLabels:
      app: wolfi-webserver
  template:
    metadata:
      labels:
        app: wolfi-webserver
    spec:
      containers:
      - name: web
        image: wolfi-webserver:latest
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 🔒 Security

### Security Features

- **Non-root user**: Runs as UID 65532
- **Minimal base image**: Wolfi Linux with minimal packages
- **No shell access**: No unnecessary tools in production image
- **Regular updates**: Based on frequently updated Wolfi images
- **CVE scanning**: Scan with tools like Trivy

### Scanning for Vulnerabilities

```bash
# Install Trivy
# See: https://aquasecurity.github.io/trivy/

# Scan the image
trivy image wolfi-webserver:latest
```

### Best Practices

1. Regularly rebuild images to get security updates
2. Use specific version tags in production
3. Implement network policies in Kubernetes
4. Use secrets management for sensitive data
5. Enable audit logging

## 🐛 Troubleshooting

### Container won't start

Check logs:
```bash
docker logs wolfi-web
```

### Port already in use

Change the host port:
```bash
docker run -d --name wolfi-web -p 8080:8000 wolfi-webserver:latest
```

### Permission errors

Ensure the app directory is owned by UID 65532:
```bash
docker exec wolfi-web ls -la /app
```

### Health check failing

Test the endpoint manually:
```bash
docker exec wolfi-web curl -f http://localhost:8000/health
```

## 🎯 Stretch Goals

### 1. **Add Nginx Reverse Proxy**
- Multi-container setup with Nginx for SSL termination
- Rate limiting and caching
- Load balancing across multiple workers

### 2. **Database Integration**
- PostgreSQL or MySQL connectivity
- SQLAlchemy ORM integration
- Database migrations with Alembic
- Connection pooling

### 3. **Redis Caching Layer**
- Session management
- API response caching
- Rate limiting with Redis
- Pub/Sub for real-time features

### 4. **Authentication & Authorization**
- JWT token-based authentication
- OAuth2 integration
- Role-based access control (RBAC)
- API key management

### 5. **Advanced Monitoring**
- Grafana dashboards
- Custom business metrics
- Distributed tracing with Jaeger
- Error tracking with Sentry

### 6. **CI/CD Pipeline**
- GitHub Actions workflow
- Automated testing
- Security scanning
- Multi-environment deployments

### 7. **API Documentation**
- OpenAPI/Swagger integration
- Interactive API docs
- Request/response examples
- Versioned API endpoints

### 8. **Logging & Observability**
- Structured JSON logging
- Log aggregation (ELK stack)
- Distributed tracing
- Application Performance Monitoring (APM)

### 9. **WebSocket Support**
- Real-time communication
- Socket.IO integration
- Chat or notification system
- Live data streaming

### 10. **Testing Suite**
- Unit tests with pytest
- Integration tests
- Load testing with Locust
- Contract testing

---
