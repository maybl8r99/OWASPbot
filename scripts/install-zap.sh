#!/bin/bash
set -e

echo "=== OWASP ZAP Installation ==="
echo ""

check_command() {
    if command -v "$1" &> /dev/null; then
        echo "✓ $1 is installed"
        return 0
    else
        echo "✗ $1 is not installed"
        return 1
    fi
}

check_docker_running() {
    if ! docker info &> /dev/null; then
        echo "✗ Docker is not running"
        echo "  Please start Docker Desktop or the Docker daemon"
        return 1
    fi
    echo "✓ Docker is running"
    return 0
}

install_zap_docker() {
    echo ""
    echo "=== Installing OWASP ZAP (Docker) ==="
    
    # Pull ZAP stable image
    echo "Pulling ZAP Docker image..."
    docker pull zaproxy/zap-stable:latest
    
    echo "✓ ZAP Docker image pulled"
}

start_zap() {
    echo ""
    echo "=== Starting OWASP ZAP ==="
    
    if docker ps -a --format '{{.Names}}' | grep -q "owasp-zap"; then
        echo "ZAP container exists..."
        if docker ps --format '{{.Names}}' | grep -q "owasp-zap"; then
            echo "✓ ZAP is already running"
        else
            echo "Starting existing ZAP container..."
            docker start owasp-zap
        fi
    else
        echo "Creating and starting ZAP via Docker Compose..."
        docker compose up -d zap
    fi
    
    echo ""
    echo "Waiting for ZAP to be ready (this may take 30-60 seconds)..."
    for i in {1..60}; do
        if curl -s http://localhost:8080/JSON/core/view/version > /dev/null 2>&1; then
            VERSION=$(curl -s http://localhost:8080/JSON/core/view/version 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            echo "✓ ZAP is ready! (version: $VERSION)"
            break
        fi
        if [ $i -eq 60 ]; then
            echo "✗ ZAP did not become ready in time"
            echo "  Check logs with: docker logs owasp-zap"
            exit 1
        fi
        echo "  Attempt $i/60 - waiting..."
        sleep 2
    done
}

show_zap_info() {
    echo ""
    echo "=== ZAP Installation Complete ==="
    echo ""
    echo "ZAP API URL: http://localhost:8080"
    echo "ZAP API Key: (disabled for local access)"
    echo ""
    echo "Run ZAP scans with:"
    echo "  ./scripts/run-zap.sh quick     # Quick spider + active scan"
    echo "  ./scripts/run-zap.sh full      # Full scan with AJAX spider"
    echo "  ./scripts/run-zap.sh baseline  # Passive scan only"
    echo "  ./scripts/run-zap.sh api       # API scan with OpenAPI"
    echo ""
    echo "Check ZAP status:"
    echo "  ./scripts/run-zap.sh status"
    echo ""
    echo "View ZAP Web UI:"
    echo "  http://localhost:8080"
    echo ""
    echo "Manage ZAP container:"
    echo "  docker stop owasp-zap          # Stop ZAP"
    echo "  docker start owasp-zap         # Start ZAP"
    echo "  docker logs owasp-zap          # View ZAP logs"
    echo "  docker-compose up -d zap       # Start with compose"
}

# Main
echo "Checking prerequisites..."
echo ""

if ! check_command docker; then
    echo "Docker is required. Install Docker first:"
    echo "  ./scripts/install-tools.sh"
    exit 1
fi

if ! check_docker_running; then
    exit 1
fi

install_zap_docker
start_zap
show_zap_info
