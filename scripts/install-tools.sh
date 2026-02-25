#!/bin/bash
set -e

echo "=== OWASP Scanner - Installing Required Tools ==="
echo ""

detect_os() {
    case "$(uname -s)" in
        Darwin*)    echo "macos" ;;
        Linux*)     echo "linux" ;;
        *)          echo "unknown" ;;
    esac
}

OS=$(detect_os)

check_command() {
    if command -v "$1" &> /dev/null; then
        echo "✓ $1 is installed"
        return 0
    else
        echo "✗ $1 is not installed"
        return 1
    fi
}

install_homebrew() {
    if ! check_command brew; then
        echo "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
}

install_node() {
    if ! check_command node; then
        echo "Installing Node.js..."
        if [ "$OS" = "macos" ]; then
            brew install node
        elif [ "$OS" = "linux" ]; then
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
            sudo apt-get install -y nodejs
        fi
    fi
}

install_docker() {
    if ! check_command docker; then
        echo "Installing Docker..."
        if [ "$OS" = "macos" ]; then
            brew install --cask docker
            echo "Please open Docker Desktop and complete the setup, then re-run this script"
            exit 1
        elif [ "$OS" = "linux" ]; then
            curl -fsSL https://get.docker.com | sudo sh
            sudo usermod -aG docker "$USER"
            echo "Docker installed. You may need to log out and back in for group changes to take effect."
        fi
    fi
}

install_git() {
    if ! check_command git; then
        echo "Installing Git..."
        if [ "$OS" = "macos" ]; then
            brew install git
        elif [ "$OS" = "linux" ]; then
            sudo apt-get update && sudo apt-get install -y git
        fi
    fi
}

start_sonarqube() {
    echo ""
    echo "=== Setting up SonarQube ==="
    
    if docker ps -a --format '{{.Names}}' | grep -q "owasp-sonarqube"; then
        echo "SonarQube container exists, starting..."
        docker start owasp-sonarqube 2>/dev/null || true
    else
        echo "Starting SonarQube via Docker Compose..."
        docker compose up -d sonarqube
    fi
    
    echo ""
    echo "Waiting for SonarQube to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:9000/api/system/status | grep -q "UP"; then
            echo "✓ SonarQube is ready!"
            break
        fi
        echo "  Attempt $i/30 - waiting..."
        sleep 10
    done
    
    echo ""
    echo "SonarQube URL: http://localhost:9000"
    echo "Default credentials: admin / admin"
}

install_npm_deps() {
    echo ""
    echo "=== Installing npm dependencies ==="
    npm install
    npx playwright install chromium
}

echo "Checking prerequisites..."
echo ""

if [ "$OS" = "macos" ]; then
    install_homebrew
fi

install_git
install_node
install_docker

echo ""
echo "Verifying Docker is running..."
if ! docker info &> /dev/null; then
    echo "Docker is not running. Please start Docker and re-run this script."
    if [ "$OS" = "macos" ]; then
        echo "Open Docker Desktop from your Applications folder."
    fi
    exit 1
fi
echo "✓ Docker is running"

start_sonarqube
install_npm_deps

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Create a .env file (copy from .env.example if available)"
echo "  2. Generate SonarQube token at http://localhost:9000"
echo "  3. Add SONARQUBE_TOKEN to .env"
echo "  4. Run ./scripts/fetch-repos.sh to fetch source code"
echo "  5. Run ./scripts/run-sast.sh for SAST scanning"
echo "  6. Run ./scripts/run-dast.sh for DAST scanning"
