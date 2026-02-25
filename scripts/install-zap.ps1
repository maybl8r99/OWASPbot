#!/usr/bin/env pwsh
#Requires -Version 5.1
$ErrorActionPreference = "Stop"

Write-Host "=== OWASP ZAP Installation ===" -ForegroundColor Cyan
Write-Host ""

function Test-Command {
    param([string]$Command)
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

function Test-DockerRunning {
    try {
        $null = docker info 2>&1
        Write-Host "✓ Docker is running" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "✗ Docker is not running" -ForegroundColor Red
        Write-Host "  Please start Docker Desktop"
        return $false
    }
}

function Install-ZapDocker {
    Write-Host ""
    Write-Host "=== Installing OWASP ZAP (Docker) ===" -ForegroundColor Cyan
    
    Write-Host "Pulling ZAP Docker image..."
    docker pull zaproxy/zap-stable:latest
    
    Write-Host "✓ ZAP Docker image pulled" -ForegroundColor Green
}

function Start-Zap {
    Write-Host ""
    Write-Host "=== Starting OWASP ZAP ===" -ForegroundColor Cyan
    
    $containerExists = docker ps -a --format "{{.Names}}" 2>$null | Select-String -Pattern "owasp-zap" -SimpleMatch
    
    if ($containerExists) {
        Write-Host "ZAP container exists..."
        $containerRunning = docker ps --format "{{.Names}}" 2>$null | Select-String -Pattern "owasp-zap" -SimpleMatch
        
        if ($containerRunning) {
            Write-Host "✓ ZAP is already running" -ForegroundColor Green
        } else {
            Write-Host "Starting existing ZAP container..."
            docker start owasp-zap
        }
    } else {
        Write-Host "Creating and starting ZAP via Docker Compose..."
        docker compose up -d zap
    }
    
    Write-Host ""
    Write-Host "Waiting for ZAP to be ready (this may take 30-60 seconds)..."
    
    for ($i = 1; $i -le 60; $i++) {
        try {
            $response = Invoke-RestMethod -Uri "http://localhost:8080/JSON/core/view/version" -Method Get -TimeoutSec 5 -ErrorAction Stop
            $version = $response.version
            Write-Host "✓ ZAP is ready! (version: $version)" -ForegroundColor Green
            return
        } catch {
            # Continue waiting
        }
        
        if ($i -eq 60) {
            Write-Host "✗ ZAP did not become ready in time" -ForegroundColor Red
            Write-Host "  Check logs with: docker logs owasp-zap"
            exit 1
        }
        
        Write-Host "  Attempt $i/60 - waiting..."
        Start-Sleep -Seconds 2
    }
}

function Show-ZapInfo {
    Write-Host ""
    Write-Host "=== ZAP Installation Complete ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "ZAP API URL: http://localhost:8080"
    Write-Host "ZAP API Key: (disabled for local access)"
    Write-Host ""
    Write-Host "Run ZAP scans with:"
    Write-Host "  .\scripts\run-zap.ps1 quick     # Quick spider + active scan"
    Write-Host "  .\scripts\run-zap.ps1 full      # Full scan with AJAX spider"
    Write-Host "  .\scripts\run-zap.ps1 baseline  # Passive scan only"
    Write-Host "  .\scripts\run-zap.ps1 api       # API scan with OpenAPI"
    Write-Host ""
    Write-Host "Check ZAP status:"
    Write-Host "  .\scripts\run-zap.ps1 status"
    Write-Host ""
    Write-Host "View ZAP Web UI:"
    Write-Host "  http://localhost:8080"
    Write-Host ""
    Write-Host "Manage ZAP container:"
    Write-Host "  docker stop owasp-zap          # Stop ZAP"
    Write-Host "  docker start owasp-zap         # Start ZAP"
    Write-Host "  docker logs owasp-zap          # View ZAP logs"
    Write-Host "  docker-compose up -d zap       # Start with compose"
}

# Main
Write-Host "Checking prerequisites..."
Write-Host ""

if (-not (Test-Command "docker")) {
    Write-Host "Docker is required. Install Docker first:" -ForegroundColor Red
    Write-Host "  .\scripts\install-tools.ps1"
    exit 1
}

if (-not (Test-DockerRunning)) {
    exit 1
}

Install-ZapDocker
Start-Zap
Show-ZapInfo
