#!/usr/bin/env pwsh
#Requires -Version 5.1
$ErrorActionPreference = "Stop"

Write-Host "=== OWASP Scanner - Installing Required Tools ===" -ForegroundColor Cyan
Write-Host ""

function Test-Command {
    param([string]$Command)
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

function Install-NodeJS {
    if (-not (Test-Command "node")) {
        Write-Host "Installing Node.js..." -ForegroundColor Yellow
        if (Test-Command "winget") {
            winget install OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
        } elseif (Test-Command "choco") {
            choco install nodejs-lts -y
        } else {
            Write-Host "Please install Node.js manually from https://nodejs.org" -ForegroundColor Red
            Write-Host "Or install winget or chocolatey first" -ForegroundColor Red
            exit 1
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    } else {
        Write-Host "✓ Node.js is installed" -ForegroundColor Green
    }
}

function Install-Docker {
    if (-not (Test-Command "docker")) {
        Write-Host "Installing Docker Desktop..." -ForegroundColor Yellow
        if (Test-Command "winget") {
            winget install Docker.DockerDesktop --accept-source-agreements --accept-package-agreements
        } elseif (Test-Command "choco") {
            choco install docker-desktop -y
        } else {
            Write-Host "Please install Docker Desktop manually from https://www.docker.com/products/docker-desktop" -ForegroundColor Red
            exit 1
        }
        Write-Host "Docker Desktop installed. Please restart your computer and re-run this script." -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "✓ Docker is installed" -ForegroundColor Green
    }
}

function Install-Git {
    if (-not (Test-Command "git")) {
        Write-Host "Installing Git..." -ForegroundColor Yellow
        if (Test-Command "winget") {
            winget install Git.Git --accept-source-agreements --accept-package-agreements
        } elseif (Test-Command "choco") {
            choco install git -y
        } else {
            Write-Host "Please install Git manually from https://git-scm.com" -ForegroundColor Red
            exit 1
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    } else {
        Write-Host "✓ Git is installed" -ForegroundColor Green
    }
}

function Start-SonarQube {
    Write-Host ""
    Write-Host "=== Setting up SonarQube ===" -ForegroundColor Cyan
    
    $containerExists = docker ps -a --format "{{.Names}}" 2>$null | Select-String -Pattern "owasp-sonarqube" -SimpleMatch
    if ($containerExists) {
        Write-Host "SonarQube container exists, starting..."
        docker start owasp-sonarqube 2>$null
    } else {
        Write-Host "Starting SonarQube via Docker Compose..."
        docker compose up -d sonarqube
    }
    
    Write-Host ""
    Write-Host "Waiting for SonarQube to be ready..."
    for ($i = 1; $i -le 30; $i++) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:9000/api/system/status" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.Content -match '"status":"UP"') {
                Write-Host "✓ SonarQube is ready!" -ForegroundColor Green
                break
            }
        } catch {}
        Write-Host "  Attempt $i/30 - waiting..."
        Start-Sleep -Seconds 10
    }
    
    Write-Host ""
    Write-Host "SonarQube URL: http://localhost:9000"
    Write-Host "Default credentials: admin / admin"
}

function Install-NpmDeps {
    Write-Host ""
    Write-Host "=== Installing npm dependencies ===" -ForegroundColor Cyan
    npm install
    npx playwright install chromium
}

Write-Host "Checking prerequisites..."
Write-Host ""

Install-Git
Install-NodeJS
Install-Docker

Write-Host ""
Write-Host "Verifying Docker is running..."
try {
    docker info | Out-Null
    Write-Host "✓ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "Docker is not running. Please start Docker Desktop and re-run this script." -ForegroundColor Red
    exit 1
}

Start-SonarQube
Install-NpmDeps

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Create a .env file (copy from .env.example if available)"
Write-Host "  2. Generate SonarQube token at http://localhost:9000"
Write-Host "  3. Add SONARQUBE_TOKEN to .env"
Write-Host "  4. Run .\scripts\fetch-repos.ps1 to fetch source code"
Write-Host "  5. Run .\scripts\run-sast.ps1 for SAST scanning"
Write-Host "  6. Run .\scripts\run-dast.ps1 for DAST scanning"
