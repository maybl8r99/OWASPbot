#!/usr/bin/env pwsh
#Requires -Version 5.1
$ErrorActionPreference = "Stop"

# Store user-provided values before loading .env (env vars should override .env)
$_USER_TARGET_ENDPOINT = $env:TARGET_ENDPOINT
$_USER_HEADLESS = $env:HEADLESS
$_USER_SKIP_AUTH = $env:SKIP_AUTH

if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match "^([^#][^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

# Restore user-provided values if they were set (override .env)
if ($_USER_TARGET_ENDPOINT) { $env:TARGET_ENDPOINT = $_USER_TARGET_ENDPOINT }
if ($_USER_HEADLESS) { $env:HEADLESS = $_USER_HEADLESS }
if ($_USER_SKIP_AUTH) { $env:SKIP_AUTH = $_USER_SKIP_AUTH }

$TARGET_ENDPOINT = if ($env:TARGET_ENDPOINT) { $env:TARGET_ENDPOINT } else { "http://localhost:3000" }
$HEADLESS = if ($env:HEADLESS) { $env:HEADLESS } else { "true" }
$SKIP_AUTH = if ($env:SKIP_AUTH) { $env:SKIP_AUTH } else { "false" }
$AUTH_FILE = "dast/.auth/user.json"

function Show-Usage {
    Write-Host "Usage: .\scripts\run-dast.ps1 [command]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  scan      Run DAST scan (default)"
    Write-Host "  auth      Authenticate manually (opens browser for login)"
    Write-Host "  status    Show authentication status"
    Write-Host "  clear     Clear stored authentication"
    Write-Host ""
    Write-Host "Environment Variables:"
    Write-Host "  TARGET_ENDPOINT  Target URL (default: http://localhost:3000)"
    Write-Host "  HEADLESS         Run headless (true/false, default: true)"
    Write-Host "  SKIP_AUTH        Skip authentication requirement (true/false)"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\scripts\run-dast.ps1 auth        # Login manually first"
    Write-Host "  .\scripts\run-dast.ps1 scan        # Run scan with saved auth"
    Write-Host "  `$env:HEADLESS='false'; .\scripts\run-dast.ps1 scan  # Scan with visible browser"
}

function Test-Auth {
    if (Test-Path $AUTH_FILE) {
        $fileTime = (Get-Item $AUTH_FILE).LastWriteTime
        $age = [Math]::Floor(((Get-Date) - $fileTime).TotalMinutes)
        Write-Host "✓ Authentication found ($age minutes old)" -ForegroundColor Green
        Write-Host "  File: $AUTH_FILE"
        return $true
    } else {
        Write-Host "✗ No authentication found" -ForegroundColor Red
        Write-Host "  Run: .\scripts\run-dast.ps1 auth"
        return $false
    }
}

function Invoke-Auth {
    Write-Host "=== Manual Authentication ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    Write-Host ""
    
    if (-not (Test-Path node_modules)) {
        Write-Host "Installing dependencies..."
        npm install
        npx playwright install chromium
    }
    
    node scripts/auth-setup.mjs
}

function Invoke-Scan {
    Write-Host "=== DAST Security Scan ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    Write-Host "Headless: $HEADLESS"
    
    if ($SKIP_AUTH -eq "true") {
        Write-Host "Auth: Skipped (SKIP_AUTH=true)"
    } elseif (Test-Path $AUTH_FILE) {
        $fileTime = (Get-Item $AUTH_FILE).LastWriteTime
        $age = [Math]::Floor(((Get-Date) - $fileTime).TotalMinutes)
        Write-Host "Auth: Using stored credentials ($age min old)"
    } else {
        Write-Host "Auth: Not found - will prompt for login"
    }
    Write-Host ""
    
    if (-not (Test-Path node_modules)) {
        Write-Host "Installing dependencies..."
        npm install
        npx playwright install chromium
    }
    
    Write-Host "Running DAST tests..."
    Write-Host ""
    
    if ($HEADLESS -eq "false") {
        npm run dast:headed
    } else {
        npm run dast
    }
    
    Write-Host ""
    Write-Host "=== DAST Scan Complete ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "View report: npm run dast:report"
    Write-Host "Report location: reports/dast-report/index.html"
}

function Clear-Auth {
    if (Test-Path $AUTH_FILE) {
        Remove-Item $AUTH_FILE
        Write-Host "✓ Authentication cleared" -ForegroundColor Green
    } else {
        Write-Host "No authentication to clear"
    }
}

$command = if ($args[0]) { $args[0] } else { "scan" }

switch ($command) {
    "scan" { Invoke-Scan }
    { $_ -in "auth", "login" } { Invoke-Auth }
    "status" {
        Write-Host "=== Authentication Status ===" -ForegroundColor Cyan
        Test-Auth
    }
    { $_ -in "clear", "logout" } { Clear-Auth }
    { $_ -in "help", "--help", "-h" } { Show-Usage }
    default {
        Write-Host "Unknown command: $command" -ForegroundColor Red
        Write-Host ""
        Show-Usage
        exit 1
    }
}
