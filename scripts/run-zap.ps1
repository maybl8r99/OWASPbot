#!/usr/bin/env pwsh
#Requires -Version 5.1
$ErrorActionPreference = "Stop"

# Store user-provided values before loading .env
$_USER_TARGET_ENDPOINT = $env:TARGET_ENDPOINT
$_USER_ZAP_API_URL = $env:ZAP_API_URL
$_USER_ZAP_FORMAT = $env:ZAP_FORMAT

if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match "^([^#][^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

# Restore user-provided values
if ($_USER_TARGET_ENDPOINT) { $env:TARGET_ENDPOINT = $_USER_TARGET_ENDPOINT }
if ($_USER_ZAP_API_URL) { $env:ZAP_API_URL = $_USER_ZAP_API_URL }
if ($_USER_ZAP_FORMAT) { $env:ZAP_FORMAT = $_USER_ZAP_FORMAT }

$TARGET_ENDPOINT = if ($env:TARGET_ENDPOINT) { $env:TARGET_ENDPOINT } else { "http://localhost:3000" }
$ZAP_API_URL = if ($env:ZAP_API_URL) { $env:ZAP_API_URL } else { "http://localhost:8080" }
$ZAP_FORMAT = if ($env:ZAP_FORMAT) { $env:ZAP_FORMAT } else { "html" }
$ZAP_REPORT_DIR = if ($env:ZAP_REPORT_DIR) { $env:ZAP_REPORT_DIR } else { "./reports/zap" }

function Show-Usage {
    Write-Host "Usage: .\scripts\run-zap.ps1 [command]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  quick     Quick scan (spider + active scan) [default]"
    Write-Host "  full      Full scan (spider + ajax spider + active scan)"
    Write-Host "  baseline  Baseline scan (passive only, no attacks)"
    Write-Host "  api       API scan (OpenAPI/Swagger)"
    Write-Host "  report    Generate report from existing session"
    Write-Host "  status    Check ZAP daemon status"
    Write-Host ""
    Write-Host "Environment Variables:"
    Write-Host "  TARGET_ENDPOINT  Target URL (default: http://localhost:3000)"
    Write-Host "  ZAP_API_URL      ZAP API URL (default: http://localhost:8080)"
    Write-Host "  ZAP_FORMAT       Report format: html, xml, json, md (default: html)"
    Write-Host "  ZAP_OPENAPI_URL  OpenAPI/Swagger URL for API scan"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\scripts\run-zap.ps1 quick                    # Quick scan"
    Write-Host "  .\scripts\run-zap.ps1 full                     # Full scan"
    Write-Host "  `$env:ZAP_FORMAT='json'; .\scripts\run-zap.ps1 quick  # JSON report"
}

function Test-Zap {
    Write-Host "Checking ZAP daemon at $ZAP_API_URL..."
    try {
        $response = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/core/view/version" -Method Get -ErrorAction Stop
        $version = $response.version
        Write-Host "✓ ZAP is running (version: $version)" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "✗ ZAP is not accessible at $ZAP_API_URL" -ForegroundColor Red
        Write-Host "  Start ZAP with: docker-compose up -d zap"
        Write-Host "  Or use ZAP desktop"
        return $false
    }
}

function Wait-ForZap {
    Write-Host "Waiting for ZAP to be ready..."
    $maxAttempts = 30
    
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $null = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/core/view/version" -Method Get -ErrorAction Stop
            Write-Host "✓ ZAP is ready" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "  Attempt $attempt/$maxAttempts..."
            Start-Sleep -Seconds 2
        }
    }
    
    Write-Host "✗ ZAP did not become ready in time" -ForegroundColor Red
    return $false
}

function Invoke-Spider {
    Write-Host "=== Starting Spider Scan ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    
    $encodedUrl = [uri]::EscapeDataString($TARGET_ENDPOINT)
    $response = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/spider/action/scan/?url=$encodedUrl&maxChildren=10&recurse=true" -Method Get
    $scanId = $response.scan
    
    if (-not $scanId) {
        Write-Host "✗ Failed to start spider" -ForegroundColor Red
        return $false
    }
    
    Write-Host "Spider started (ID: $scanId)"
    
    while ($true) {
        $statusResponse = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/spider/view/status/?scanId=$scanId" -Method Get
        $progress = $statusResponse.status
        Write-Host "  Spider progress: $progress%"
        
        if ($progress -eq "100") {
            Write-Host "✓ Spider complete" -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 3
    }
}

function Invoke-AjaxSpider {
    Write-Host "=== Starting AJAX Spider ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    
    $encodedUrl = [uri]::EscapeDataString($TARGET_ENDPOINT)
    Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/ajaxSpider/action/scan/?url=$encodedUrl&inScope=true" -Method Get | Out-Null
    
    Write-Host "AJAX Spider started"
    
    while ($true) {
        $statusResponse = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/ajaxSpider/view/status" -Method Get
        $status = $statusResponse.status
        Write-Host "  AJAX Spider status: $status"
        
        if ($status -eq "stopped") {
            Write-Host "✓ AJAX Spider complete" -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 5
    }
}

function Invoke-ActiveScan {
    Write-Host "=== Starting Active Scan ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    
    $encodedUrl = [uri]::EscapeDataString($TARGET_ENDPOINT)
    $response = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/ascan/action/scan/?url=$encodedUrl&recurse=true&inScopeOnly=false" -Method Get
    $scanId = $response.scan
    
    if (-not $scanId) {
        Write-Host "✗ Failed to start active scan" -ForegroundColor Red
        return $false
    }
    
    Write-Host "Active scan started (ID: $scanId)"
    
    while ($true) {
        $statusResponse = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/ascan/view/status/?scanId=$scanId" -Method Get
        $progress = $statusResponse.status
        Write-Host "  Active scan progress: $progress%"
        
        if ($progress -eq "100") {
            Write-Host "✓ Active scan complete" -ForegroundColor Green
            break
        }
        Start-Sleep -Seconds 5
    }
}

function Invoke-BaselineScan {
    Write-Host "=== Starting Baseline Scan (Passive) ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    
    Invoke-Spider
    Write-Host "✓ Baseline scan complete (passive findings only)" -ForegroundColor Green
}

function Invoke-ApiScan {
    Write-Host "=== Starting API Scan ===" -ForegroundColor Cyan
    
    if (-not $env:ZAP_OPENAPI_URL) {
        Write-Host "Error: ZAP_OPENAPI_URL not set" -ForegroundColor Red
        Write-Host "  Set it in .env or environment, e.g.:"
        Write-Host "  `$env:ZAP_OPENAPI_URL='http://localhost:3000/api-docs'"
        return $false
    }
    
    Write-Host "OpenAPI URL: $($env:ZAP_OPENAPI_URL)"
    Write-Host "Target: $TARGET_ENDPOINT"
    
    $encodedOpenApiUrl = [uri]::EscapeDataString($env:ZAP_OPENAPI_URL)
    $importResponse = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/openapi/action/importUrl/?url=$encodedOpenApiUrl" -Method Get
    
    if ($importResponse.result -eq "OK") {
        Write-Host "✓ OpenAPI imported successfully" -ForegroundColor Green
    } else {
        Write-Host "⚠ OpenAPI import may have issues" -ForegroundColor Yellow
    }
    
    Invoke-ActiveScan
}

function Export-Report {
    Write-Host "=== Generating ZAP Report ===" -ForegroundColor Cyan
    
    New-Item -ItemType Directory -Force -Path $ZAP_REPORT_DIR | Out-Null
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = Join-Path $ZAP_REPORT_DIR "zap-report-$timestamp.$ZAP_FORMAT"
    
    switch ($ZAP_FORMAT) {
        "html" {
            Invoke-RestMethod -Uri "$ZAP_API_URL/OTHER/core/other/htmlreport" -Method Get -OutFile $reportFile
        }
        "xml" {
            Invoke-RestMethod -Uri "$ZAP_API_URL/OTHER/core/other/xmlreport" -Method Get -OutFile $reportFile
        }
        "json" {
            Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/core/view/alerts" -Method Get -OutFile $reportFile
        }
        "md" {
            Invoke-RestMethod -Uri "$ZAP_API_URL/OTHER/core/other/mdreport" -Method Get -OutFile $reportFile
        }
        default {
            Write-Host "Unknown format: $ZAP_FORMAT" -ForegroundColor Red
            return $false
        }
    }
    
    if (Test-Path $reportFile) {
        Write-Host "✓ Report saved: $reportFile" -ForegroundColor Green
        
        # Show summary
        $alertsResponse = Invoke-RestMethod -Uri "$ZAP_API_URL/JSON/core/view/alerts" -Method Get
        $alerts = $alertsResponse.alerts
        $high = ($alerts | Where-Object { $_.riskcode -eq "3" }).Count
        $medium = ($alerts | Where-Object { $_.riskcode -eq "2" }).Count
        $low = ($alerts | Where-Object { $_.riskcode -eq "1" }).Count
        $info = ($alerts | Where-Object { $_.riskcode -eq "0" }).Count
        
        Write-Host ""
        Write-Host "Scan Summary:"
        Write-Host "  Total Alerts: $($alerts.Count)"
        Write-Host "  High Risk: $high" -ForegroundColor Red
        Write-Host "  Medium Risk: $medium" -ForegroundColor Yellow
        Write-Host "  Low Risk: $low" -ForegroundColor Green
        Write-Host "  Informational: $info"
    } else {
        Write-Host "✗ Failed to generate report" -ForegroundColor Red
        return $false
    }
}

function Invoke-QuickScan {
    if (-not (Test-Zap)) {
        exit 1
    }
    
    Write-Host "=== ZAP Quick Scan ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    Write-Host ""
    
    Invoke-Spider
    Invoke-ActiveScan
    Export-Report
    
    Write-Host ""
    Write-Host "=== Quick Scan Complete ===" -ForegroundColor Green
    Write-Host "View report in: $ZAP_REPORT_DIR"
}

function Invoke-FullScan {
    if (-not (Test-Zap)) {
        exit 1
    }
    
    Write-Host "=== ZAP Full Scan ===" -ForegroundColor Cyan
    Write-Host "Target: $TARGET_ENDPOINT"
    Write-Host ""
    
    Invoke-Spider
    Invoke-AjaxSpider
    Invoke-ActiveScan
    Export-Report
    
    Write-Host ""
    Write-Host "=== Full Scan Complete ===" -ForegroundColor Green
    Write-Host "View report in: $ZAP_REPORT_DIR"
}

$command = if ($args[0]) { $args[0] } else { "quick" }

switch ($command) {
    "quick" { Invoke-QuickScan }
    "full" { Invoke-FullScan }
    "baseline" {
        if (-not (Test-Zap)) { exit 1 }
        Invoke-BaselineScan
        Export-Report
    }
    "api" {
        if (-not (Test-Zap)) { exit 1 }
        Invoke-ApiScan
        Export-Report
    }
    "report" { Export-Report }
    "status" { Test-Zap }
    { $_ -in "help", "--help", "-h" } { Show-Usage }
    default {
        Write-Host "Unknown command: $command" -ForegroundColor Red
        Write-Host ""
        Show-Usage
        exit 1
    }
}
