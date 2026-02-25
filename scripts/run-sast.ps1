#!/usr/bin/env pwsh
#Requires -Version 5.1
$ErrorActionPreference = "Stop"

if (Test-Path .env) {
    Get-Content .env | ForEach-Object {
        if ($_ -match "^([^#][^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
}

$SAST_TOOL = if ($env:SAST_TOOL) { $env:SAST_TOOL } else { "sonarqube" }
$SOURCE_CODE_PATH = if ($env:SOURCE_CODE_PATH) { $env:SOURCE_CODE_PATH } else { "./source_code" }

if (-not (Test-Path $SOURCE_CODE_PATH) -or -not (Get-ChildItem $SOURCE_CODE_PATH -ErrorAction SilentlyContinue)) {
    Write-Host "Error: No source code found in $SOURCE_CODE_PATH" -ForegroundColor Red
    Write-Host "Run .\scripts\fetch-repos.ps1 first"
    exit 1
}

Write-Host "=== Running SAST with $SAST_TOOL ===" -ForegroundColor Cyan

if ($SAST_TOOL -eq "sonarqube") {
    if (-not $env:SONARQUBE_TOKEN) {
        Write-Host "Error: SONARQUBE_TOKEN not set in .env" -ForegroundColor Red
        Write-Host "Generate token at http://localhost:9000"
        exit 1
    }
    
    $SONAR_PROJECT_KEY = if ($env:SONAR_PROJECT_KEY) { $env:SONAR_PROJECT_KEY } else { "my-project" }
    $SONARQUBE_URL = if ($env:SONARQUBE_URL) { $env:SONARQUBE_URL } else { "http://localhost:9000" }
    $SONARQUBE_URL = $SONARQUBE_URL -replace "localhost", "host.docker.internal"
    $SONAR_EXCLUSIONS = if ($env:SONAR_EXCLUSIONS) { $env:SONAR_EXCLUSIONS } else { "**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/vendor/**" }
    
    $sourcePath = (Resolve-Path $SOURCE_CODE_PATH).Path
    
    docker run --rm `
        --add-host=host.docker.internal:host-gateway `
        -v "${sourcePath}:/usr/src" `
        sonarsource/sonar-scanner-cli `
        -Dsonar.projectKey=$SONAR_PROJECT_KEY `
        -Dsonar.sources=. `
        -Dsonar.host.url=$SONARQUBE_URL `
        -Dsonar.token=$env:SONARQUBE_TOKEN `
        "-Dsonar.exclusions=$SONAR_EXCLUSIONS"
    
    Write-Host ""
    Write-Host "=== Scan complete. View results at $SONARQUBE_URL ===" -ForegroundColor Green

} elseif ($SAST_TOOL -eq "semgrep") {
    $SEMGREP_RULES = if ($env:SEMGREP_RULES) { $env:SEMGREP_RULES } else { "p/ci,p/security-audit,p/owasp-top-ten" }
    
    $sourcePath = (Resolve-Path $SOURCE_CODE_PATH).Path
    
    docker run --rm `
        -v "${sourcePath}:/src" `
        semgrep/semgrep `
        semgrep --config auto --config $SEMGREP_RULES --json > reports/scan-results/semgrep-report.json
    
    Write-Host ""
    Write-Host "=== Results saved to reports/scan-results/semgrep-report.json ===" -ForegroundColor Green
}
