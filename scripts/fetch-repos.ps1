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

$SOURCE_CODE_PATH = if ($env:SOURCE_CODE_PATH) { $env:SOURCE_CODE_PATH } else { "./source_code" }
$REPO_BRANCH = if ($env:REPO_BRANCH) { $env:REPO_BRANCH } else { "main" }

New-Item -ItemType Directory -Force -Path $SOURCE_CODE_PATH | Out-Null

Write-Host "=== Repository Authentication ===" -ForegroundColor Cyan
Write-Host "For Azure DevOps: Username can be anything, Password = Personal Access Token (PAT)"
Write-Host "Press Enter twice for no authentication"
Write-Host ""

$AUTH_USERNAME = Read-Host "Username (blank for no auth)"
$AUTH_PASSWORD_SECURE = Read-Host "Password/PAT (blank for no auth)" -AsSecureString
$AUTH_PASSWORD_PLAIN = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AUTH_PASSWORD_SECURE))

if ([string]::IsNullOrWhiteSpace($AUTH_USERNAME) -and [string]::IsNullOrWhiteSpace($AUTH_PASSWORD_PLAIN)) {
    Write-Host "Proceeding without authentication..."
    $REPO_AUTH = $false
} else {
    $REPO_AUTH = $true
}

Write-Host ""
Write-Host "=== Fetching Repositories ===" -ForegroundColor Cyan

function Invoke-FetchRepo {
    param(
        [string]$Name,
        [string]$Url
    )
    
    $targetDir = Join-Path $SOURCE_CODE_PATH $Name
    $cloneUrl = $Url
    
    if ($REPO_AUTH) {
        $cloneUrl = $Url -replace "https://", "https://${AUTH_USERNAME}:$([uri]::EscapeDataString($AUTH_PASSWORD_PLAIN))@"
    }
    
    if (Test-Path $targetDir) {
        Write-Host "Updating $Name..."
        Push-Location $targetDir
        
        if ($REPO_AUTH) {
            git remote set-url origin $cloneUrl
        }
        
        git fetch origin
        git checkout $REPO_BRANCH 2>$null
        if ($LASTEXITCODE -ne 0) {
            git checkout -b $REPO_BRANCH origin/$REPO_BRANCH 2>$null
        }
        git reset --hard origin/$REPO_BRANCH 2>$null
        
        Pop-Location
    } else {
        Write-Host "Cloning $Name..."
        git clone --branch $REPO_BRANCH $cloneUrl $targetDir
        
        Push-Location $targetDir
        git remote set-url origin $Url
        Pop-Location
    }
}

if ($env:REPO_FRONTEND) {
    Invoke-FetchRepo -Name "repo-frontend" -Url $env:REPO_FRONTEND
}

if ($env:REPO_API) {
    Invoke-FetchRepo -Name "repo-api" -Url $env:REPO_API
}

if ($env:REPO_SHARED) {
    Invoke-FetchRepo -Name "repo-shared" -Url $env:REPO_SHARED
}

if ($env:REPO_URLS) {
    $urls = $env:REPO_URLS -split "\s+"
    foreach ($url in $urls) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($url)
        Invoke-FetchRepo -Name $name -Url $url
    }
}

Write-Host ""
Write-Host "=== Repositories ready in $SOURCE_CODE_PATH ===" -ForegroundColor Green
Get-ChildItem $SOURCE_CODE_PATH
