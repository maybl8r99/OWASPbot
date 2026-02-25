#!/bin/bash
set -e

# Store user-provided values before sourcing .env (env vars should override .env)
_USER_TARGET_ENDPOINT=${TARGET_ENDPOINT:-}
_USER_HEADLESS=${HEADLESS:-}
_USER_SKIP_AUTH=${SKIP_AUTH:-}

set -a
source .env 2>/dev/null || true
set +a

# Restore user-provided values if they were set (override .env)
[ -n "$_USER_TARGET_ENDPOINT" ] && TARGET_ENDPOINT=$_USER_TARGET_ENDPOINT
[ -n "$_USER_HEADLESS" ] && HEADLESS=$_USER_HEADLESS
[ -n "$_USER_SKIP_AUTH" ] && SKIP_AUTH=$_USER_SKIP_AUTH

# Apply defaults only if still not set
TARGET_ENDPOINT=${TARGET_ENDPOINT:-http://localhost:3000}
HEADLESS=${HEADLESS:-true}
SKIP_AUTH=${SKIP_AUTH:-false}
AUTH_FILE="dast/.auth/user.json"

show_usage() {
    echo "Usage: ./scripts/run-dast.sh [command]"
    echo ""
    echo "Commands:"
    echo "  scan      Run DAST scan (default)"
    echo "  auth      Authenticate manually (opens browser for login)"
    echo "  status    Show authentication status"
    echo "  clear     Clear stored authentication"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_ENDPOINT  Target URL (default: http://localhost:3000)"
    echo "  HEADLESS         Run headless (true/false, default: true)"
    echo "  SKIP_AUTH        Skip authentication requirement (true/false)"
    echo ""
    echo "Examples:"
    echo "  ./scripts/run-dast.sh auth        # Login manually first"
    echo "  ./scripts/run-dast.sh scan        # Run scan with saved auth"
    echo "  HEADLESS=false ./scripts/run-dast.sh scan  # Scan with visible browser"
}

check_auth() {
    if [ -f "$AUTH_FILE" ]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            AGE=$(( ($(date +%s) - $(stat -f %m "$AUTH_FILE")) / 60 ))
        else
            AGE=$(( ($(date +%s) - $(stat -c %Y "$AUTH_FILE")) / 60 ))
        fi
        echo "✓ Authentication found (${AGE} minutes old)"
        echo "  File: $AUTH_FILE"
        return 0
    else
        echo "✗ No authentication found"
        echo "  Run: ./scripts/run-dast.sh auth"
        return 1
    fi
}

do_auth() {
    echo "=== Manual Authentication ==="
    echo "Target: $TARGET_ENDPOINT"
    echo ""
    
    if [ ! -d "node_modules" ]; then
        echo "Installing dependencies..."
        npm install
        npx playwright install chromium
    fi
    
    node scripts/auth-setup.mjs
}

do_scan() {
    echo "=== DAST Security Scan ==="
    echo "Target: $TARGET_ENDPOINT"
    echo "Headless: $HEADLESS"
    
    if [ "$SKIP_AUTH" = "true" ]; then
        echo "Auth: Skipped (SKIP_AUTH=true)"
    elif [ -f "$AUTH_FILE" ]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            AGE=$(( ($(date +%s) - $(stat -f %m "$AUTH_FILE")) / 60 ))
        else
            AGE=$(( ($(date +%s) - $(stat -c %Y "$AUTH_FILE")) / 60 ))
        fi
        echo "Auth: Using stored credentials (${AGE} min old)"
    else
        echo "Auth: Not found - will prompt for login"
    fi
    echo ""
    
    if [ ! -d "node_modules" ]; then
        echo "Installing dependencies..."
        npm install
        npx playwright install chromium
    fi
    
    echo "Running DAST tests..."
    echo ""
    
    if [ "$HEADLESS" = "false" ]; then
        npm run dast:headed
    else
        npm run dast
    fi
    
    echo ""
    echo "=== DAST Scan Complete ==="
    echo ""
    echo "View report: npm run dast:report"
    echo "Report location: reports/dast-report/index.html"
}

do_clear() {
    if [ -f "$AUTH_FILE" ]; then
        rm "$AUTH_FILE"
        echo "✓ Authentication cleared"
    else
        echo "No authentication to clear"
    fi
}

case "${1:-scan}" in
    scan)
        do_scan
        ;;
    auth|login)
        do_auth
        ;;
    status)
        echo "=== Authentication Status ==="
        check_auth
        ;;
    clear|logout)
        do_clear
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac
