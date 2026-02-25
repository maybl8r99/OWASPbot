#!/bin/bash
set -e

# Store user-provided values before sourcing .env
_USER_TARGET_ENDPOINT=${TARGET_ENDPOINT:-}
_USER_ZAP_API_URL=${ZAP_API_URL:-}
_USER_ZAP_FORMAT=${ZAP_FORMAT:-}

set -a
source .env 2>/dev/null || true
set +a

# Restore user-provided values
[ -n "$_USER_TARGET_ENDPOINT" ] && TARGET_ENDPOINT=$_USER_TARGET_ENDPOINT
[ -n "$_USER_ZAP_API_URL" ] && ZAP_API_URL=$_USER_ZAP_API_URL
[ -n "$_USER_ZAP_FORMAT" ] && ZAP_FORMAT=$_USER_ZAP_FORMAT

# Apply defaults
TARGET_ENDPOINT=${TARGET_ENDPOINT:-http://localhost:3000}
ZAP_API_URL=${ZAP_API_URL:-http://localhost:8080}
ZAP_FORMAT=${ZAP_FORMAT:-html}
ZAP_REPORT_DIR=${ZAP_REPORT_DIR:-./reports/zap}

show_usage() {
    echo "Usage: ./scripts/run-zap.sh [command]"
    echo ""
    echo "Commands:"
    echo "  quick     Quick scan (spider + active scan) [default]"
    echo "  full      Full scan (spider + ajax spider + active scan)"
    echo "  baseline  Baseline scan (passive only, no attacks)"
    echo "  api       API scan (OpenAPI/Swagger)"
    echo "  report    Generate report from existing session"
    echo "  status    Check ZAP daemon status"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET_ENDPOINT  Target URL (default: http://localhost:3000)"
    echo "  ZAP_API_URL      ZAP API URL (default: http://localhost:8080)"
    echo "  ZAP_FORMAT       Report format: html, xml, json, md (default: html)"
    echo "  ZAP_OPENAPI_URL  OpenAPI/Swagger URL for API scan"
    echo ""
    echo "Examples:"
    echo "  ./scripts/run-zap.sh quick                    # Quick scan"
    echo "  ./scripts/run-zap.sh full                     # Full scan"
    echo "  ZAP_FORMAT=json ./scripts/run-zap.sh quick    # JSON report"
}

check_zap() {
    echo "Checking ZAP daemon at $ZAP_API_URL..."
    if curl -s "$ZAP_API_URL/JSON/core/view/version" > /dev/null 2>&1; then
        VERSION=$(curl -s "$ZAP_API_URL/JSON/core/view/version" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
        echo "✓ ZAP is running (version: $VERSION)"
        return 0
    else
        echo "✗ ZAP is not accessible at $ZAP_API_URL"
        echo "  Start ZAP with: docker-compose up -d zap"
        echo "  Or use ZAP desktop"
        return 1
    fi
}

wait_for_zap() {
    echo "Waiting for ZAP to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s "$ZAP_API_URL/JSON/core/view/version" > /dev/null 2>&1; then
            echo "✓ ZAP is ready"
            return 0
        fi
        echo "  Attempt $attempt/$max_attempts..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo "✗ ZAP did not become ready in time"
    return 1
}

run_spider() {
    echo "=== Starting Spider Scan ==="
    echo "Target: $TARGET_ENDPOINT"
    
    # Start spider
    SPIDER_RESPONSE=$(curl -s "$ZAP_API_URL/JSON/spider/action/scan/?url=$TARGET_ENDPOINT&maxChildren=10&recurse=true")
    SCAN_ID=$(echo "$SPIDER_RESPONSE" | grep -o '"scan":[0-9]*' | cut -d':' -f2)
    
    if [ -z "$SCAN_ID" ]; then
        echo "✗ Failed to start spider"
        return 1
    fi
    
    echo "Spider started (ID: $SCAN_ID)"
    
    # Wait for spider to complete
    while true; do
        STATUS=$(curl -s "$ZAP_API_URL/JSON/spider/view/status/?scanId=$SCAN_ID" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        PROGRESS=$(curl -s "$ZAP_API_URL/JSON/spider/view/status/?scanId=$SCAN_ID" | grep -o '"status":[0-9]*' | cut -d':' -f2)
        echo "  Spider progress: ${PROGRESS:-0}%"
        
        if [ "$STATUS" = "100" ] || [ "$PROGRESS" = "100" ]; then
            echo "✓ Spider complete"
            break
        fi
        sleep 3
    done
    
    # Show spider results
    URLS_FOUND=$(curl -s "$ZAP_API_URL/JSON/spider/view/results/?scanId=$SCAN_ID" | grep -o '"results":\[' | wc -l)
    echo "URLs found: $URLS_FOUND"
}

run_ajax_spider() {
    echo "=== Starting AJAX Spider ==="
    echo "Target: $TARGET_ENDPOINT"
    
    # Start AJAX spider
    curl -s "$ZAP_API_URL/JSON/ajaxSpider/action/scan/?url=$TARGET_ENDPOINT&inScope=true&scanId=$SCAN_ID" > /dev/null
    
    echo "AJAX Spider started"
    
    # Wait for AJAX spider to complete
    while true; do
        STATUS=$(curl -s "$ZAP_API_URL/JSON/ajaxSpider/view/status" | grep -o '"status":"[^"]*""' | cut -d'"' -f4)
        echo "  AJAX Spider status: ${STATUS:-running}"
        
        if [ "$STATUS" = "stopped" ]; then
            echo "✓ AJAX Spider complete"
            break
        fi
        sleep 5
    done
}

run_active_scan() {
    echo "=== Starting Active Scan ==="
    echo "Target: $TARGET_ENDPOINT"
    
    # Start active scan
    SCAN_RESPONSE=$(curl -s "$ZAP_API_URL/JSON/ascan/action/scan/?url=$TARGET_ENDPOINT&recurse=true&inScopeOnly=false")
    SCAN_ID=$(echo "$SCAN_RESPONSE" | grep -o '"scan":[0-9]*' | cut -d':' -f2)
    
    if [ -z "$SCAN_ID" ]; then
        echo "✗ Failed to start active scan"
        return 1
    fi
    
    echo "Active scan started (ID: $SCAN_ID)"
    
    # Wait for active scan to complete
    while true; do
        PROGRESS=$(curl -s "$ZAP_API_URL/JSON/ascan/view/status/?scanId=$SCAN_ID" | grep -o '"status":"[0-9]*"' | grep -o '[0-9]*')
        echo "  Active scan progress: ${PROGRESS:-0}%"
        
        if [ "$PROGRESS" = "100" ]; then
            echo "✓ Active scan complete"
            break
        fi
        sleep 5
    done
}

run_baseline_scan() {
    echo "=== Starting Baseline Scan (Passive) ==="
    echo "Target: $TARGET_ENDPOINT"
    
    # Spider only (no active scanning)
    run_spider
    
    echo "✓ Baseline scan complete (passive findings only)"
}

run_api_scan() {
    echo "=== Starting API Scan ==="
    
    if [ -z "$ZAP_OPENAPI_URL" ]; then
        echo "Error: ZAP_OPENAPI_URL not set"
    echo "  Set it in .env or environment, e.g.:"
    echo "  ZAP_OPENAPI_URL=http://localhost:3000/api-docs"
        return 1
    fi
    
    echo "OpenAPI URL: $ZAP_OPENAPI_URL"
    echo "Target: $TARGET_ENDPOINT"
    
    # Import OpenAPI
    IMPORT_RESPONSE=$(curl -s "$ZAP_API_URL/JSON/openapi/action/importUrl/?url=$ZAP_OPENAPI_URL")
    
    if echo "$IMPORT_RESPONSE" | grep -q '"result":"OK"'; then
        echo "✓ OpenAPI imported successfully"
    else
        echo "⚠ OpenAPI import may have issues: $IMPORT_RESPONSE"
    fi
    
    # Run active scan on API endpoints
    run_active_scan
}

generate_report() {
    echo "=== Generating ZAP Report ==="
    
    mkdir -p "$ZAP_REPORT_DIR"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="$ZAP_REPORT_DIR/zap-report-$timestamp.$ZAP_FORMAT"
    
    case "$ZAP_FORMAT" in
        html)
            curl -s "$ZAP_API_URL/OTHER/core/other/htmlreport" -o "$report_file"
            ;;
        xml)
            curl -s "$ZAP_API_URL/OTHER/core/other/xmlreport" -o "$report_file"
            ;;
        json)
            curl -s "$ZAP_API_URL/JSON/core/view/alerts" -o "$report_file"
            ;;
        md)
            curl -s "$ZAP_API_URL/OTHER/core/other/mdreport" -o "$report_file"
            ;;
        *)
            echo "Unknown format: $ZAP_FORMAT"
            return 1
            ;;
    esac
    
    if [ -f "$report_file" ]; then
        echo "✓ Report saved: $report_file"
        
        # Show summary
        ALERTS=$(curl -s "$ZAP_API_URL/JSON/core/view/alerts" | grep -o '"riskcode":"[0-9]*"' | wc -l)
        HIGH=$(curl -s "$ZAP_API_URL/JSON/core/view/alerts/?riskId=3" | grep -o '"riskcode":"3"' | wc -l)
        MEDIUM=$(curl -s "$ZAP_API_URL/JSON/core/view/alerts/?riskId=2" | grep -o '"riskcode":"2"' | wc -l)
        LOW=$(curl -s "$ZAP_API_URL/JSON/core/view/alerts/?riskId=1" | grep -o '"riskcode":"1"' | wc -l)
        
        echo ""
        echo "Scan Summary:"
        echo "  Total Alerts: $ALERTS"
        echo "  High Risk: $HIGH"
        echo "  Medium Risk: $MEDIUM"
        echo "  Low Risk: $LOW"
    else
        echo "✗ Failed to generate report"
        return 1
    fi
}

do_quick_scan() {
    if ! check_zap; then
        exit 1
    fi
    
    echo "=== ZAP Quick Scan ==="
    echo "Target: $TARGET_ENDPOINT"
    echo ""
    
    run_spider
    run_active_scan
    generate_report
    
    echo ""
    echo "=== Quick Scan Complete ==="
    echo "View report in: $ZAP_REPORT_DIR"
}

do_full_scan() {
    if ! check_zap; then
        exit 1
    fi
    
    echo "=== ZAP Full Scan ==="
    echo "Target: $TARGET_ENDPOINT"
    echo ""
    
    run_spider
    run_ajax_spider
    run_active_scan
    generate_report
    
    echo ""
    echo "=== Full Scan Complete ==="
    echo "View report in: $ZAP_REPORT_DIR"
}

case "${1:-quick}" in
    quick)
        do_quick_scan
        ;;
    full)
        do_full_scan
        ;;
    baseline)
        if ! check_zap; then
            exit 1
        fi
        run_baseline_scan
        generate_report
        ;;
    api)
        if ! check_zap; then
            exit 1
        fi
        run_api_scan
        generate_report
        ;;
    report)
        generate_report
        ;;
    status)
        check_zap
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
