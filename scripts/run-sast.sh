#!/bin/bash
set -e

source .env 2>/dev/null || true

SAST_TOOL=${SAST_TOOL:-sonarqube}
SOURCE_CODE_PATH=${SOURCE_CODE_PATH:-./source_code}

if [ ! -d "$SOURCE_CODE_PATH" ] || [ -z "$(ls -A $SOURCE_CODE_PATH 2>/dev/null)" ]; then
    echo "Error: No source code found in $SOURCE_CODE_PATH"
    echo "Run ./scripts/fetch-repos.sh first"
    exit 1
fi

echo "=== Running SAST with $SAST_TOOL ==="

if [ "$SAST_TOOL" = "sonarqube" ]; then
    if [ -z "$SONARQUBE_TOKEN" ]; then
        echo "Error: SONARQUBE_TOKEN not set in .env"
        echo "Generate token at http://localhost:9000"
        exit 1
    fi
    
    SONAR_PROJECT_KEY=${SONAR_PROJECT_KEY:-my-project}
    SONARQUBE_URL=${SONARQUBE_URL:-http://localhost:9000}
    SONARQUBE_URL=${SONARQUBE_URL//localhost/host.docker.internal}
    SONAR_EXCLUSIONS=${SONAR_EXCLUSIONS:-"**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/vendor/**"}
    
    docker run --rm \
        --add-host=host.docker.internal:host-gateway \
        -v "$(cd $SOURCE_CODE_PATH && pwd)":/usr/src \
        sonarsource/sonar-scanner-cli \
        -Dsonar.projectKey=$SONAR_PROJECT_KEY \
        -Dsonar.sources=. \
        -Dsonar.host.url=$SONARQUBE_URL \
        -Dsonar.token=$SONARQUBE_TOKEN \
        -Dsonar.exclusions="$SONAR_EXCLUSIONS"
    
    echo ""
    echo "=== Scan complete. View results at $SONARQUBE_URL ==="

elif [ "$SAST_TOOL" = "semgrep" ]; then
    SEMGREP_RULES=${SEMGREP_RULES:-"p/ci,p/security-audit,p/owasp-top-ten"}
    
    docker run --rm \
        -v "$(cd $SOURCE_CODE_PATH && pwd)":/src \
        semgrep/semgrep \
        semgrep --config auto --config $SEMGREP_RULES --json > reports/scan-results/semgrep-report.json
    
    echo ""
    echo "=== Results saved to reports/scan-results/semgrep-report.json ==="
fi
