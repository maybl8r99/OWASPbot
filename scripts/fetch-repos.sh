#!/bin/bash
set -e

source .env 2>/dev/null || true

SOURCE_CODE_PATH=${SOURCE_CODE_PATH:-./source_code}
REPO_BRANCH=${REPO_BRANCH:-main}

mkdir -p "$SOURCE_CODE_PATH"

echo "=== Repository Authentication ==="
echo "For Azure DevOps: Username can be anything, Password = Personal Access Token (PAT)"
echo "Press Enter twice for no authentication"
echo ""

read -p "Username (blank for no auth): " AUTH_USERNAME
read -s -p "Password/PAT (blank for no auth): " AUTH_PASSWORD
echo ""
echo ""

if [ -z "$AUTH_USERNAME" ] && [ -z "$AUTH_PASSWORD" ]; then
    echo "Proceeding without authentication..."
    REPO_AUTH=false
else
    REPO_AUTH=true
    REPO_USERNAME="$AUTH_USERNAME"
    REPO_PASSWORD="$AUTH_PASSWORD"
fi

echo ""
echo "=== Fetching Repositories ==="

fetch_repo() {
    local name=$1
    local url=$2
    local target_dir="$SOURCE_CODE_PATH/$name"
    
    local clone_url="$url"
    
    if [ "$REPO_AUTH" = true ]; then
        clone_url=$(echo "$url" | sed "s|https://|https://${REPO_USERNAME}:${REPO_PASSWORD}@|")
    fi
    
    if [ -d "$target_dir" ]; then
        echo "Updating $name..."
        cd "$target_dir"
        
        if [ "$REPO_AUTH" = true ]; then
            git remote set-url origin "$clone_url"
        fi
        
        git fetch origin
        git checkout "$REPO_BRANCH" 2>/dev/null || git checkout -b "$REPO_BRANCH" origin/$REPO_BRANCH 2>/dev/null || true
        git reset --hard origin/$REPO_BRANCH 2>/dev/null || true
        cd - > /dev/null
    else
        echo "Cloning $name..."
        git clone --branch "$REPO_BRANCH" "$clone_url" "$target_dir"
        
        cd "$target_dir"
        git remote set-url origin "$url"
        cd - > /dev/null
    fi
}

if [ -n "$REPO_FRONTEND" ]; then
    fetch_repo "repo-frontend" "$REPO_FRONTEND"
fi

if [ -n "$REPO_API" ]; then
    fetch_repo "repo-api" "$REPO_API"
fi

if [ -n "$REPO_SHARED" ]; then
    fetch_repo "repo-shared" "$REPO_SHARED"
fi

if [ -n "$REPO_URLS" ]; then
    for url in $REPO_URLS; do
        name=$(basename "$url" .git)
        fetch_repo "$name" "$url"
    done
fi

echo ""
echo "=== Repositories ready in $SOURCE_CODE_PATH ==="
ls -la "$SOURCE_CODE_PATH"
