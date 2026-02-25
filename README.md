# OWASP Security Scanner

Comprehensive security scanning with **SAST** (Static Application Security Testing) and **DAST** (Dynamic Application Security Testing).

## Features

### SAST (Code Analysis)
- SonarQube integration for source code scanning
- Detects vulnerabilities in code before deployment
- Supports multiple programming languages

### DAST (Runtime Testing)
- Playwright-based dynamic security testing
- Manual authentication with automatic JWT/cookie capture
- OWASP Top 10 vulnerability detection:
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - Command Injection
  - Path Traversal
  - Open Redirect
  - CSRF
  - Security Headers
  - Authentication/Authorization
  - Sensitive Data Exposure
  - CORS Misconfiguration

## Quick Start

### 1. Setup
```bash
cp .env.example .env
# Edit .env with your settings
```

### 2. SAST (Code Scanning)
```bash
# Start SonarQube
docker-compose up -d

# Wait for startup, then open http://localhost:9000
# Login: admin/admin, generate token

# Add token to .env, then:
./scripts/fetch-repos.sh    # Clone repositories
./scripts/run-sast.sh       # Run code scan
```

### 3. DAST (Runtime Scanning)

**For authenticated applications:**
```bash
# Set TARGET_ENDPOINT in .env, then authenticate:
./scripts/run-dast.sh auth  # Opens browser for manual login

# After logging in and pressing Enter, run the scan:
./scripts/run-dast.sh scan  # Uses saved authentication
npm run dast:report         # View HTML report
```

**For public/unauthenticated applications:**
```bash
# Set in .env: SKIP_AUTH=true
./scripts/run-dast.sh scan
```

## DAST Authentication

The scanner supports manual authentication with automatic JWT/cookie capture:

### How It Works
1. Run `./scripts/run-dast.sh auth`
2. Browser opens to your target application
3. Log in manually (including any MFA/2FA)
4. Press Enter in terminal when done
5. Authentication state (cookies, localStorage) is saved
6. Subsequent scans use the saved authentication

### Commands
```bash
./scripts/run-dast.sh auth    # Manual login (saves JWT/cookies)
./scripts/run-dast.sh scan    # Run scan with saved auth
./scripts/run-dast.sh status  # Check auth status
./scripts/run-dast.sh clear   # Clear saved authentication
```

### Environment Variables
```bash
TARGET_ENDPOINT=https://your-app.com  # Target URL
HEADLESS=true                         # Headless browser mode
SKIP_AUTH=false                       # Skip auth for public apps
```

### Authentication Storage
- Saved to: `dast/.auth/user.json`
- Expires: 1 hour (re-authenticate after)
- Contains: Cookies, localStorage tokens

## Project Structure

```
.
├── .env                    # Configuration
├── docker-compose.yml      # SonarQube container
├── dast/
│   ├── auth.setup.ts       # Manual authentication flow
│   ├── .auth/              # Stored auth state (gitignored)
│   ├── tests/              # DAST test files
│   │   ├── 01-xss.spec.ts
│   │   ├── 02-sqli.spec.ts
│   │   ├── 03-security-headers.spec.ts
│   │   ├── 04-open-redirect.spec.ts
│   │   ├── 05-command-injection.spec.ts
│   │   ├── 06-path-traversal.spec.ts
│   │   ├── 07-auth.spec.ts
│   │   ├── 08-sensitive-data.spec.ts
│   │   ├── 09-csrf.spec.ts
│   │   └── 10-cors.spec.ts
│   ├── fixtures/           # Test payloads
│   └── utils/              # Helper functions
├── scripts/
│   ├── fetch-repos.sh      # Clone repositories
│   ├── run-sast.sh         # Run SAST scan
│   └── run-dast.sh         # Run DAST scan
├── source_code/            # Cloned repos (gitignored)
└── reports/
    ├── dast-report/        # DAST HTML report
    └── dast-results.json   # DAST JSON results
```

## Configuration

Edit `.env`:

```bash
# Target application (for DAST)
TARGET_ENDPOINT=https://your-app.com

# DAST authentication
SKIP_AUTH=false           # Set true for public apps
HEADLESS=true             # Set false to see browser

# Azure DevOps repositories (for SAST)
REPO_FRONTEND=https://dev.azure.com/org/project/_git/frontend
REPO_API=https://dev.azure.com/org/project/_git/api
REPO_BRANCH=main

# SonarQube
SONARQUBE_URL=http://localhost:9000
SONARQUBE_TOKEN=squ_xxx
SONAR_PROJECT_KEY=my-project
```

### Azure DevOps Authentication

When running `fetch-repos.sh`:
- **Username**: Any non-empty value (e.g., "user")
- **Password**: Personal Access Token (PAT) with **Code > Read** scope
- Leave both blank for public repos

## Commands

| Command | Description |
|---------|-------------|
| `docker-compose up -d` | Start SonarQube |
| `docker-compose down` | Stop containers |
| `./scripts/fetch-repos.sh` | Clone/pull repositories |
| `./scripts/run-sast.sh` | Run SAST (code) scan |
| `./scripts/run-dast.sh auth` | Manual login for DAST |
| `./scripts/run-dast.sh scan` | Run DAST (runtime) scan |
| `./scripts/run-dast.sh status` | Check auth status |
| `./scripts/run-dast.sh clear` | Clear saved auth |
| `npm run dast:report` | Open DAST HTML report |
| `npm run dast:headed` | Run DAST with visible browser |

## SAST Tool Alternatives

### Semgrep (Lightweight)
```bash
# In .env:
SAST_TOOL=semgrep
```

## DAST Test Categories

| Test | Description |
|------|-------------|
| XSS | Reflected, stored, and DOM-based XSS |
| SQL Injection | Error-based and blind SQLi |
| Command Injection | OS command execution |
| Path Traversal | Directory traversal attacks |
| Open Redirect | URL redirect vulnerabilities |
| Security Headers | Missing/insecure headers |
| Authentication | Auth bypass, IDOR, session issues |
| Sensitive Data | Exposed credentials, PII |
| CSRF | Cross-site request forgery |
| CORS | Cross-origin misconfigurations |

## Reports

- **SAST**: View in SonarQube at http://localhost:9000
- **DAST**: `reports/dast-report/index.html` or `reports/dast-results.json`
