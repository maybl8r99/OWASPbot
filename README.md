# OWASP Security Scanner

Comprehensive security scanning with **SAST** (Static Application Security Testing) and **DAST** (Dynamic Application Security Testing).

## Features

### SAST (Code Analysis)
- SonarQube integration for source code scanning
- Detects vulnerabilities in code before deployment
- Supports multiple programming languages

### DAST (Runtime Testing)
#### Playwright-based DAST
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


#### OWASP ZAP Integration
- Full-featured web application security scanner
- Spider and AJAX Spider for discovery
- Active and passive vulnerability scanning
- API scanning (OpenAPI/Swagger support)
- Multiple report formats (HTML, XML, JSON, Markdown)
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
- Additional vulnerability detection:
  - NoSQL Injection
  - SSRF (Server-Side Request Forgery)
  - XXE (XML External Entity)
  - File Upload vulnerabilities
  - HTTP Method security
  - Cache vulnerabilities
  - JWT security issues
  - Insecure Deserialization
  - Business Logic flaws

## Quick Start

### 1. Setup
```bash
cp .env.example .env
# Edit .env with your settings
```

### 2. ZAP Setup (Optional DAST Scanner)
```bash
# Install and start OWASP ZAP
./scripts/install-zap.sh        # One-time setup
# or on Windows: .\scripts\install-zap.ps1

# ZAP is now running at http://localhost:8080
```

### 3. SAST (Code Scanning)
```bash
# Start SonarQube (if not using install-tools.sh)
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
│   │   ├── 10-cors.spec.ts
│   │   ├── 11-nosql-injection.spec.ts
│   │   ├── 12-ssrf.spec.ts
│   │   ├── 13-xxe.spec.ts
│   │   ├── 14-file-upload.spec.ts
│   │   ├── 15-http-methods.spec.ts
│   │   ├── 16-cache-vulnerabilities.spec.ts
│   │   ├── 17-jwt-vulnerabilities.spec.ts
│   │   ├── 18-insecure-deserialization.spec.ts
│   │   └── 19-business-logic.spec.ts
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
| `docker-compose up -d` | Start SonarQube and ZAP |
| `./scripts/install-zap.sh` | Install/setup ZAP |
| `./scripts/install-tools.sh` | Install all prerequisites |
| `docker-compose down` | Stop containers |
| `./scripts/fetch-repos.sh` | Clone/pull repositories |
| `./scripts/run-sast.sh` | Run SAST (code) scan |
| `./scripts/run-dast.sh auth` | Manual login for DAST |
| `./scripts/run-dast.sh scan` | Run DAST (runtime) scan |
| `./scripts/run-dast.sh status` | Check auth status |
| `./scripts/run-dast.sh clear` | Clear saved auth |
| `npm run dast:report` | Open DAST HTML report |
| `npm run dast:headed` | Run DAST with visible browser |
| `./scripts/run-zap.sh quick` | Run ZAP quick scan |
| `./scripts/run-zap.sh full` | Run ZAP full scan |
| `./scripts/run-zap.sh api` | Run ZAP API scan |

## SAST Tool Alternatives

### Semgrep (Lightweight)
```bash
# In .env:
SAST_TOOL=semgrep
```

## DAST Scanners

### 1. Playwright DAST (Custom Tests)
Custom security tests built with Playwright for targeted vulnerability detection.

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
| **NoSQL Injection** | MongoDB, CouchDB injection |
| **SSRF** | Server-Side Request Forgery |
| **XXE** | XML External Entity injection |
| **File Upload** | Unrestricted uploads, web shells |
| **HTTP Methods** | Dangerous methods, XST |
| **Cache** | Cache poisoning, deception |
| **JWT** | Weak signatures, algorithm confusion |
| **Deserialization** | Java/PHP/Python deserialization |
| **Business Logic** | Price manipulation, race conditions |

### 2. OWASP ZAP
Industry-standard web application security scanner.

```bash
# Install and start ZAP (one-time setup)
./scripts/install-zap.sh

# Or use Docker Compose directly
docker-compose up -d zap

# Wait for ZAP to be ready
./scripts/run-zap.sh status

# Run scans
./scripts/run-zap.sh quick     # Spider + Active Scan (fast)
./scripts/run-zap.sh full      # Spider + AJAX Spider + Active Scan (thorough)
./scripts/run-zap.sh baseline  # Passive scan only (safe for CI/CD)
./scripts/run-zap.sh api       # API scan with OpenAPI/Swagger

# Configure target
export TARGET_ENDPOINT=https://your-app.com
export ZAP_FORMAT=json         # html, xml, json, or md
./scripts/run-zap.sh quick
```

**ZAP Commands:**

| Command | Description |
|---------|-------------|
| `quick` | Spider + Active scan (recommended) |
| `full` | Spider + AJAX Spider + Active scan |
| `baseline` | Passive scan only (no attacks) |
| `api` | OpenAPI/Swagger API scanning |
| `report` | Generate report from existing session |
| `status` | Check if ZAP is running |

**ZAP Environment Variables:**

```bash
TARGET_ENDPOINT=https://your-app.com    # Target URL
ZAP_API_URL=http://localhost:8080       # ZAP API endpoint
ZAP_FORMAT=html                         # Report format
ZAP_OPENAPI_URL=http://app/api-docs     # OpenAPI spec URL
```

## Reports

- **SAST**: View in SonarQube at http://localhost:9000
- **Playwright DAST**: `reports/dast-report/index.html` or `reports/dast-results.json`
- **ZAP DAST**: `reports/zap/zap-report-YYYYMMDD_HHMMSS.html`

### Report Comparison

| Feature | Playwright DAST | OWASP ZAP |
|---------|-----------------|-----------|
| Speed | Fast | Medium |
| Coverage | Targeted (19 categories) | Comprehensive |
| Customization | Full code control | Extensive addons |
| CI/CD | Easy | Baseline mode ideal |
| Authentication | Built-in manual auth | Script-based |
| API Scanning | Basic | Excellent (OpenAPI) |

**Recommendation**: Use both scanners for comprehensive coverage. Playwright DAST for targeted business logic tests, ZAP for broad vulnerability discovery.
