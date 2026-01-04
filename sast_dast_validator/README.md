# SAST-to-DAST Security Validator

A fast, lightweight tool that dynamically validates static analysis findings to reduce false positives. Uses direct HTTP requests and Playwright for deterministic testing - no slow LLM agents.

## Features

- ⚡ **Fast** - Tests complete in seconds, not minutes
- 🎯 **Accurate** - Direct payload injection and response analysis
- 🔧 **Simple** - Only 7 CLI options, easy to integrate
- 📊 **Comprehensive** - Supports XSS, SQLi, SSRF, headers, redirects, and more

## Quick Start

```bash
# Basic usage
python -m browser_use.security.validator.cli \
    -i findings.json \
    -t http://localhost:3000 \
    -o results.json

# With timeout and screenshots
python -m browser_use.security.validator.cli \
    -i findings.json \
    -t http://localhost:3000 \
    -o results.json \
    --timeout 30 \
    --screenshots
```

## CLI Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input JSON file with findings | **required** |
| `--target` | `-t` | Target base URL | **required** |
| `--output` | `-o` | Output JSON file | `results.json` |
| `--timeout` | | Timeout per test (seconds) | `30` |
| `--headless` | | Run browser headless | `true` |
| `--no-headless` | | Show browser window | |
| `--screenshots` | | Capture on confirmed vulns | `false` |
| `--verbose` | `-v` | Verbose logging | `false` |

## Input Format

Simple JSON with findings array:

```json
{
  "findings": [
    {
      "vuln_type": "xss",
      "url": "/search",
      "param_name": "q",
      "message": "Potential XSS"
    },
    {
      "vuln_type": "sqli",
      "url": "/api/products",
      "param_name": "id",
      "message": "SQL injection"
    },
    {
      "vuln_type": "missing_headers",
      "url": "/",
      "message": "Missing security headers"
    }
  ]
}
```

### Supported Vulnerability Types

| Type | Description | Test Method |
|------|-------------|-------------|
| `xss` | Cross-Site Scripting | Playwright + dialog detection |
| `sqli` | SQL Injection | HTTP + error pattern matching |
| `ssti` | Server-Side Template Injection | HTTP + marker detection |
| `ssrf` | Server-Side Request Forgery | HTTP + response analysis |
| `open_redirect` | Open Redirect | HTTP + Location header check |
| `missing_headers` | Missing Security Headers | HTTP + header check |
| `secrets` | Hardcoded Secrets | Returns needs_review |
| `crypto` | Weak Cryptography | Returns needs_review |

### Optional Fields

| Field | Description | Default |
|-------|-------------|---------|
| `param_name` | Parameter to inject | auto-detect |
| `param_location` | query, body, path | `query` |
| `method` | HTTP method | `GET` |
| `payload_hint` | Custom payload | auto-generated |
| `severity` | low/medium/high/critical | `medium` |
| `source_tool` | SAST tool name | `unknown` |

## Output Format

```json
{
  "results": [
    {
      "finding_id": "uuid",
      "status": "confirmed",
      "is_vulnerable": true,
      "tested_url": "http://target/search?q=<script>...",
      "tested_payload": "<script>alert('XSS')</script>",
      "evidence": "XSS CONFIRMED: Alert triggered",
      "duration_seconds": 2.5
    }
  ],
  "summary": {
    "confirmed": 1,
    "false_positives": 3,
    "needs_review": 0,
    "errors": 0,
    "duration_seconds": 6
  }
}
```

### Validation Status

| Status | Emoji | Meaning |
|--------|-------|---------|
| `confirmed` | 🔴 | Vulnerability verified |
| `false_positive` | ✅ | Not exploitable |
| `needs_review` | 🟡 | Manual review needed |
| `error` | ❌ | Test failed |

## How It Works

### XSS Testing
1. Launch Chromium via Playwright
2. Navigate to URL with XSS payload injected
3. Listen for JavaScript `dialog` events (alert/confirm/prompt)
4. If dialog triggered → **CONFIRMED**
5. If payload reflected but no dialog → **NEEDS_REVIEW**
6. If payload not reflected → **FALSE_POSITIVE**

### SQL Injection Testing
1. Send HTTP request with SQLi payload
2. Check response for error markers:
   - `sql syntax`, `mysql`, `postgresql`, `oracle`
   - `syntax error`, `unclosed quotation`
   - `ORA-`, `ODBC SQL Server Driver`
3. If markers found → **CONFIRMED**

### Security Headers Testing
1. Send HTTP request to target
2. Check for presence of:
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Content-Security-Policy`
   - `Strict-Transport-Security`
3. If any missing → **CONFIRMED**

## Semgrep Integration

```bash
# Run Semgrep and pipe to validator
semgrep --config=auto --json > findings.json

python -m browser_use.security.validator.cli \
    -i findings.json \
    -t http://localhost:3000 \
    -o validated.json
```

## Python API

```python
from browser_use.security.validator import (
    DynamicValidator,
    SastNormalizer,
    ValidationStatus,
)

# Load and normalize findings
normalizer = SastNormalizer(target_base_url="http://localhost:3000")
with open("findings.json") as f:
    sast_input = normalizer.normalize(json.load(f))

# Validate
validator = DynamicValidator(headless=True, timeout=30)
results = await validator.validate_all(sast_input.findings)

# Process results
for result in results:
    if result.status == ValidationStatus.CONFIRMED:
        print(f"🔴 CONFIRMED: {result.evidence}")
```

## Performance

| Metric | Old (LLM Agent) | New (Direct) |
|--------|-----------------|--------------|
| 4 findings | 348+ seconds | **6.5 seconds** |
| Success rate | 12% | **100%** |
| Timeouts | 7/8 tests | 0/4 tests |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No confirmed vulnerabilities |
| `1` | One or more confirmed vulnerabilities |
