# SAST-DAST Validator

**Dynamic Security Validation Tool** - Automatically validates SAST (Static Analysis) findings using DAST (Dynamic Analysis) with browser automation.

## Overview

This tool bridges the gap between static and dynamic security testing:

1. **Takes SAST findings** (from Semgrep, CodeQL, Snyk, etc.)
2. **Normalizes** them into a common format
3. **Dynamically tests** each finding using Browser-Use automation
4. **Reports** which vulnerabilities are confirmed, false positives, or need review

## Features

- 🔍 **Multi-format input**: Supports Semgrep, CodeQL, Bearer, custom JSON
- 🌐 **Real browser testing**: Uses Browser-Use for authentic browser automation
- 🤖 **LLM-powered validation**: Dynamic, context-aware payload generation
- 📊 **Detailed reports**: JSON reports with evidence
- ⚡ **Parallel execution**: Configurable workers for faster validation
- 🔐 **Authentication support**: Cookie-based authentication

## Installation

```bash
# Clone the repository
git clone https://github.com/anishalx/sast-dast.git
cd sast-dast

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install -e .

# Set up environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

## Quick Start

```bash
# Run validation
sast-dast -i findings.json -t http://localhost:3000 -o results.json
```

## CLI Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Path to JSON file with SAST findings | **required** |
| `--target` | `-t` | Target base URL | **required** |
| `--output` | `-o` | Output JSON file for results | stdout |
| `--model` | `-m` | LLM model to use | `gpt-4o-mini` |
| `--headless` | | Run browser in headless mode | `true` |
| `--no-headless` | | Show browser window | |
| `--timeout` | | Timeout per test in seconds | `90` |
| `--max-steps` | | Maximum agent steps per test | `6` |
| `--workers` | `-w` | Number of parallel workers | `1` |
| `--delay` | | Delay between tests (seconds) | `0.5` |
| `--cookies` | | Path to JSON file with auth cookies | |
| `--screenshots` | | Capture screenshots on confirmed vulns | `true` |
| `--evidence-dir` | | Directory to save evidence files | |
| `--verbose` | `-v` | Enable verbose logging | |
| `--quiet` | `-q` | Minimal output | |

## Usage Examples

```bash
# Basic usage
sast-dast -i semgrep.json -t http://localhost:3000

# With authentication and multiple workers
sast-dast -i findings.json -t http://app.local --workers 5 --cookies auth.json -o results.json

# Verbose mode with screenshots
sast-dast -i findings.json -t http://localhost:3000 -v --screenshots --evidence-dir ./evidence
```

## Input Formats

### Semgrep
```bash
semgrep --config auto --json -o findings.json .
```

### Custom JSON
```json
[
  {
    "id": "vuln-001",
    "type": "xss",
    "file": "app.py",
    "line": 42,
    "message": "Reflected XSS in search parameter",
    "endpoint": "/search",
    "param": "q",
    "severity": "high"
  }
]
```

## Supported Vulnerability Types

| Category | Types |
|----------|-------|
| **XSS** | Reflected XSS, Stored XSS, DOM XSS |
| **Injection** | SQL Injection, Command Injection, SSTI, Code Injection |
| **SSRF** | Server-Side Request Forgery |
| **Redirect** | Open Redirect |
| **Access Control** | IDOR, Auth Bypass, Missing Authorization |
| **Secrets** | Hardcoded Credentials, API Keys |
| **Headers** | Missing Security Headers |

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
    "total": 10,
    "confirmed": 2,
    "false_positive": 6,
    "needs_review": 1,
    "error": 1
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

## Project Structure

```
sast-dast-validator/
├── sast_dast_validator/
│   ├── __init__.py          # Package exports
│   ├── cli.py               # CLI interface
│   ├── executor.py          # Validation engine
│   ├── models.py            # Data models
│   ├── normalizer.py        # SAST format normalizers
│   ├── payload_generator.py # LLM-powered payload generation
│   ├── tools.py             # Custom browser tools
│   └── prompts/             # LLM prompt templates
├── requirements.txt         # Python dependencies
├── pyproject.toml           # Project configuration
├── .env.example             # Environment template
├── LICENSE                  # MIT License
└── README.md                # This file
```

## License

MIT License - See [LICENSE](LICENSE) file for details.
