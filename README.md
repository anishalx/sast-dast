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
- 🤖 **LLM-powered payload generation**: Dynamic, context-aware payloads
- 📊 **Detailed reports**: Markdown reports with evidence and screenshots
- ⚡ **Parallel execution**: Configurable workers for faster validation
- 🔐 **Authentication support**: Cookies and login scripts

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/sast-dast-validator.git
cd sast-dast-validator

# Create virtual environment
uv venv --python 3.11
source .venv/bin/activate

# Install dependencies
uv pip install -e .

# Install browser
uvx browser-use install
```

## Quick Start

```bash
# Set up your API key
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY or BROWSER_USE_API_KEY

# Run validation
sast-dast validate semgrep_results.json --target-url http://localhost:3000
```

## Usage

### CLI Commands

```bash
# Validate SAST findings
sast-dast validate <input_file> --target-url <url> [options]

# Options:
#   --target-url, -t    Base URL of the target application
#   --format, -f        Input format (semgrep, codeql, bearer, generic)
#   --output, -o        Output file path
#   --output-format     Output format (json, markdown)
#   --workers, -w       Number of parallel workers (default: 1)
#   --headless          Run browser in headless mode
#   --timeout           Timeout per test in seconds (default: 90)
#   --delay             Delay between tests in seconds (default: 0.5)

# Example with options
sast-dast validate findings.json \
  --target-url http://localhost:3000 \
  --format semgrep \
  --output report.md \
  --output-format markdown \
  --workers 2 \
  --headless
```

### Python API

```python
import asyncio
from sast_dast_validator import (
    DynamicValidator,
    SastNormalizer,
    NormalizedFinding,
    ValidationResult,
)
from browser_use import ChatOpenAI  # or ChatBrowserUse

async def main():
    # Initialize LLM
    llm = ChatOpenAI(model="gpt-4o-mini")
    
    # Normalize SAST findings
    normalizer = SastNormalizer()
    findings = normalizer.normalize_file(
        "semgrep_results.json",
        source_format="semgrep",
        target_base_url="http://localhost:3000"
    )
    
    # Create validator
    validator = DynamicValidator(
        llm=llm,
        headless=True,
        workers=2,
        timeout=90,
    )
    
    # Validate all findings
    results = await validator.validate_all(findings)
    
    # Process results
    for result in results:
        print(f"{result.finding_id}: {result.status.value}")

asyncio.run(main())
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
| **Crypto** | Weak Cryptography |

## Input Formats

### Semgrep
```bash
semgrep --config auto --json -o findings.json .
```

### CodeQL
```bash
codeql database analyze db --format=sarif-latest --output=findings.sarif
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
├── tests/                   # Test suite
├── pyproject.toml          # Project configuration
├── .env.example            # Environment template
└── README.md               # This file
```

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.
