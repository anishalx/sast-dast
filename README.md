# SAST-DAST Validator

**Dynamic Security Validation Framework** - Bridges Static Application Security Testing (SAST) with Dynamic Application Security Testing (DAST) using AI-powered browser automation.

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Core Modules Reference](#core-modules-reference)
- [Data Models](#data-models)
- [Input Formats](#input-formats)
- [Output Format](#output-format)
- [Extending the Framework](#extending-the-framework)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Overview

SAST (Static Application Security Testing) tools analyze source code to find vulnerabilities, but they often produce false positives because they can't verify if issues are actually exploitable at runtime. This tool solves that problem by:

1. **Ingesting SAST findings** from tools like Semgrep
2. **Normalizing** them into a standardized format
3. **Dynamically testing** each finding using real browser automation
4. **Reporting** which vulnerabilities are confirmed exploitable, false positives, or need manual review

### Key Features

| Feature | Description |
|---------|-------------|
| **🤖 LLM-Powered Validation** | Uses GPT-4 to generate context-aware exploitation payloads and analyze responses |
| **🌐 Real Browser Testing** | Powered by [Browser-Use](https://github.com/browser-use/browser-use) for authentic browser automation |
| **⚡ Parallel Execution** | Configurable workers with staggered starts to prevent API rate limits |
| **🔄 Adaptive Payloads** | Dynamically generates technology-specific payloads (MySQL vs PostgreSQL, Jinja2 vs Twig, etc.) |
| **📊 Evidence Collection** | Screenshots, response snippets, and detailed reasoning for confirmed findings |
| **🔐 Authentication Support** | Cookie-based authentication for testing authenticated endpoints |
| **⏱️ Rate Limit Handling** | Built-in exponential backoff and retry logic for API rate limits |
| **📁 Multi-Format Input** | Supports Semgrep JSON, custom JSON, and pre-normalized formats |

---

## How It Works

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SAST Tools    │    │   Normalizer    │    │    Executor     │    │     Results     │
│   (Semgrep,     │───▶│   Transforms    │───▶│   LLM + Browser │───▶│   JSON Report   │
│    )      │    │   to standard   │    │   validates     │    │   with evidence │
└─────────────────┘    │   format        │    │   each finding  │    └─────────────────┘
                       └─────────────────┘    └─────────────────┘
```

### Validation Flow

1. **Normalization Phase** (`normalizer.py`)
   - Parses SAST output (Semgrep JSON, custom format)
   - Detects vulnerability type from rule IDs, messages, CWE mappings
   - Generates initial witness payloads for each vulnerability type
   - Groups findings by category for batch processing

2. **Payload Generation Phase** (`payload_generator.py`)
   - LLM analyzes the vulnerability context (code snippets, technology stack)
   - Generates targeted payloads specific to detected database, template engine, OS
   - Adapts payloads if WAF blocking is detected

3. **Validation Phase** (`executor.py`)
   - Creates browser session using Browser-Use
   - Injects payloads into vulnerable parameters
   - LLM agent navigates and observes response
   - Analyzes evidence (alerts, SQL errors, SSTI math results, redirects)

4. **Result Classification**
   - **CONFIRMED (🔴)**: Vulnerability verified with evidence
   - **FALSE_POSITIVE (✅)**: Payload was sanitized/blocked
   - **NEEDS_REVIEW (🟡)**: Couldn't determine; manual review needed
   - **ERROR (❌)**: Test failed to execute

---

## Architecture

```
sast-dast-validator/
├── sast_dast_validator/
│   ├── __init__.py              # Package exports and version
│   ├── cli.py                   # Command-line interface (Click-based)
│   ├── models.py                # Pydantic data models (NormalizedFinding, ValidationResult, etc.)
│   ├── normalizer.py            # SAST format parsing and normalization
│   ├── executor.py              # Dynamic validation engine with Browser-Use
│   ├── payload_generator.py     # LLM-powered payload generation
│   ├── rate_limit.py            # Rate limit handling and retry logic
│   ├── tools.py                 # Custom browser actions for security testing
│   └── prompts/                 # LLM prompt templates
│       ├── __init__.py          # Template loading utilities
│       ├── exploit_xss.md       # XSS validation prompt
│       ├── exploit_injection.md # SQL/Command/SSTI injection prompt
│       ├── exploit_ssrf.md      # SSRF validation prompt
│       ├── exploit_redirect.md  # Open redirect prompt
│       ├── exploit_access.md    # IDOR/Auth bypass prompt
│       ├── exploit_secrets.md   # Secrets exposure prompt
│       ├── exploit_headers.md   # Missing headers validation
│       └── exploit_generic.md   # Fallback generic prompt
├── pyproject.toml               # Project metadata and dependencies
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment template
└── README.md                    # This documentation
```

---

## Installation

### Prerequisites

- **Python 3.11+**
- **OpenAI API Key** (for LLM-powered validation)
- **Playwright browsers** (installed automatically by Browser-Use)

### Setup Steps

```bash
# 1. Clone the repository
git clone https://github.com/anishalx/sast-dast.git
cd sast-dast

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# OR
venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install the package in development mode
pip install -e .

# 5. Install Playwright browsers (required by Browser-Use)
playwright install chromium

# 6. Configure environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `browser-use>=0.10.0` | AI-powered browser automation framework |
| `pydantic>=2.0` | Data validation and serialization |
| `httpx>=0.25.0` | Async HTTP client for header checks |
| `click>=8.0` | CLI framework |
| `rich>=13.0` | Enhanced terminal output |
| `python-dotenv>=1.0.0` | Environment variable loading |
| `aiohttp>=3.9.0` | Async HTTP for connectivity checks |
| `langchain-core>=0.0.266` | LLM abstraction layer |

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Required: OpenAI API key for LLM-powered validation
OPENAI_API_KEY=sk-your-api-key-here

# Optional: Browser-Use cloud API key (for cloud browser support)
BROWSER_USE_API_KEY=your-browser-use-api-key-here
```

### ValidatorConfig Options

When using the validator programmatically, you can configure these options:

```python
from sast_dast_validator import DynamicValidator, ValidatorConfig

config = ValidatorConfig(
    llm=llm,                          # LangChain LLM instance
    headless=True,                    # Run browser without GUI
    timeout=90,                       # Timeout per test (seconds)
    max_steps=6,                      # Max LLM agent steps per test
    workers=1,                        # Parallel workers (adjust for API rate limits)
    delay=0.5,                        # Delay between tests (seconds)
    capture_screenshots=True,         # Screenshot on confirmed findings
    generate_gif=False,               # Generate GIF recordings
    use_cloud=False,                  # Use cloud browser (anti-detection)
    cookies=[...],                    # Authentication cookies
    initial_actions=[...],            # Actions before testing (e.g., login)
    evidence_dir=Path("./evidence"),  # Directory for evidence files
    use_vision=True,                  # Use vision capabilities (for XSS dialog detection)
)

validator = DynamicValidator(config=config)
```

---

## Usage

### CLI Usage

```bash
# Basic usage
sast-dast -i findings.json -t http://localhost:3000

# With authentication and parallel workers
sast-dast -i findings.json -t http://localhost:3000 \
    --workers 3 \
    --cookies auth.json \
    -o results.json

# Verbose mode with evidence collection
sast-dast -i findings.json -t http://localhost:3000 \
    -v \
    --screenshots \
    --evidence-dir ./evidence \
    -o results.json

# Show browser window (non-headless) for debugging
sast-dast -i findings.json -t http://localhost:3000 --no-headless

# Use a specific LLM model
sast-dast -i findings.json -t http://localhost:3000 --model gpt-4o
```

### CLI Options Reference

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Path to SAST findings JSON file | **required** |
| `--target` | `-t` | Target application base URL | **required** |
| `--output` | `-o` | Output JSON file for results | stdout |
| `--model` | `-m` | LLM model to use | `gpt-4o-mini` |
| `--headless` | | Run browser in headless mode | `true` |
| `--no-headless` | | Show browser window | |
| `--timeout` | | Timeout per test (seconds) | `90` |
| `--max-steps` | | Maximum LLM agent steps per test | `6` |
| `--workers` | `-w` | Number of parallel workers | `1` |
| `--delay` | | Delay between tests (seconds) | `0.5` |
| `--cookies` | | Path to JSON file with auth cookies | |
| `--screenshots` | | Capture screenshots on confirmed vulns | `true` |
| `--evidence-dir` | | Directory to save evidence files | |
| `--verbose` | `-v` | Enable verbose logging | |
| `--quiet` | `-q` | Minimal output (only results) | |

### Programmatic Usage

```python
import asyncio
from pathlib import Path
from sast_dast_validator import (
    SastNormalizer,
    DynamicValidator,
    ValidatorConfig,
    ValidationOutput,
)
from browser_use import ChatOpenAI

async def validate_findings():
    # Initialize LLM
    llm = ChatOpenAI(model="gpt-4o-mini")
    
    # Load and normalize SAST findings
    normalizer = SastNormalizer(target_base_url="http://localhost:3000")
    sast_input = normalizer.normalize_file("findings.json")
    
    print(f"Loaded {len(sast_input.findings)} findings")
    
    # Configure validator
    config = ValidatorConfig(
        llm=llm,
        headless=True,
        workers=2,
        timeout=60,
        capture_screenshots=True,
        evidence_dir=Path("./evidence"),
    )
    
    validator = DynamicValidator(config=config)
    
    # Run validation with progress callback
    def on_progress(completed, total, result):
        print(f"[{completed}/{total}] {result.status.value}: {result.tested_url}")
    
    results = await validator.validate_all(
        sast_input.findings,
        on_progress=on_progress,
    )
    
    # Build output
    output = ValidationOutput(results=results, target_url="http://localhost:3000")
    output.compute_summary()
    
    print(f"\nSummary: {output.summary}")
    
    # Get confirmed vulnerabilities
    confirmed = [r for r in results if r.status.value == "confirmed"]
    print(f"\nConfirmed vulnerabilities: {len(confirmed)}")
    for r in confirmed:
        print(f"  - {r.tested_url}: {r.evidence}")

asyncio.run(validate_findings())
```

---

## Core Modules Reference

### `models.py` - Data Models

Defines all Pydantic models used throughout the framework.

#### Key Classes

| Class | Purpose |
|-------|---------|
| `VulnType` | Enum of supported vulnerability types (XSS, SQLI, CMDI, SSTI, SSRF, etc.) |
| `VulnCategory` | High-level groupings (XSS, INJECTION, SSRF, REDIRECT, ACCESS_CONTROL, SECRETS, HEADERS, CRYPTO, OTHER) |
| `ValidationStatus` | Test outcomes (CONFIRMED, FALSE_POSITIVE, NEEDS_REVIEW, ERROR, SKIPPED) |
| `NormalizedFinding` | Standard format for SAST findings - the "contract" between SAST and DAST |
| `ValidationResult` | Result of validating a single finding |
| `EvidenceData` | Structured evidence from exploitation attempts |
| `ValidationOutput` | Complete output with all results and summary statistics |
| `SARIFOutput` | SARIF 2.1.0 compatible output for GitHub/GitLab integration |

#### NormalizedFinding Fields

```python
class NormalizedFinding(BaseModel):
    id: str                        # Unique identifier (UUID7)
    source_tool: str               # e.g., 'semgrep'
    source_rule_id: str            # Original SAST rule ID
    vuln_type: VulnType            # Detected vulnerability type
    category: VulnCategory | None  # High-level category
    url: str                       # Full URL to test
    method: str                    # HTTP method (GET, POST, etc.)
    param_name: str | None         # Vulnerable parameter name
    param_location: str            # query, body, path, header
    payload_hint: str | None       # Suggested payload to inject
    witness_payload: str | None    # Generated test payload
    severity: str                  # low, medium, high, critical
    message: str                   # Original SAST finding message
    file_path: str | None          # Source file where vulnerability found
    line_number: int | None        # Line number in source
    cwe: list[str]                 # CWE identifiers
    owasp: list[str]               # OWASP categories
    metadata: dict                 # Additional metadata
```

---

### `normalizer.py` - SAST Format Normalization

Transforms output from various SAST tools into the `NormalizedFinding` format.

#### Key Features

1. **Auto-detection of Vulnerability Type**
   - Regex pattern matching on rule IDs and messages
   - CWE mapping (e.g., CWE-79 → XSS, CWE-89 → SQLi)
   - Semgrep vulnerability_class extraction

2. **Technology Stack Detection**
   - Database detection from keywords (mysql, postgresql, sqlite)
   - Template engine detection (jinja2, twig, freemarker)
   - Framework detection (express, django, flask, spring)
   - Language detection from file extensions

3. **Witness Payload Generation**
   - Pre-defined payloads for each vulnerability type
   - XSS: `<script>alert('BU_XSS_TEST')</script>`
   - SQLi: `' OR '1'='1' --`
   - SSTI: `{{7*7}}`
   - SSRF: `http://127.0.0.1:22`

#### Supported Input Formats

**Semgrep JSON:**
```bash
semgrep --config auto --json -o findings.json .
```

**Custom JSON Array:**
```json
[
  {
    "vuln_type": "xss",
    "url": "/search",
    "param_name": "q",
    "method": "GET",
    "message": "Potential XSS in search parameter",
    "severity": "high"
  }
]
```

**Pre-normalized Format:**
```json
{
  "findings": [
    {
      "source_tool": "manual",
      "source_rule_id": "custom-xss-001",
      "vuln_type": "xss_reflected",
      "url": "http://target.com/search",
      "param_name": "q",
      "param_location": "query"
    }
  ]
}
```

---

### `executor.py` - Dynamic Validation Engine

The core validation engine that uses Browser-Use to dynamically test findings.

#### Validation Methods

| Method | Categories | Description |
|--------|------------|-------------|
| `_validate_xss` | XSS, XSS_REFLECTED, XSS_STORED, XSS_DOM | Checks for alert dialogs, unescaped script tags |
| `_validate_injection` | SQLI, CMDI, SSTI, CODE_INJECTION | Checks for SQL errors, command output, math results |
| `_validate_ssrf` | SSRF | Checks for internal service responses, metadata access |
| `_validate_open_redirect` | OPEN_REDIRECT | Checks if browser redirected to external domain |
| `_validate_access_control` | IDOR, AUTH_BYPASS, BROKEN_ACCESS | Checks for unauthorized data access |
| `_validate_secrets` | SECRETS, HARDCODED_CREDS | Checks for exposed credentials |
| `_validate_missing_headers` | MISSING_HEADERS | HTTP check for security headers (no browser) |
| `_validate_crypto` | CRYPTO, WEAK_CRYPTO | Returns NEEDS_REVIEW (requires code review) |
| `_validate_generic` | OTHER | Generic exploitation attempt |

#### Parallel Execution

```
Staggered Execution:
Agent 0: Starts immediately
Agent 1: Starts after 2s
Agent 2: Starts after 4s
...

This prevents API rate limits by avoiding simultaneous LLM calls.
```

#### Retry Logic

```
Rate Limit Errors:
- Attempt 1: Wait 30s
- Attempt 2: Wait 45s
- Attempt 3: Wait 60s
- Max: 120s

Other Errors (network, timeout):
- Attempt 1: Wait 2s
- Attempt 2: Wait 4s
- Attempt 3: Wait 8s
- Max: 30s
```

---

### `payload_generator.py` - LLM-Powered Payload Generation

Generates context-aware exploitation payloads using LLM.

#### PayloadContext

```python
@dataclass
class PayloadContext:
    vuln_type: VulnType
    category: VulnCategory
    url: str
    param_name: str | None
    
    # Technology stack (auto-detected or from metadata)
    database: str | None        # mysql, postgresql, sqlite, mssql, oracle
    template_engine: str | None # jinja2, twig, freemarker, erb, velocity
    os: str | None              # linux, windows
    framework: str | None       # express, django, flask, spring
    language: str | None        # python, javascript, php, java
    
    # Code context from SAST
    source_code: str | None
    sink_function: str | None
    data_flow: str | None
    sanitization_attempts: list[str]
    
    # Adaptive refinement
    previous_payloads: list[dict]  # For iterative testing
    waf_detected: bool
    blocked_patterns: list[str]
```

#### Technology-Specific Payloads

**Database-specific SQL Injection:**
```python
# MySQL
"' AND SLEEP(3)#"
"' UNION SELECT @@version,NULL,NULL#"

# PostgreSQL  
"'; SELECT pg_sleep(3)--"
"' UNION SELECT version(),NULL,NULL--"

# MSSQL
"'; WAITFOR DELAY '0:0:3'--"
"'; EXEC xp_cmdshell 'whoami'--"
```

**Template Engine-specific SSTI:**
```python
# Jinja2 (Python)
"{{7*7}}"  # Result: 49
"{{config}}"
"{{''.__class__.__mro__[1].__subclasses__()}}"

# Twig (PHP)
"{{_self.env.display('id')}}"
"{{['id']|filter('system')}}"

# Freemarker (Java)
"${7*7}"
"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"
```

---

### `rate_limit.py` - Rate Limit Handling

Multi-layered approach for handling API rate limits.

#### Error Classification

```python
def is_rate_limit_error(error: Exception) -> bool:
    """Detects rate limit errors by checking for patterns like:
    - '429' status code
    - 'rate limit' in message
    - 'too many requests'
    - 'quota exceeded'
    - 'tokens per minute'
    """

def is_retryable_error(error: Exception) -> bool:
    """Determines if error should trigger retry:
    - Rate limits: Yes (with longer backoff)
    - Network errors: Yes
    - 5xx errors: Yes
    - 401/403 auth errors: No
    """
```

#### RateLimitConfig

```python
@dataclass
class RateLimitConfig:
    max_retries: int = 3
    stagger_delay: float = 2.0           # Delay between parallel agent starts
    rate_limit_base_delay: float = 30.0  # Base delay for rate limits
    rate_limit_increment: float = 15.0   # Increment per retry
    rate_limit_max_delay: float = 120.0  # Maximum delay
    other_error_base_delay: float = 2.0  # Base delay for other errors
    other_error_max_delay: float = 30.0  # Maximum delay
    jitter_range: float = 1.0            # Random jitter (0-1 seconds)
```

---

### `tools.py` - Custom Browser Actions

Security-specific browser actions for use with Browser-Use agents.

#### Available Actions

| Action | Description |
|--------|-------------|
| `save_evidence` | Save evidence of security test result with optional screenshot |
| `test_payload` | Inject payload into URL parameter and navigate |
| `check_reflection` | Check if marker string is reflected in page (DOM/source) |
| `check_alert_dialog` | Detect JavaScript alert/confirm/prompt dialogs |
| `check_security_headers` | Check HTTP response for security headers |
| `check_sqli_indicators` | Scan page for SQL error messages |
| `check_redirect` | Detect if redirected to external domain |

#### Example: Creating Custom Security Tools

```python
from sast_dast_validator import create_security_tools
from pathlib import Path

# Create tools registry with security-specific actions
tools = create_security_tools(
    evidence_dir=Path("./evidence"),
    capture_screenshots=True,
)

# Tools can be used with Browser-Use agents
from browser_use import Agent

agent = Agent(
    task="Test XSS vulnerability",
    llm=llm,
    browser=browser,
    tools=tools,
)
```

---

### `prompts/` - LLM Prompt Templates

Templates for each vulnerability category that guide the LLM agent.

#### Template Variables

| Variable | Description |
|----------|-------------|
| `{url}` | Full test URL with injected payload |
| `{param_name}` | Parameter being tested |
| `{payload}` | Payload injected |
| `{marker}` | Expected marker in response |
| `{vuln_type}` | Vulnerability type name |
| `{message}` | Original SAST finding message |
| `{file_path}` | Source file path |
| `{line_number}` | Line number in source |

#### Sample XSS Prompt (`exploit_xss.md`)

```markdown
# XSS Test

Navigate to: {url}

Look for XSS evidence:
- Alert dialog with "{marker}"  
- Unescaped script/img/svg tags in page source
- JavaScript execution in console

If no evidence appears after the first quick check, return NOT_VULNERABLE to avoid extra steps.

**Result format** (use done action):
- `done("VULNERABLE: [evidence]")` - if XSS executed
- `done("NOT_VULNERABLE: payload sanitized")` - if encoded/stripped
- `done("BLOCKED: [reason]")` - if page error/403
```

---

## Data Models

### Supported Vulnerability Types (`VulnType`)

| Category | Types |
|----------|-------|
| **XSS** | `xss`, `xss_reflected`, `xss_stored`, `xss_dom` |
| **Injection** | `sqli`, `cmdi`, `ssti`, `code_injection`, `ldap_injection`, `xpath_injection`, `injection` |
| **SSRF** | `ssrf` |
| **Redirect** | `open_redirect` |
| **Access Control** | `idor`, `broken_access`, `auth_bypass` |
| **Secrets** | `secrets`, `hardcoded_creds`, `info_disclosure` |
| **Crypto** | `crypto`, `weak_crypto` |
| **Headers** | `missing_headers`, `security_misconfig` |
| **Other** | `other` |

### Validation Status

| Status | Emoji | Meaning |
|--------|-------|---------|
| `confirmed` | 🔴 | Vulnerability verified with evidence |
| `false_positive` | ✅ | Not exploitable (payload sanitized/blocked) |
| `needs_review` | 🟡 | Couldn't determine automatically |
| `error` | ❌ | Test failed to execute |
| `skipped` | ⏭️ | Test was skipped |

---

## Input Formats

### 1. Semgrep JSON

```bash
semgrep --config auto --json -o semgrep.json .
```

The normalizer extracts findings from the `results` array and maps:
- `check_id` → `source_rule_id`
- `extra.message` → `message`
- `extra.severity` → `severity`
- `extra.metadata.cwe` → `cwe`

### 2. Custom JSON Array

```json
[
  {
    "vuln_type": "sqli",
    "url": "/api/users",
    "param_name": "id",
    "param_location": "query",
    "method": "GET",
    "message": "SQL injection in user lookup",
    "severity": "critical",
    "cwe": ["CWE-89"]
  },
  {
    "vuln_type": "xss_reflected",
    "url": "/search",
    "param_name": "q",
    "method": "GET",
    "message": "Reflected XSS in search",
    "severity": "high"
  }
]
```

### 3. Findings Object Format

```json
{
  "findings": [
    {
      "source_tool": "custom-scanner",
      "source_rule_id": "SQLI-001",
      "vuln_type": "sqli",
      "url": "http://target.com/api/data",
      "param_name": "filter",
      "metadata": {
        "database": "mysql",
        "sink_function": "db.raw_query()"
      }
    }
  ]
}
```

---

## Output Format

### Validation Result Structure

```json
{
  "results": [
    {
      "finding_id": "0695a390-9acb-789f-8000-f05ce6a6b556",
      "status": "confirmed",
      "is_vulnerable": true,
      "tested_url": "http://localhost:3000/search?q=%27%20OR%20%271%27%3D%271%27%20--",
      "tested_payload": "' OR '1'='1' --",
      "http_status": 200,
      "evidence": "VULNERABLE: SQL error message exposed table structure",
      "agent_reasoning": "SQL syntax error revealed in response indicating injection worked",
      "screenshot_path": "./evidence/screenshot-0695a390-1704380220.png",
      "screenshot_base64": "iVBORw0KGgo...",
      "duration_seconds": 45.2,
      "tested_at": "2026-01-04T10:30:00Z"
    }
  ],
  "summary": {
    "total": 10,
    "confirmed": 2,
    "false_positive": 6,
    "needs_review": 1,
    "error": 1,
    "skipped": 0
  },
  "target_url": "http://localhost:3000",
  "tested_at": "2026-01-04T10:25:00Z",
  "total_duration_seconds": 450.5,
  "exit_code": 0,
  "high_severity_confirmed": 2
}
```

---

## Extending the Framework

### Adding a New Vulnerability Type

1. **Add to `VulnType` enum** (`models.py`):
   ```python
   class VulnType(str, Enum):
       # ... existing types
       XXES = "xxe"  # XML External Entity
   ```

2. **Add detection patterns** (`normalizer.py`):
   ```python
   RULE_TO_VULN_TYPE = {
       # ... existing patterns
       r"xxe|xml.?external": VulnType.XXE,
   }
   ```

3. **Add witness payload** (`normalizer.py`):
   ```python
   WITNESS_PAYLOADS = {
       # ... existing payloads
       VulnType.XXE: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
   }
   ```

4. **Create validation method** (`executor.py`):
   ```python
   async def _validate_xxe(self, finding: NormalizedFinding) -> ValidationResult:
       # Implementation
       pass
   ```

5. **Register in validators dict** (`executor.py`):
   ```python
   validators = {
       # ... existing validators
       VulnCategory.XXE: self._validate_xxe,
   }
   ```

6. **Create prompt template** (`prompts/exploit_xxe.md`)

### Adding Custom Payload Generation

```python
from sast_dast_validator import PayloadGenerator, PayloadContext

# Create generator with custom LLM
generator = PayloadGenerator(llm=my_llm)

# Build context with technology information
context = PayloadContext(
    vuln_type=VulnType.SQLI,
    category=VulnCategory.INJECTION,
    url="http://target.com/api",
    param_name="id",
    database="mysql",
    database_version="8.0",
)

# Generate payloads
payloads = await generator.generate_payloads(finding, context, num_payloads=10)

# Generate bypass payloads if WAF detected
if waf_blocked:
    bypass_payloads = await generator.generate_bypass_payloads(
        finding, context, blocked_payloads=["' OR '1'='1'"]
    )
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **Rate limit errors (429)** | Reduce `--workers` to 1-2, increase `--delay` |
| **Target not reachable** | Ensure your target app is running and accessible |
| **Timeout errors** | Increase `--timeout`, simplify page interactions |
| **No browser window** | Use `--no-headless` to debug visually |
| **LLM errors** | Verify `OPENAI_API_KEY` is set correctly in `.env` |
| **All findings show ERROR** | Check API key, network connectivity |
| **Blank results** | Enable `-v` for verbose logging |

### Debug Mode

```bash
# Enable verbose logging
sast-dast -i findings.json -t http://localhost:3000 -v

# Show browser for visual debugging
sast-dast -i findings.json -t http://localhost:3000 --no-headless -v

# Single worker for easier debugging
sast-dast -i findings.json -t http://localhost:3000 --workers 1 --timeout 120
```

### Performance Tuning

```bash
# For high API rate limits (increase workers)
sast-dast -i findings.json -t http://target.com --workers 5 --delay 1.0

# For low rate limits (single worker, longer delays)
sast-dast -i findings.json -t http://target.com --workers 1 --delay 2.0

# For complex SPAs (increase timeout and steps)
sast-dast -i findings.json -t http://spa.app --timeout 120 --max-steps 10
```

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

**Made with ❤️ for the security community**
