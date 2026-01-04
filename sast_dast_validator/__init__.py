"""
SAST-to-DAST Validator

A comprehensive dynamic security testing framework that bridges static analysis 
findings with browser-based exploitation validation using Browser-Use.

Supported Vulnerability Types:
- XSS (Reflected, Stored, DOM)
- Injection (SQLi, CMDi, SSTI, Code Injection)
- SSRF (Server-Side Request Forgery)
- Open Redirect
- Access Control (IDOR, Auth Bypass, Broken Access)
- Secrets (Hardcoded Credentials, Info Disclosure)
- Crypto (Weak Cryptography)
- Missing Security Headers

Features:
- Parallel execution with configurable workers
- Screenshot capture on confirmed vulnerabilities
- GIF recording for demos
- Cloud browser support (anti-detection)
- Authentication support (cookies, login scripts)
- CI/CD integration (exit codes, SARIF output)
- Rate limiting for WAF evasion
"""

from sast_dast_validator.models import (
    NormalizedFinding,
    ValidationResult,
    VulnType,
    VulnCategory,
    ValidationStatus,
    Severity,
    EvidenceData,
    ExploitationQueue,
    ValidationOutput,
    SARIFOutput,
    SastInput,
)
from sast_dast_validator.normalizer import SastNormalizer
from sast_dast_validator.executor import DynamicValidator, ValidatorConfig
from sast_dast_validator.tools import (
    create_security_tools,
    SecurityEvidence,
    SecurityTestResult,
)
from sast_dast_validator.prompts import (
    format_prompt,
    get_template_for_category,
)
from sast_dast_validator.payload_generator import (
    PayloadGenerator,
    PayloadContext,
    GeneratedPayload,
    PayloadTester,
)

__all__ = [
    # Models
    "NormalizedFinding",
    "ValidationResult", 
    "VulnType",
    "VulnCategory",
    "ValidationStatus",
    "Severity",
    "EvidenceData",
    "ExploitationQueue",
    "ValidationOutput",
    "SARIFOutput",
    "SastInput",
    # Core
    "SastNormalizer",
    "DynamicValidator",
    "ValidatorConfig",
    # Tools
    "create_security_tools",
    "SecurityEvidence",
    "SecurityTestResult",
    # Prompts
    "format_prompt",
    "get_template_for_category",
    # Payload Generator
    "PayloadGenerator",
    "PayloadContext",
    "GeneratedPayload",
    "PayloadTester",
]

__version__ = "0.1.0"
