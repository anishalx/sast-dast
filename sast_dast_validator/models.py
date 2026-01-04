"""
Normalized models for SAST-to-DAST validation.

This is the CONTRACT between static analysis tools and Browser-Use.
Browser-Use understands: URLs, Params, Payloads, Actions - NOT code.

Extended to support comprehensive security testing including:
- Injection attacks (SQL, Command, SSTI, Code)
- XSS (Reflected, Stored, DOM-based)
- SSRF, Open Redirect, IDOR
- Secrets/Credentials exposure
- Cryptographic issues
- Authentication bypass
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field
from uuid_extensions import uuid7str


class VulnType(str, Enum):
    """Supported vulnerability types."""
    # Cross-Site Scripting
    XSS = "xss"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    
    # Injection attacks
    INJECTION = "injection"
    SQLI = "sqli"
    CMDI = "cmdi"  # Command injection
    SSTI = "ssti"  # Server-Side Template Injection
    CODE_INJECTION = "code_injection"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    
    # Server-Side attacks
    SSRF = "ssrf"
    
    # Redirect/Navigation
    OPEN_REDIRECT = "open_redirect"
    
    # Access Control
    IDOR = "idor"
    BROKEN_ACCESS = "broken_access"
    AUTH_BYPASS = "auth_bypass"
    
    # Information Disclosure
    SECRETS = "secrets"
    HARDCODED_CREDS = "hardcoded_creds"
    INFO_DISCLOSURE = "info_disclosure"
    
    # Crypto Issues
    CRYPTO = "crypto"
    WEAK_CRYPTO = "weak_crypto"
    
    # Headers & Config
    MISSING_HEADERS = "missing_headers"
    SECURITY_MISCONFIG = "security_misconfig"
    
    # Other
    OTHER = "other"


class VulnCategory(str, Enum):
    """High-level vulnerability categories for grouping."""
    XSS = "xss"
    INJECTION = "injection"
    SSRF = "ssrf"
    REDIRECT = "redirect"
    ACCESS_CONTROL = "access_control"
    SECRETS = "secrets"
    CRYPTO = "crypto"
    HEADERS = "headers"
    OTHER = "other"


class ValidationStatus(str, Enum):
    """Outcome of dynamic validation."""
    CONFIRMED = "confirmed"      # Vulnerability is real
    FALSE_POSITIVE = "false_positive"  # Not exploitable
    NEEDS_REVIEW = "needs_review"  # Could not determine
    ERROR = "error"              # Test failed to run
    SKIPPED = "skipped"          # Test was skipped (e.g., auth required)


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NormalizedFinding(BaseModel):
    """
    Normalized finding from SAST tools.
    
    This is what Browser-Use can understand and test.
    Transform your Semgrep/other tool output to this format.
    """
    
    # Identification
    id: str = Field(default_factory=uuid7str)
    source_tool: str = Field(description="e.g., 'semgrep', 'bandit', 'codeql'")
    source_rule_id: str = Field(description="Original rule ID from SAST tool")
    
    # What to test
    vuln_type: VulnType
    category: VulnCategory | None = Field(default=None, description="High-level category for grouping")
    url: str = Field(description="Full URL to test (e.g., http://target.com/search)")
    method: str = Field(default="GET", description="HTTP method: GET, POST, etc.")
    
    # Parameters and payload
    param_name: str | None = Field(default=None, description="Vulnerable parameter name")
    param_location: str = Field(default="query", description="query, body, path, header")
    payload_hint: str | None = Field(default=None, description="Suggested payload to inject")
    witness_payload: str | None = Field(default=None, description="Generated witness/test payload")
    
    # Context from static analysis
    severity: str = Field(default="medium", description="low, medium, high, critical")
    message: str = Field(default="", description="Original SAST finding message")
    file_path: str | None = Field(default=None, description="Source file where found")
    line_number: int | None = Field(default=None, description="Line number in source")
    
    # CWE/OWASP references
    cwe: list[str] = Field(default_factory=list, description="CWE identifiers")
    owasp: list[str] = Field(default_factory=list, description="OWASP categories")
    
    # Extra metadata (optional)
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    def get_category(self) -> VulnCategory:
        """Get the high-level category for this finding."""
        if self.category:
            return self.category
        
        # Auto-detect from vuln_type
        type_to_category = {
            VulnType.XSS: VulnCategory.XSS,
            VulnType.XSS_REFLECTED: VulnCategory.XSS,
            VulnType.XSS_STORED: VulnCategory.XSS,
            VulnType.XSS_DOM: VulnCategory.XSS,
            VulnType.INJECTION: VulnCategory.INJECTION,
            VulnType.SQLI: VulnCategory.INJECTION,
            VulnType.CMDI: VulnCategory.INJECTION,
            VulnType.SSTI: VulnCategory.INJECTION,
            VulnType.CODE_INJECTION: VulnCategory.INJECTION,
            VulnType.LDAP_INJECTION: VulnCategory.INJECTION,
            VulnType.XPATH_INJECTION: VulnCategory.INJECTION,
            VulnType.SSRF: VulnCategory.SSRF,
            VulnType.OPEN_REDIRECT: VulnCategory.REDIRECT,
            VulnType.IDOR: VulnCategory.ACCESS_CONTROL,
            VulnType.BROKEN_ACCESS: VulnCategory.ACCESS_CONTROL,
            VulnType.AUTH_BYPASS: VulnCategory.ACCESS_CONTROL,
            VulnType.SECRETS: VulnCategory.SECRETS,
            VulnType.HARDCODED_CREDS: VulnCategory.SECRETS,
            VulnType.INFO_DISCLOSURE: VulnCategory.SECRETS,
            VulnType.CRYPTO: VulnCategory.CRYPTO,
            VulnType.WEAK_CRYPTO: VulnCategory.CRYPTO,
            VulnType.MISSING_HEADERS: VulnCategory.HEADERS,
            VulnType.SECURITY_MISCONFIG: VulnCategory.HEADERS,
        }
        return type_to_category.get(self.vuln_type, VulnCategory.OTHER)


class EvidenceData(BaseModel):
    """Structured evidence from exploitation attempt."""
    
    # Identification
    finding_id: str
    vuln_type: str
    
    # Test details
    payload_used: str
    payload_encoded: str | None = None
    
    # Results
    success: bool = False
    evidence_text: str = ""
    
    # Visual evidence
    screenshot_base64: str | None = None
    screenshot_path: str | None = None
    
    # Response data
    response_url: str | None = None
    response_status: int | None = None
    response_snippet: str | None = None
    
    # Markers detected
    markers_found: list[str] = Field(default_factory=list)
    
    # Timing
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ValidationResult(BaseModel):
    """Result of dynamic validation by Browser-Use."""
    
    # Link to original finding
    finding_id: str
    
    # Outcome
    status: ValidationStatus
    is_vulnerable: bool = False
    success: bool = False  # Alias for is_vulnerable (compatibility)
    
    # Evidence
    evidence: str = Field(default="", description="What was observed")
    evidence_data: EvidenceData | None = None
    screenshot_path: str | None = None
    screenshot_base64: str | None = None
    response_snippet: str | None = None
    
    # Test details
    tested_url: str
    tested_payload: str | None = None
    http_status: int | None = None
    
    # Timing
    tested_at: datetime = Field(default_factory=datetime.utcnow)
    timestamp: datetime = Field(default_factory=datetime.utcnow)  # Alias (compatibility)
    duration_seconds: float = 0.0
    
    # Agent reasoning
    agent_reasoning: str = Field(default="", description="LLM explanation of decision")
    
    # GIF recording path (if enabled)
    gif_path: str | None = None
    
    def __init__(self, **data):
        super().__init__(**data)
        # Sync success with is_vulnerable
        object.__setattr__(self, 'success', self.is_vulnerable)


class SastInput(BaseModel):
    """Input format for the CLI - array of normalized findings."""
    findings: list[NormalizedFinding]


class ExploitationQueue(BaseModel):
    """Queue of vulnerabilities grouped by category for exploitation."""
    category: VulnCategory
    vulnerabilities: list[NormalizedFinding]
    prompt_template: str | None = None
    
    @property
    def count(self) -> int:
        return len(self.vulnerabilities)


class ValidationOutput(BaseModel):
    """Output format from the CLI - array of validation results."""
    results: list[ValidationResult]
    summary: dict[str, int] = Field(default_factory=dict)
    
    # Metadata
    target_url: str | None = None
    tested_at: datetime = Field(default_factory=datetime.utcnow)
    total_duration_seconds: float = 0.0
    
    # CI/CD support
    exit_code: int = 0
    high_severity_confirmed: int = 0
    
    def compute_summary(self):
        """Compute summary statistics from results."""
        self.summary = {
            "total": len(self.results),
            "confirmed": sum(1 for r in self.results if r.status == ValidationStatus.CONFIRMED),
            "false_positive": sum(1 for r in self.results if r.status == ValidationStatus.FALSE_POSITIVE),
            "needs_review": sum(1 for r in self.results if r.status == ValidationStatus.NEEDS_REVIEW),
            "error": sum(1 for r in self.results if r.status == ValidationStatus.ERROR),
            "skipped": sum(1 for r in self.results if r.status == ValidationStatus.SKIPPED),
        }
        self.high_severity_confirmed = sum(
            1 for r in self.results 
            if r.status == ValidationStatus.CONFIRMED and r.is_vulnerable
        )
    
    def get_exit_code(self, fail_on_high: bool = False) -> int:
        """Get exit code for CI/CD integration."""
        if fail_on_high and self.high_severity_confirmed > 0:
            return 1
        return 0


class SARIFOutput(BaseModel):
    """SARIF 2.1.0 compatible output for GitHub/GitLab integration."""
    
    version: str = "2.1.0"
    schema_uri: str = Field(
        default="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        alias="$schema"
    )
    runs: list[dict] = Field(default_factory=list)
    
    @classmethod
    def from_validation_output(
        cls, 
        output: ValidationOutput,
        tool_name: str = "browser-use-security",
        tool_version: str = "1.0.0"
    ) -> "SARIFOutput":
        """Convert ValidationOutput to SARIF format."""
        results = []
        
        for r in output.results:
            if r.status != ValidationStatus.CONFIRMED:
                continue
                
            sarif_result = {
                "ruleId": r.finding_id,
                "level": "error" if r.is_vulnerable else "warning",
                "message": {
                    "text": r.evidence or r.agent_reasoning or "Vulnerability confirmed"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": r.tested_url
                        }
                    }
                }],
                "properties": {
                    "tested_payload": r.tested_payload,
                    "tested_at": r.tested_at.isoformat() if r.tested_at else None,
                }
            }
            results.append(sarif_result)
        
        return cls(
            runs=[{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/browser-use/browser-use"
                    }
                },
                "results": results
            }]
        )
    
    class Config:
        populate_by_name = True
    summary: dict[str, int] = Field(default_factory=dict)
    
    def compute_summary(self) -> None:
        """Compute summary statistics."""
        self.summary = {
            "total": len(self.results),
            "confirmed": sum(1 for r in self.results if r.status == ValidationStatus.CONFIRMED),
            "false_positive": sum(1 for r in self.results if r.status == ValidationStatus.FALSE_POSITIVE),
            "needs_review": sum(1 for r in self.results if r.status == ValidationStatus.NEEDS_REVIEW),
            "error": sum(1 for r in self.results if r.status == ValidationStatus.ERROR),
        }
