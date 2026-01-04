"""
SAST Normalizer

Transforms output from various static analysis tools (Semgrep, Bandit, etc.)
into the normalized format that Browser-Use can understand.

Features:
- Multi-format SAST output parsing (Semgrep, generic JSON)
- Vulnerability type detection from rules and messages
- Witness payload generation for each vulnerability type
- Queue generation grouped by vulnerability category
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

from sast_dast_validator.models import (
    NormalizedFinding, 
    VulnType, 
    VulnCategory,
    SastInput,
    ExploitationQueue,
)

logger = logging.getLogger(__name__)


# Comprehensive mapping of SAST rule patterns to VulnType
RULE_TO_VULN_TYPE = {
    # XSS patterns
    r"xss": VulnType.XSS,
    r"cross.?site.?script": VulnType.XSS,
    r"reflected": VulnType.XSS_REFLECTED,
    r"stored.?xss": VulnType.XSS_STORED,
    r"dom.?xss|dom.?based": VulnType.XSS_DOM,
    r"dangerouslysetinnerhtml": VulnType.XSS,
    r"innerhtml": VulnType.XSS,
    r"document\.write": VulnType.XSS,
    r"v-html": VulnType.XSS,
    r"ng-bind-html": VulnType.XSS,
    
    # SQL Injection patterns
    r"sql.?inject": VulnType.SQLI,
    r"sqli": VulnType.SQLI,
    r"sql.?query": VulnType.SQLI,
    r"raw.?query": VulnType.SQLI,
    r"string.?concat.*sql": VulnType.SQLI,
    
    # Command Injection patterns
    r"command.?inject": VulnType.CMDI,
    r"cmd.?inject": VulnType.CMDI,
    r"os.?command": VulnType.CMDI,
    r"shell.?inject": VulnType.CMDI,
    r"exec\(|system\(|popen\(": VulnType.CMDI,
    r"child_process": VulnType.CMDI,
    r"subprocess": VulnType.CMDI,
    
    # Code Injection / Eval patterns
    r"code.?inject": VulnType.CODE_INJECTION,
    r"eval.?inject": VulnType.CODE_INJECTION,
    r"unsafe.?eval": VulnType.CODE_INJECTION,
    r"dynamic.?code": VulnType.CODE_INJECTION,
    
    # SSTI patterns
    r"ssti": VulnType.SSTI,
    r"template.?inject": VulnType.SSTI,
    r"server.?side.?template": VulnType.SSTI,
    r"jinja|mako|freemarker|velocity|thymeleaf": VulnType.SSTI,
    
    # Generic Injection (fallback)
    r"inject": VulnType.INJECTION,
    
    # SSRF patterns
    r"ssrf": VulnType.SSRF,
    r"server.?side.?request": VulnType.SSRF,
    r"url.?fetch": VulnType.SSRF,
    r"request.?forgery": VulnType.SSRF,
    
    # Open Redirect patterns
    r"open.?redirect": VulnType.OPEN_REDIRECT,
    r"url.?redirect": VulnType.OPEN_REDIRECT,
    r"unvalidated.?redirect": VulnType.OPEN_REDIRECT,
    
    # Access Control patterns
    r"idor": VulnType.IDOR,
    r"insecure.?direct": VulnType.IDOR,
    r"authorization": VulnType.BROKEN_ACCESS,
    r"access.?control": VulnType.BROKEN_ACCESS,
    r"broken.?access": VulnType.BROKEN_ACCESS,
    r"auth.?bypass": VulnType.AUTH_BYPASS,
    r"authentication.?bypass": VulnType.AUTH_BYPASS,
    
    # Secrets/Credentials patterns
    r"hardcoded.?secret": VulnType.SECRETS,
    r"hardcoded.?password": VulnType.HARDCODED_CREDS,
    r"hardcoded.?credential": VulnType.HARDCODED_CREDS,
    r"hardcoded.?key": VulnType.SECRETS,
    r"api.?key.?exposed": VulnType.SECRETS,
    r"secret.?in.?source": VulnType.SECRETS,
    r"password.?in.?code": VulnType.HARDCODED_CREDS,
    r"credential.?leak": VulnType.SECRETS,
    r"sensitive.?data": VulnType.INFO_DISCLOSURE,
    
    # Crypto patterns
    r"weak.?crypto": VulnType.WEAK_CRYPTO,
    r"insecure.?crypto": VulnType.WEAK_CRYPTO,
    r"md5|sha1": VulnType.WEAK_CRYPTO,
    r"crypto": VulnType.CRYPTO,
    r"encryption": VulnType.CRYPTO,
    
    # Missing Headers patterns
    r"missing.?header": VulnType.MISSING_HEADERS,
    r"security.?header": VulnType.MISSING_HEADERS,
    r"x-frame-options": VulnType.MISSING_HEADERS,
    r"content-security-policy": VulnType.MISSING_HEADERS,
    r"x-content-type": VulnType.MISSING_HEADERS,
    r"strict-transport": VulnType.MISSING_HEADERS,
    r"hsts": VulnType.MISSING_HEADERS,
    
    # Misconfiguration
    r"misconfig": VulnType.SECURITY_MISCONFIG,
    r"debug.?enabled": VulnType.SECURITY_MISCONFIG,
    r"verbose.?error": VulnType.SECURITY_MISCONFIG,
}

# CWE to VulnType mapping
CWE_TO_VULN_TYPE = {
    "CWE-79": VulnType.XSS,
    "CWE-89": VulnType.SQLI,
    "CWE-78": VulnType.CMDI,
    "CWE-94": VulnType.CODE_INJECTION,
    "CWE-1336": VulnType.SSTI,
    "CWE-918": VulnType.SSRF,
    "CWE-601": VulnType.OPEN_REDIRECT,
    "CWE-639": VulnType.IDOR,
    "CWE-284": VulnType.BROKEN_ACCESS,
    "CWE-798": VulnType.HARDCODED_CREDS,
    "CWE-200": VulnType.INFO_DISCLOSURE,
    "CWE-327": VulnType.WEAK_CRYPTO,
    "CWE-693": VulnType.MISSING_HEADERS,
}

# Witness payloads for each vulnerability type
WITNESS_PAYLOADS = {
    # XSS payloads with unique markers
    VulnType.XSS: "<script>alert('BU_XSS_TEST')</script>",
    VulnType.XSS_REFLECTED: "<img src=x onerror=alert('BU_XSS_REFLECTED')>",
    VulnType.XSS_STORED: "<script>document.body.innerHTML+='BU_XSS_STORED'</script>",
    VulnType.XSS_DOM: "'-alert('BU_XSS_DOM')-'",
    
    # SQL Injection payloads
    VulnType.SQLI: "' OR '1'='1' --",
    VulnType.INJECTION: "' OR '1'='1' --",
    
    # Command Injection payloads
    VulnType.CMDI: "; echo BU_CMDI_TEST",
    
    # Code Injection / Eval payloads
    VulnType.CODE_INJECTION: "require('child_process').execSync('echo BU_CODE_INJ')",
    
    # SSTI payloads (various template engines)
    VulnType.SSTI: "{{7*7}}",
    
    # SSRF payloads
    VulnType.SSRF: "http://127.0.0.1:22",
    
    # Open Redirect payloads
    VulnType.OPEN_REDIRECT: "https://evil.example.com",
    
    # IDOR payloads
    VulnType.IDOR: "99999",
    VulnType.BROKEN_ACCESS: "admin",
    VulnType.AUTH_BYPASS: "admin",
    
    # Secrets/Crypto - no active payloads, just detection
    VulnType.SECRETS: "",
    VulnType.HARDCODED_CREDS: "",
    VulnType.INFO_DISCLOSURE: "",
    VulnType.CRYPTO: "",
    VulnType.WEAK_CRYPTO: "",
    
    # Headers - no payloads needed
    VulnType.MISSING_HEADERS: "",
    VulnType.SECURITY_MISCONFIG: "",
    
    # LDAP/XPath Injection
    VulnType.LDAP_INJECTION: "*)(uid=*))(|(uid=*",
    VulnType.XPATH_INJECTION: "' or '1'='1",
    
    # Other
    VulnType.OTHER: "",
}


class SastNormalizer:
    """
    Normalizes SAST tool output to the format Browser-Use understands.
    
    Supported formats:
    - Semgrep JSON
    - Generic JSON (custom format)
    - Pre-normalized format
    
    Features:
    - Auto-detect vulnerability types from rules/messages
    - Generate witness payloads for each finding
    - Group findings by category for exploitation queues
    """
    
    def __init__(self, target_base_url: str):
        """
        Initialize normalizer.
        
        Args:
            target_base_url: Base URL of the target application (e.g., http://localhost:3000)
        """
        self.target_base_url = target_base_url.rstrip("/")
    
    def normalize_file(self, file_path: str | Path) -> SastInput:
        """Load and normalize a SAST output file."""
        path = Path(file_path)
        
        with open(path) as f:
            data = json.load(f)
        
        return self.normalize(data)
    
    def normalize(self, data: dict | list) -> SastInput:
        """
        Normalize SAST output to our standard format.
        
        Auto-detects format and converts accordingly.
        """
        # If already in our format with findings key
        if isinstance(data, dict) and "findings" in data:
            findings = []
            for f in data["findings"]:
                try:
                    # Use _normalize_generic for flexible parsing
                    findings.append(self._normalize_generic(f))
                except Exception as e:
                    logger.warning(f"Failed to normalize finding: {e}")
            return SastInput(findings=findings)
        
        # If it's a Semgrep output
        if isinstance(data, dict) and "results" in data:
            return self._normalize_semgrep(data)
        
        # If it's a raw list of findings
        if isinstance(data, list):
            findings = []
            for item in data:
                try:
                    findings.append(self._normalize_generic(item))
                except Exception as e:
                    logger.warning(f"Failed to normalize finding: {e}")
            return SastInput(findings=findings)
        
        raise ValueError(f"Unknown SAST format: {type(data)}")
    
    def generate_queues(
        self, 
        findings: list[NormalizedFinding],
        output_dir: Path | None = None
    ) -> dict[VulnCategory, ExploitationQueue]:
        """
        Group findings by category and create exploitation queues.
        
        Args:
            findings: List of normalized findings
            output_dir: Optional directory to save queue files
            
        Returns:
            Dictionary mapping category to exploitation queue
        """
        queues: dict[VulnCategory, list[NormalizedFinding]] = {}
        
        for finding in findings:
            category = finding.get_category()
            if category not in queues:
                queues[category] = []
            queues[category].append(finding)
        
        # Create ExploitationQueue objects
        result = {}
        for category, vuln_list in queues.items():
            queue = ExploitationQueue(
                category=category,
                vulnerabilities=vuln_list,
                prompt_template=self._get_prompt_template(category),
            )
            result[category] = queue
            
            # Save to file if output_dir provided
            if output_dir:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                queue_file = output_dir / f"{category.value}_exploitation_queue.json"
                
                queue_data = {
                    "category": category.value,
                    "count": queue.count,
                    "prompt_template": queue.prompt_template,
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "vuln_type": v.vuln_type.value,
                            "url": v.url,
                            "param_name": v.param_name,
                            "witness_payload": v.witness_payload,
                            "severity": v.severity,
                            "message": v.message,
                            "cwe": v.cwe,
                        }
                        for v in vuln_list
                    ]
                }
                
                with open(queue_file, "w") as f:
                    json.dump(queue_data, f, indent=2)
                
                logger.info(f"Created {queue_file.name} with {queue.count} vulnerabilities")
        
        return result
    
    def _get_prompt_template(self, category: VulnCategory) -> str:
        """Get the prompt template filename for a category."""
        templates = {
            VulnCategory.XSS: "exploit_xss.md",
            VulnCategory.INJECTION: "exploit_injection.md",
            VulnCategory.SSRF: "exploit_ssrf.md",
            VulnCategory.REDIRECT: "exploit_redirect.md",
            VulnCategory.ACCESS_CONTROL: "exploit_access.md",
            VulnCategory.SECRETS: "exploit_secrets.md",
            VulnCategory.CRYPTO: "exploit_crypto.md",
            VulnCategory.HEADERS: "exploit_headers.md",
            VulnCategory.OTHER: "exploit_generic.md",
        }
        return templates.get(category, "exploit_generic.md")
    
    def _get_witness_payload(self, vuln_type: VulnType) -> str:
        """Get the witness/test payload for a vulnerability type."""
        return WITNESS_PAYLOADS.get(vuln_type, "")
    
    def _normalize_semgrep(self, data: dict) -> SastInput:
        """Normalize Semgrep JSON output."""
        findings = []
        
        for result in data.get("results", []):
            try:
                finding = self._semgrep_to_normalized(result)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to normalize Semgrep result: {e}")
        
        return SastInput(findings=findings)
    
    def _semgrep_to_normalized(self, result: dict) -> NormalizedFinding | None:
        """Convert a single Semgrep result to NormalizedFinding."""
        rule_id = result.get("check_id", "")
        message = result.get("extra", {}).get("message", "")
        metadata = result.get("extra", {}).get("metadata", {})
        
        # Detect vulnerability type
        vuln_type = self._detect_vuln_type(rule_id, message, metadata)
        if not vuln_type:
            logger.debug(f"Skipping unsupported rule: {rule_id}")
            return None
        
        # Extract endpoint from metadata or message
        endpoint = self._extract_endpoint(result)
        url = f"{self.target_base_url}{endpoint}"
        
        # Extract parameter name if mentioned
        param_name = self._extract_param_name(result)
        
        # Get severity
        severity = result.get("extra", {}).get("severity", "medium").lower()
        
        # Extract CWE/OWASP references
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):
            cwe = [cwe]
        owasp = metadata.get("owasp", [])
        if isinstance(owasp, str):
            owasp = [owasp]
        
        return NormalizedFinding(
            source_tool="semgrep",
            source_rule_id=rule_id,
            vuln_type=vuln_type,
            url=url,
            method=self._infer_method(result),
            param_name=param_name,
            payload_hint=self._get_witness_payload(vuln_type),
            witness_payload=self._get_witness_payload(vuln_type),
            severity=severity,
            message=message,
            file_path=result.get("path"),
            line_number=result.get("start", {}).get("line"),
        )
    
    def _normalize_generic(self, item: dict) -> NormalizedFinding:
        """Normalize a generic/custom format finding."""
        # Try to extract required fields
        vuln_type_str = item.get("vuln_type") or item.get("type") or item.get("vulnerability_type")
        
        if vuln_type_str:
            try:
                vuln_type = VulnType(vuln_type_str.lower())
            except ValueError:
                vuln_type = VulnType.OTHER
        else:
            # Try to detect from rule/message
            rule = item.get("rule") or item.get("rule_id") or ""
            message = item.get("message") or ""
            metadata = item.get("metadata", {})
            vuln_type = self._detect_vuln_type(rule, message, metadata)
            if not vuln_type:
                vuln_type = VulnType.OTHER
        
        # Build URL
        endpoint = item.get("endpoint") or item.get("path") or item.get("url") or "/"
        if endpoint.startswith("http"):
            url = endpoint
        else:
            url = f"{self.target_base_url}{endpoint}"
        
        # Extract CWE/OWASP
        cwe = item.get("cwe", [])
        if isinstance(cwe, str):
            cwe = [cwe]
        owasp = item.get("owasp", [])
        if isinstance(owasp, str):
            owasp = [owasp]
        
        return NormalizedFinding(
            source_tool=item.get("tool") or item.get("source") or "unknown",
            source_rule_id=item.get("rule_id") or item.get("rule") or "custom",
            vuln_type=vuln_type,
            url=url,
            method=item.get("method", "GET").upper(),
            param_name=item.get("param") or item.get("parameter") or item.get("param_name"),
            param_location=item.get("param_location", "query"),
            payload_hint=item.get("payload") or item.get("payload_hint") or self._get_witness_payload(vuln_type),
            witness_payload=self._get_witness_payload(vuln_type),
            severity=item.get("severity", "medium").lower(),
            message=item.get("message") or item.get("description") or "",
            file_path=item.get("file") or item.get("file_path"),
            line_number=item.get("line") or item.get("line_number"),
            cwe=cwe,
            owasp=owasp,
            metadata=item.get("metadata", {}),
        )
    
    def _detect_vuln_type(
        self, 
        rule_id: str, 
        message: str,
        metadata: dict | None = None
    ) -> VulnType | None:
        """Detect vulnerability type from rule ID, message, and metadata."""
        text = f"{rule_id} {message}".lower()
        
        # First check CWE mappings if available
        if metadata:
            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            for cwe in cwe_list:
                if cwe in CWE_TO_VULN_TYPE:
                    return CWE_TO_VULN_TYPE[cwe]
            
            # Check vulnerability_class from Semgrep
            vuln_classes = metadata.get("vulnerability_class", [])
            if isinstance(vuln_classes, str):
                vuln_classes = [vuln_classes]
            for vc in vuln_classes:
                vc_lower = vc.lower()
                if "xss" in vc_lower or "cross-site-scripting" in vc_lower:
                    return VulnType.XSS
                if "sql" in vc_lower and "injection" in vc_lower:
                    return VulnType.SQLI
                if "command" in vc_lower and "injection" in vc_lower:
                    return VulnType.CMDI
                if "ssrf" in vc_lower or "request-forgery" in vc_lower:
                    return VulnType.SSRF
        
        # Then check rule patterns
        for pattern, vuln_type in RULE_TO_VULN_TYPE.items():
            if re.search(pattern, text, re.IGNORECASE):
                return vuln_type
        
        return None
    
    def _extract_endpoint(self, result: dict) -> str:
        """Extract endpoint from Semgrep result."""
        # Try metadata first
        metadata = result.get("extra", {}).get("metadata", {})
        if "endpoint" in metadata:
            return metadata["endpoint"]
        
        # Try to extract from message
        message = result.get("extra", {}).get("message", "")
        
        # Look for URL patterns in message
        url_match = re.search(r'["\']?(/[a-zA-Z0-9_/\-{}:]+)["\']?', message)
        if url_match:
            return url_match.group(1)
        
        # Fallback to path-based inference from file
        file_path = result.get("path", "")
        if "routes" in file_path or "controllers" in file_path:
            # Try to infer from file structure
            parts = Path(file_path).stem.split("_")
            if parts:
                return f"/{parts[0]}"
        
        return "/"
    
    def _extract_param_name(self, result: dict) -> str | None:
        """Extract parameter name from result."""
        message = result.get("extra", {}).get("message", "")
        
        # Look for common patterns
        patterns = [
            r'parameter\s+["\']?(\w+)["\']?',
            r'param\s+["\']?(\w+)["\']?',
            r'["\'](\w+)["\']?\s+parameter',
            r'req\.(query|body|params)\.(\w+)',
            r'request\.(get|post|params)\[["\'](\w+)["\']\]',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(match.lastindex)
        
        return None
    
    def _infer_method(self, result: dict) -> str:
        """Infer HTTP method from result."""
        message = result.get("extra", {}).get("message", "").lower()
        
        if "post" in message or "body" in message:
            return "POST"
        if "put" in message:
            return "PUT"
        if "delete" in message:
            return "DELETE"
        if "patch" in message:
            return "PATCH"
        
        return "GET"
