"""
Security Testing Tools

Custom browser actions for dynamic security testing.
Provides specialized tools for vulnerability validation.
"""

import asyncio
import base64
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, quote

from pydantic import BaseModel, Field

from browser_use.tools.service import Tools
from browser_use.agent.views import ActionResult

logger = logging.getLogger(__name__)


class SecurityEvidence(BaseModel):
    """Evidence collected during security testing."""
    finding_id: str
    vuln_type: str
    payload: str
    success: bool = False
    evidence_text: str = ""
    screenshot_base64: str | None = None
    response_url: str | None = None
    response_status: int | None = None
    markers_found: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SecurityTestResult(BaseModel):
    """Result of a security test action."""
    vulnerable: bool = False
    evidence: str = ""
    payload_reflected: bool = False
    markers_detected: list[str] = Field(default_factory=list)
    response_info: dict[str, Any] = Field(default_factory=dict)


def create_security_tools(
    evidence_dir: Path | None = None,
    capture_screenshots: bool = True,
) -> Tools:
    """
    Create a Tools registry with security-specific actions.
    
    Args:
        evidence_dir: Directory to save evidence files
        capture_screenshots: Whether to capture screenshots on findings
        
    Returns:
        Tools registry with security actions
    """
    tools = Tools()
    
    # Storage for collected evidence
    _evidence_store: list[SecurityEvidence] = []
    
    @tools.action("Save evidence of a security finding")
    async def save_evidence(
        finding_id: str,
        vuln_type: str,
        payload: str,
        success: bool,
        evidence_text: str,
        browser: Any = None,
    ) -> ActionResult:
        """
        Save evidence of a security test result.
        
        Args:
            finding_id: ID of the finding being tested
            vuln_type: Type of vulnerability
            payload: Payload that was tested
            success: Whether the vulnerability was confirmed
            evidence_text: Description of what was observed
        """
        screenshot_b64 = None
        
        # Capture screenshot if enabled and browser available
        if capture_screenshots and success and browser:
            try:
                page = await browser.get_current_page()
                if page:
                    screenshot_bytes = await page.screenshot()
                    screenshot_b64 = base64.b64encode(screenshot_bytes).decode()
            except Exception as e:
                logger.debug(f"Failed to capture screenshot: {e}")
        
        evidence = SecurityEvidence(
            finding_id=finding_id,
            vuln_type=vuln_type,
            payload=payload,
            success=success,
            evidence_text=evidence_text,
            screenshot_base64=screenshot_b64,
        )
        
        _evidence_store.append(evidence)
        
        # Save to file if evidence_dir specified
        if evidence_dir:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            filename = f"evidence-{finding_id}-{int(time.time())}.json"
            filepath = evidence_dir / filename
            
            with open(filepath, "w") as f:
                json.dump(evidence.model_dump(mode="json"), f, indent=2, default=str)
            
            return ActionResult(
                extracted_content=f"Evidence saved to {filename}",
                long_term_memory=f"Saved evidence for {finding_id}: {success=}",
            )
        
        return ActionResult(
            extracted_content=f"Evidence recorded for {finding_id}",
            long_term_memory=f"Evidence for {finding_id}: {'VULNERABLE' if success else 'NOT VULNERABLE'}",
        )
    
    @tools.action("Test a payload by injecting it into a URL parameter")
    async def test_payload(
        url: str,
        param_name: str,
        payload: str,
        param_location: str = "query",
        browser: Any = None,
    ) -> ActionResult:
        """
        Inject a payload into a URL parameter and navigate.
        
        Args:
            url: Base URL to test
            param_name: Parameter to inject into
            payload: Payload to inject
            param_location: Where to inject (query, path, body)
        """
        test_url = _inject_payload_into_url(url, param_name, payload, param_location)
        
        if browser:
            try:
                page = await browser.get_current_page()
                if page:
                    await page.goto(test_url, wait_until="domcontentloaded", timeout=30000)
                    
                    # Get page info
                    current_url = page.url
                    title = await page.title()
                    
                    return ActionResult(
                        extracted_content=f"Navigated to test URL. Current URL: {current_url}, Title: {title}",
                        long_term_memory=f"Tested payload at {current_url}",
                    )
            except Exception as e:
                return ActionResult(
                    extracted_content=f"Navigation failed: {str(e)}",
                    error=str(e),
                )
        
        return ActionResult(
            extracted_content=f"Test URL constructed: {test_url}",
        )
    
    @tools.action("Check if a marker or payload is reflected in the page")
    async def check_reflection(
        marker: str,
        check_dom: bool = True,
        check_source: bool = True,
        browser: Any = None,
    ) -> ActionResult:
        """
        Check if a marker string is reflected in the page.
        
        Args:
            marker: The marker string to look for
            check_dom: Check visible DOM content
            check_source: Check page HTML source
        """
        if not browser:
            return ActionResult(
                extracted_content="No browser available",
                error="Browser not available",
            )
        
        try:
            page = await browser.get_current_page()
            if not page:
                return ActionResult(
                    extracted_content="No active page",
                    error="No active page",
                )
            
            found_in = []
            
            if check_dom:
                # Check visible text content
                text_content = await page.evaluate("() => document.body.innerText")
                if marker in text_content:
                    found_in.append("visible_text")
            
            if check_source:
                # Check HTML source
                html_content = await page.content()
                if marker in html_content:
                    found_in.append("html_source")
                
                # Check if marker is unescaped (potential XSS)
                if f">{marker}<" in html_content or f"'{marker}'" in html_content:
                    found_in.append("unescaped_html")
            
            if found_in:
                return ActionResult(
                    extracted_content=f"REFLECTED: Marker '{marker}' found in: {', '.join(found_in)}",
                    long_term_memory=f"Marker reflected in {found_in}",
                )
            else:
                return ActionResult(
                    extracted_content=f"NOT REFLECTED: Marker '{marker}' not found in page",
                )
                
        except Exception as e:
            return ActionResult(
                extracted_content=f"Check failed: {str(e)}",
                error=str(e),
            )
    
    @tools.action("Check for JavaScript alerts or dialogs")
    async def check_alert_dialog(
        timeout_ms: int = 2000,
        browser: Any = None,
    ) -> ActionResult:
        """
        Check if a JavaScript alert/confirm/prompt dialog appeared.
        
        Args:
            timeout_ms: How long to wait for dialog in milliseconds
        """
        if not browser:
            return ActionResult(
                extracted_content="No browser available",
            )
        
        try:
            page = await browser.get_current_page()
            if not page:
                return ActionResult(
                    extracted_content="No active page",
                )
            
            # Try to detect if there's a dialog
            dialog_detected = False
            dialog_message = None
            
            def handle_dialog(dialog):
                nonlocal dialog_detected, dialog_message
                dialog_detected = True
                dialog_message = dialog.message
                asyncio.create_task(dialog.dismiss())
            
            page.on("dialog", handle_dialog)
            
            # Wait briefly for any pending dialogs
            await asyncio.sleep(timeout_ms / 1000)
            
            page.remove_listener("dialog", handle_dialog)
            
            if dialog_detected:
                return ActionResult(
                    extracted_content=f"ALERT DETECTED: Dialog with message '{dialog_message}'",
                    long_term_memory=f"XSS alert detected: {dialog_message}",
                )
            else:
                return ActionResult(
                    extracted_content="No alert dialog detected",
                )
                
        except Exception as e:
            return ActionResult(
                extracted_content=f"Alert check failed: {str(e)}",
            )
    
    @tools.action("Check response headers for security issues")
    async def check_security_headers(
        url: str | None = None,
        browser: Any = None,
    ) -> ActionResult:
        """
        Check security headers in the HTTP response.
        
        Args:
            url: URL to check (uses current page if not specified)
        """
        import httpx
        
        check_url = url
        
        if not check_url and browser:
            try:
                page = await browser.get_current_page()
                if page:
                    check_url = page.url
            except Exception:
                pass
        
        if not check_url:
            return ActionResult(
                extracted_content="No URL to check",
                error="URL required",
            )
        
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(check_url)
                
                security_headers = {
                    "Content-Security-Policy": response.headers.get("content-security-policy"),
                    "X-Frame-Options": response.headers.get("x-frame-options"),
                    "X-Content-Type-Options": response.headers.get("x-content-type-options"),
                    "Strict-Transport-Security": response.headers.get("strict-transport-security"),
                    "X-XSS-Protection": response.headers.get("x-xss-protection"),
                    "Referrer-Policy": response.headers.get("referrer-policy"),
                }
                
                missing = [k for k, v in security_headers.items() if v is None]
                present = {k: v for k, v in security_headers.items() if v is not None}
                
                result = f"Security Headers Check:\n"
                result += f"- Present: {list(present.keys())}\n"
                result += f"- Missing: {missing}\n"
                
                if present:
                    result += f"- Values: {present}"
                
                return ActionResult(
                    extracted_content=result,
                    long_term_memory=f"Missing headers: {missing}",
                )
                
        except Exception as e:
            return ActionResult(
                extracted_content=f"Header check failed: {str(e)}",
                error=str(e),
            )
    
    @tools.action("Check for SQL injection indicators in response")
    async def check_sqli_indicators(
        browser: Any = None,
    ) -> ActionResult:
        """
        Check page content for SQL injection indicators like error messages.
        """
        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"PG::SyntaxError",
            r"ORA-\d{5}",
            r"Oracle.*Driver",
            r"SQLite.*error",
            r"sqlite3\.OperationalError",
            r"Microsoft.*ODBC.*Driver",
            r"SQLSTATE\[",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"SQL Server.*Error",
        ]
        
        if not browser:
            return ActionResult(
                extracted_content="No browser available",
            )
        
        try:
            page = await browser.get_current_page()
            if not page:
                return ActionResult(
                    extracted_content="No active page",
                )
            
            content = await page.content()
            
            found_indicators = []
            for pattern in sql_error_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_indicators.append(pattern)
            
            if found_indicators:
                return ActionResult(
                    extracted_content=f"SQL ERROR DETECTED: Found {len(found_indicators)} SQL error patterns",
                    long_term_memory=f"SQLi indicators: {found_indicators[:3]}",
                )
            else:
                return ActionResult(
                    extracted_content="No SQL error indicators found",
                )
                
        except Exception as e:
            return ActionResult(
                extracted_content=f"SQLi check failed: {str(e)}",
            )
    
    @tools.action("Check if redirected to external domain")
    async def check_redirect(
        original_domain: str,
        browser: Any = None,
    ) -> ActionResult:
        """
        Check if the browser was redirected to an external domain.
        
        Args:
            original_domain: The expected/original domain
        """
        if not browser:
            return ActionResult(
                extracted_content="No browser available",
            )
        
        try:
            page = await browser.get_current_page()
            if not page:
                return ActionResult(
                    extracted_content="No active page",
                )
            
            current_url = page.url
            current_domain = urlparse(current_url).netloc
            original = urlparse(original_domain).netloc if "://" in original_domain else original_domain
            
            if current_domain != original and current_domain not in original:
                return ActionResult(
                    extracted_content=f"REDIRECTED: External redirect detected! From '{original}' to '{current_domain}'",
                    long_term_memory=f"Open redirect to {current_domain}",
                )
            else:
                return ActionResult(
                    extracted_content=f"No external redirect. Current domain: {current_domain}",
                )
                
        except Exception as e:
            return ActionResult(
                extracted_content=f"Redirect check failed: {str(e)}",
            )
    
    # Attach evidence store getter
    tools._evidence_store = _evidence_store
    
    return tools


def _inject_payload_into_url(
    url: str, 
    param_name: str | None, 
    payload: str, 
    param_location: str = "query"
) -> str:
    """Inject a payload into a URL based on parameter location."""
    parsed = urlparse(url)
    encoded_payload = quote(payload, safe='')
    
    if not param_name:
        # No specific param, append to query string
        if parsed.query:
            new_query = f"{parsed.query}&test={encoded_payload}"
        else:
            new_query = f"test={encoded_payload}"
        return urlunparse(parsed._replace(query=new_query))
    
    if param_location == "query":
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    
    elif param_location == "path":
        new_path = parsed.path.replace(f"{{{param_name}}}", encoded_payload)
        new_path = new_path.replace(f":{param_name}", encoded_payload)
        return urlunparse(parsed._replace(path=new_path))
    
    # Default: append to query
    if parsed.query:
        new_query = f"{parsed.query}&{param_name}={encoded_payload}"
    else:
        new_query = f"{param_name}={encoded_payload}"
    return urlunparse(parsed._replace(query=new_query))


def get_evidence_store(tools: Tools) -> list[SecurityEvidence]:
    """Get the evidence store from a security tools instance."""
    return getattr(tools, '_evidence_store', [])
