"""
Dynamic Validator Executor

Uses Browser-Use to dynamically test normalized SAST findings.

Features:
- Parallel execution with configurable workers
- Category-specific validators (XSS, SQLi, SSRF, SSTI, etc.)
- Screenshot capture on confirmed vulnerabilities
- GIF recording support
- Rate limiting between tests
- Cloud browser support
- Authentication support (cookies, login scripts)
"""

import asyncio
import base64
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, quote

from sast_dast_validator.models import (
    NormalizedFinding,
    ValidationResult,
    ValidationStatus,
    VulnType,
    VulnCategory,
    EvidenceData,
)
from sast_dast_validator.prompts import format_prompt, get_template_for_category
from sast_dast_validator.payload_generator import (
    PayloadGenerator,
    PayloadContext,
    GeneratedPayload,
    PayloadTester,
)
from sast_dast_validator.rate_limit import (
    is_retryable_error,
    is_rate_limit_error,
    get_retry_delay,
    format_retry_message,
    RateLimitConfig,
)

logger = logging.getLogger(__name__)


def _is_vulnerable(result_text: str) -> bool:
    """Check if result indicates vulnerability (excludes NOT_VULNERABLE)."""
    upper = result_text.upper()
    # Must have VULNERABLE but not NOT_VULNERABLE or FALSE_POSITIVE
    if "NOT_VULNERABLE" in upper or "FALSE_POSITIVE" in upper:
        return False
    return upper.startswith("VULNERABLE") or ": VULNERABLE" in upper or "VULNERABLE:" in upper


# ============================================================================
# Payload Definitions
# ============================================================================

XSS_PAYLOADS = [
    {"payload": "<script>alert('BU_XSS_TEST')</script>", "marker": "BU_XSS_TEST"},
    {"payload": "<img src=x onerror=alert('BU_XSS_IMG')>", "marker": "BU_XSS_IMG"},
    {"payload": "'\"><script>alert('BU_XSS_QUOTE')</script>", "marker": "BU_XSS_QUOTE"},
    {"payload": "<svg onload=alert('BU_XSS_SVG')>", "marker": "BU_XSS_SVG"},
]

SQLI_PAYLOADS = [
    {"payload": "' OR '1'='1' --", "marker": "error", "type": "error-based"},
    {"payload": "' AND '1'='1", "marker": None, "type": "boolean-true"},
    {"payload": "' AND '1'='2", "marker": None, "type": "boolean-false"},
    {"payload": "' AND SLEEP(3) --", "marker": None, "type": "time-based"},
]

SSTI_PAYLOADS = [
    {"payload": "{{7*7}}", "marker": "49", "engine": "jinja2/twig"},
    {"payload": "${7*7}", "marker": "49", "engine": "freemarker"},
    {"payload": "{{7*'7'}}", "marker": "7777777", "engine": "jinja2"},
    {"payload": "<%= 7*7 %>", "marker": "49", "engine": "erb"},
]

SSRF_PAYLOADS = [
    {"payload": "http://127.0.0.1:22", "marker": "connection", "type": "port-scan"},
    {"payload": "http://169.254.169.254/latest/meta-data/", "marker": "ami-id", "type": "aws-metadata"},
    {"payload": "file:///etc/passwd", "marker": "root:", "type": "file-read"},
]

REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "https://evil.example.com%2F%2E%2E",
    "https://trusted.com@evil.example.com",
]

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options", 
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
]


# ============================================================================
# Configuration
# ============================================================================

class ValidatorConfig:
    """Configuration for the dynamic validator."""
    
    def __init__(
        self,
        llm: Any = None,
        headless: bool = True,
        timeout: int = 90,
        max_steps: int = 6,
        workers: int = 1,
        delay: float = 0.5,
        capture_screenshots: bool = True,
        generate_gif: bool = False,
        use_cloud: bool = False,
        cookies: list[dict] | None = None,
        initial_actions: list | None = None,
        evidence_dir: Path | None = None,
        use_vision: bool = True,
    ):
        self.llm = llm
        self.headless = headless
        self.timeout = timeout
        self.max_steps = max_steps
        self.workers = workers
        self.delay = delay
        self.capture_screenshots = capture_screenshots
        self.generate_gif = generate_gif
        self.use_cloud = use_cloud
        self.cookies = cookies or []
        self.initial_actions = initial_actions
        self.evidence_dir = evidence_dir
        self.use_vision = use_vision


# ============================================================================
# Dynamic Validator
# ============================================================================

class DynamicValidator:
    """
    Validates SAST findings dynamically using Browser-Use.
    
    For each finding:
    1. Constructs test URL with payload
    2. Uses browser agent to navigate and observe
    3. Analyzes response to determine if vulnerable
    
    Supports parallel execution with configurable workers.
    """
    
    def __init__(
        self,
        llm: Any = None,
        headless: bool = True,
        timeout: int = 90,
        max_steps: int = 6,
        workers: int = 1,
        delay: float = 0.5,
        capture_screenshots: bool = True,
        generate_gif: bool = False,
        use_cloud: bool = False,
        cookies: list[dict] | None = None,
        initial_actions: list | None = None,
        evidence_dir: Path | None = None,
        config: ValidatorConfig | None = None,
    ):
        """
        Initialize the validator.
        
        Args:
            llm: Language model for the agent
            headless: Run browser in headless mode
            timeout: Timeout per test in seconds
            max_steps: Maximum agent steps per test
            workers: Number of parallel workers
            delay: Delay between tests in seconds (rate limiting)
            capture_screenshots: Capture screenshots on confirmed vulns
            generate_gif: Generate GIF recordings
            use_cloud: Use cloud browser
            cookies: Cookies for authentication
            initial_actions: Actions to run before testing (login script)
            evidence_dir: Directory to save evidence
            config: ValidatorConfig object (overrides other params)
        """
        if config:
            self.config = config
        else:
            self.config = ValidatorConfig(
                llm=llm,
                headless=headless,
                timeout=timeout,
                max_steps=max_steps,
                workers=workers,
                delay=delay,
                capture_screenshots=capture_screenshots,
                generate_gif=generate_gif,
                use_cloud=use_cloud,
                cookies=cookies,
                initial_actions=initial_actions,
                evidence_dir=evidence_dir,
            )
        
        # For backward compatibility
        self.llm = self.config.llm
        self.headless = self.config.headless
        self.timeout = self.config.timeout
        self.max_steps = self.config.max_steps
        
        # Semaphore for parallel execution
        self._semaphore = asyncio.Semaphore(self.config.workers)
        
        # Progress tracking
        self._completed = 0
        self._total = 0
        
        # Dynamic payload generator (LLM-powered)
        self.payload_generator = PayloadGenerator(llm=self.config.llm)
    
    async def validate_all(
        self, 
        findings: list[NormalizedFinding],
        parallel: bool = True,
        on_progress: Callable[[int, int, ValidationResult], None] | None = None,
    ) -> list[ValidationResult]:
        """
        Validate all findings.
        
        Args:
            findings: List of normalized findings to validate
            parallel: Run tests in parallel
            on_progress: Callback for progress updates (completed, total, result)
        
        Returns:
            List of validation results
        """
        self._total = len(findings)
        self._completed = 0
        
        logger.info(f"Starting validation of {len(findings)} findings...")
        logger.info(f"Workers: {self.config.workers}, Parallel: {parallel}")
        
        if parallel:
            results = await self._validate_parallel(findings, on_progress)
        else:
            results = await self._validate_sequential(findings, on_progress)
        
        return results
    
    async def _validate_parallel(
        self,
        findings: list[NormalizedFinding],
        on_progress: Callable[[int, int, ValidationResult], None] | None = None,
    ) -> list[ValidationResult]:
        """
        Validate findings in parallel with:
        - Staggered execution (2s delay between starts to prevent API overwhelm)
        - Retry logic with exponential backoff for rate limits
        - Fault-tolerant execution (one failure doesn't stop others)
        """
        stagger_delay = 2.0  # Delay between parallel agent starts
        max_retries = 3
        
        async def validate_with_stagger_and_retry(
            finding: NormalizedFinding,
            index: int
        ) -> ValidationResult:
            """Validate with staggered start and retry logic."""
            # Stagger: Add delay based on index to prevent API overwhelm
            # Agent 0: starts immediately
            # Agent 1: starts after 2s
            # Agent 2: starts after 4s
            # etc.
            if index > 0:
                await asyncio.sleep(index * stagger_delay)
                logger.debug(f"Agent {index} starting after {index * stagger_delay}s stagger")
            
            async with self._semaphore:
                last_error = None
                
                for attempt in range(1, max_retries + 1):
                    try:
                        result = await self._validate_one_safe(finding)
                        self._completed += 1
                        
                        if on_progress:
                            on_progress(self._completed, self._total, result)
                        
                        # Rate limiting between successful tests
                        if self.config.delay > 0:
                            await asyncio.sleep(self.config.delay)
                        
                        return result
                        
                    except Exception as e:
                        last_error = e
                        
                        # Check if error is retryable
                        if is_retryable_error(e) and attempt < max_retries:
                            delay = get_retry_delay(e, attempt)
                            
                            # Log retry message
                            if is_rate_limit_error(e):
                                logger.warning(
                                    f"⚠️ Rate limit hit for finding {finding.id} "
                                    f"(attempt {attempt}/{max_retries}), "
                                    f"retrying in {delay:.1f}s..."
                                )
                            else:
                                logger.warning(
                                    f"⚠️ Retryable error for finding {finding.id} "
                                    f"(attempt {attempt}/{max_retries}): {str(e)[:80]}, "
                                    f"retrying in {delay:.1f}s..."
                                )
                            
                            await asyncio.sleep(delay)
                        else:
                            # Non-retryable or max retries exhausted
                            if attempt >= max_retries:
                                logger.error(
                                    f"❌ All {max_retries} retries exhausted for finding {finding.id}"
                                )
                            break
                
                # All retries exhausted - return error result
                self._completed += 1
                error_result = ValidationResult(
                    finding_id=finding.id,
                    status=ValidationStatus.ERROR,
                    tested_url=finding.url,
                    evidence=f"ERROR: {str(last_error)[:200]}" if last_error else "ERROR: Unknown error",
                )
                
                if on_progress:
                    on_progress(self._completed, self._total, error_result)
                
                return error_result
        
        # Create tasks with staggered execution
        tasks = [
            validate_with_stagger_and_retry(finding, index)
            for index, finding in enumerate(findings)
        ]
        
        # Fault-tolerant execution: return_exceptions=True means
        # one failure doesn't stop others
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert any exceptions to error results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Unexpected exception for finding {findings[i].id}: {result}")
                final_results.append(ValidationResult(
                    finding_id=findings[i].id,
                    status=ValidationStatus.ERROR,
                    tested_url=findings[i].url,
                    evidence=f"ERROR: Unexpected exception - {str(result)[:150]}",
                ))
            else:
                final_results.append(result)
        
        return final_results
    
    async def _validate_sequential(
        self,
        findings: list[NormalizedFinding],
        on_progress: Callable[[int, int, ValidationResult], None] | None = None,
    ) -> list[ValidationResult]:
        """Validate findings sequentially."""
        results = []
        
        for i, finding in enumerate(findings, 1):
            logger.info(f"[{i}/{len(findings)}] Validating: {finding.vuln_type.value} at {finding.url}")
            
            result = await self._validate_one_safe(finding)
            results.append(result)
            self._completed += 1
            
            if on_progress:
                on_progress(self._completed, self._total, result)
            
            self._log_result(result)
            
            # Rate limiting
            if self.config.delay > 0:
                await asyncio.sleep(self.config.delay)
        
        return results
    
    async def _validate_one_safe(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate one finding with error handling."""
        try:
            return await self.validate_one(finding)
        except Exception as e:
            logger.error(f"Error validating finding {finding.id}: {e}")
            return ValidationResult(
                finding_id=finding.id,
                status=ValidationStatus.ERROR,
                tested_url=finding.url,
                evidence=f"Validation error: {str(e)}",
            )
    
    def _log_result(self, result: ValidationResult):
        """Log a validation result."""
        status_emoji = {
            ValidationStatus.CONFIRMED: "🔴",
            ValidationStatus.FALSE_POSITIVE: "✅",
            ValidationStatus.NEEDS_REVIEW: "🟡",
            ValidationStatus.ERROR: "❌",
            ValidationStatus.SKIPPED: "⏭️",
        }
        emoji = status_emoji.get(result.status, "?")
        evidence_preview = result.evidence[:100] if result.evidence else "No evidence"
        logger.info(f"  {emoji} {result.status.value}: {evidence_preview}")
    
    async def validate_one(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate a single finding based on its type."""
        start_time = time.time()
        
        # Get the appropriate validator
        category = finding.get_category()
        
        validators = {
            VulnCategory.XSS: self._validate_xss,
            VulnCategory.INJECTION: self._validate_injection,
            VulnCategory.SSRF: self._validate_ssrf,
            VulnCategory.REDIRECT: self._validate_open_redirect,
            VulnCategory.ACCESS_CONTROL: self._validate_access_control,
            VulnCategory.SECRETS: self._validate_secrets,
            VulnCategory.HEADERS: self._validate_missing_headers,
            VulnCategory.CRYPTO: self._validate_crypto,
            VulnCategory.OTHER: self._validate_generic,
        }
        
        validator = validators.get(category, self._validate_generic)
        
        try:
            result = await asyncio.wait_for(
                validator(finding),
                timeout=self.timeout
            )
            result.duration_seconds = time.time() - start_time
            return result
        except asyncio.TimeoutError:
            return ValidationResult(
                finding_id=finding.id,
                status=ValidationStatus.ERROR,
                tested_url=finding.url,
                evidence=f"Test timed out after {self.timeout} seconds",
                duration_seconds=time.time() - start_time,
            )
    
    def _create_browser_session(self):
        """Create a browser session with configured settings."""
        from browser_use import Browser
        
        browser_kwargs = {
            "headless": self.headless,
            "minimum_wait_page_load_time": 0.3,
            "wait_for_network_idle_page_load_time": 1.0,
            "wait_between_actions": 0.2,
        }
        
        if self.config.use_cloud:
            browser_kwargs["use_cloud"] = True
        
        return Browser(**browser_kwargs)
    
    async def _apply_cookies(self, browser) -> None:
        """Apply authentication cookies to the browser."""
        if not self.config.cookies:
            return
        
        try:
            page = await browser.get_current_page()
            if page:
                context = page.context
                await context.add_cookies(self.config.cookies)
                logger.debug(f"Applied {len(self.config.cookies)} cookies")
        except Exception as e:
            logger.warning(f"Failed to apply cookies: {e}")
    
    async def _capture_screenshot(self, browser) -> str | None:
        """Capture screenshot and return as base64."""
        if not self.config.capture_screenshots:
            return None
        
        try:
            page = await browser.get_current_page()
            if page:
                screenshot_bytes = await page.screenshot()
                return base64.b64encode(screenshot_bytes).decode()
        except Exception as e:
            logger.debug(f"Failed to capture screenshot: {e}")
        
        return None
    
    async def _save_screenshot(self, browser, finding_id: str) -> str | None:
        """Save screenshot to evidence directory and return path."""
        if not self.config.evidence_dir or not self.config.capture_screenshots:
            return None
        
        try:
            page = await browser.get_current_page()
            if page:
                self.config.evidence_dir.mkdir(parents=True, exist_ok=True)
                filename = f"screenshot-{finding_id}-{int(time.time())}.png"
                filepath = self.config.evidence_dir / filename
                await page.screenshot(path=str(filepath))
                return str(filepath)
        except Exception as e:
            logger.debug(f"Failed to save screenshot: {e}")
        
        return None
    
    # ========================================================================
    # XSS Validation
    # ========================================================================
    
    async def _validate_xss(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate XSS vulnerability using browser agent with dynamic payloads."""
        from browser_use import Agent, Browser
        
        # Generate dynamic payloads using LLM
        payloads = await self.payload_generator.generate_payloads(finding, num_payloads=5)
        
        if not payloads:
            # Fallback to static payload
            payload = finding.payload_hint or XSS_PAYLOADS[0]["payload"]
            marker = "XSS"
        else:
            # Use first generated payload
            gp = payloads[0]
            payload = gp.payload
            marker = gp.marker or "XSS"
        
        test_url = self._inject_payload(finding, payload)
        
        # Format prompt from template
        prompt_template = get_template_for_category("xss")
        task = format_prompt(
            prompt_template,
            url=test_url,
            param_name=finding.param_name or "",
            payload=payload,
            marker=marker,
            vuln_type="XSS",
            message=finding.message,
        )
        
        browser = self._create_browser_session()
        
        try:
            await browser.start()
            await self._apply_cookies(browser)
            
            agent = Agent(
                task=task,
                llm=self.llm,
                browser=browser,
                use_vision=False,
                generate_gif=self.config.generate_gif,
                initial_actions=self.config.initial_actions,
                flash_mode=True,  # Use fast mode
            )
            
            try:
                history = await asyncio.wait_for(
                    agent.run(max_steps=self.max_steps),
                    timeout=self.timeout
                )
                result_text = history.final_result() or ""
            except asyncio.TimeoutError:
                result_text = "BLOCKED: Test timed out"
            except Exception as e:
                result_text = f"BLOCKED: Agent error - {str(e)[:100]}"
            
            is_vulnerable = _is_vulnerable(result_text)
            is_blocked = "BLOCKED" in result_text.upper()
            is_error = not result_text or result_text.strip() == ""
            
            if is_error:
                status = ValidationStatus.ERROR
                result_text = "ERROR: LLM agent failed - no result returned (check API key)"
            elif is_vulnerable:
                status = ValidationStatus.CONFIRMED
            elif is_blocked:
                status = ValidationStatus.NEEDS_REVIEW
            else:
                status = ValidationStatus.FALSE_POSITIVE
            
            screenshot_path = None
            screenshot_b64 = None
            if is_vulnerable:
                screenshot_path = await self._save_screenshot(browser, finding.id)
                screenshot_b64 = await self._capture_screenshot(browser)
            
            return ValidationResult(
                finding_id=finding.id,
                status=status,
                is_vulnerable=is_vulnerable,
                tested_url=test_url,
                tested_payload=payload,
                evidence=result_text,
                agent_reasoning=result_text,
                screenshot_path=screenshot_path,
                screenshot_base64=screenshot_b64,
                gif_path=str(agent._gif_path) if self.config.generate_gif and hasattr(agent, '_gif_path') else None,
            )
        finally:
            try:
                await browser.close()
            except Exception as e:
                logger.debug(f"Error stopping browser: {e}")
    
    # ========================================================================
    # Injection Validation (SQLi, CMDi, SSTI)
    # ========================================================================
    
    async def _validate_injection(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate injection vulnerabilities (SQLi, CMDi, SSTI, etc.) with dynamic payloads."""
        from browser_use import Agent, Browser
        
        # Determine vulnerability name for prompt
        vuln_name_map = {
            VulnType.SQLI: "SQLi",
            VulnType.INJECTION: "SQLi",
            VulnType.SSTI: "SSTI",
            VulnType.CMDI: "Command Injection",
            VulnType.CODE_INJECTION: "Code Injection",
        }
        vuln_name = vuln_name_map.get(finding.vuln_type, "Injection")
        
        # Generate dynamic payloads using LLM
        generated_payloads = await self.payload_generator.generate_payloads(finding, num_payloads=5)
        
        if generated_payloads:
            gp = generated_payloads[0]
            payload = gp.payload
            marker = gp.marker or ""
        elif finding.payload_hint:
            payload = finding.payload_hint
            marker = ""
        else:
            # Fallback to static payload
            if finding.vuln_type in (VulnType.SQLI, VulnType.INJECTION):
                payload = SQLI_PAYLOADS[0]["payload"]
                marker = SQLI_PAYLOADS[0].get("marker", "")
            elif finding.vuln_type == VulnType.SSTI:
                payload = SSTI_PAYLOADS[0]["payload"]
                marker = SSTI_PAYLOADS[0].get("marker", "")
            elif finding.vuln_type == VulnType.CMDI:
                payload = "; echo BU_CMD_TEST"
                marker = "BU_CMD_TEST"
            else:
                payload = SQLI_PAYLOADS[0]["payload"]
                marker = ""
        
        test_url = self._inject_payload(finding, payload)
        
        # Format prompt
        prompt_template = get_template_for_category("injection")
        task = format_prompt(
            prompt_template,
            url=test_url,
            param_name=finding.param_name or "",
            payload=payload,
            marker=marker,
            vuln_type=vuln_name,
            message=finding.message,
        )
        
        browser = self._create_browser_session()
        
        try:
            await browser.start()
            await self._apply_cookies(browser)
            
            agent = Agent(
                task=task,
                llm=self.llm,
                browser=browser,
                use_vision=False,
                generate_gif=self.config.generate_gif,
                initial_actions=self.config.initial_actions,
                flash_mode=True,
            )
            
            try:
                history = await asyncio.wait_for(
                    agent.run(max_steps=self.max_steps),
                    timeout=self.timeout
                )
                result_text = history.final_result() or ""
            except asyncio.TimeoutError:
                result_text = "BLOCKED: Test timed out"
            except Exception as e:
                result_text = f"BLOCKED: Agent error - {str(e)[:100]}"
            
            is_vulnerable = _is_vulnerable(result_text)
            is_blocked = "BLOCKED" in result_text.upper()
            is_error = not result_text or result_text.strip() == ""
            
            if is_error:
                status = ValidationStatus.ERROR
                result_text = "ERROR: LLM agent failed - no result returned (check API key)"
            elif is_vulnerable:
                status = ValidationStatus.CONFIRMED
            elif is_blocked:
                status = ValidationStatus.NEEDS_REVIEW
            else:
                status = ValidationStatus.FALSE_POSITIVE
            
            screenshot_path = None
            if is_vulnerable:
                screenshot_path = await self._save_screenshot(browser, finding.id)
            
            return ValidationResult(
                finding_id=finding.id,
                status=status,
                is_vulnerable=is_vulnerable,
                tested_url=test_url,
                tested_payload=payload,
                evidence=result_text,
                agent_reasoning=result_text,
                screenshot_path=screenshot_path,
            )
        finally:
            try:
                await browser.close()
            except Exception as e:
                logger.debug(f"Error stopping browser: {e}")
    
    # ========================================================================
    # SSRF Validation
    # ========================================================================
    
    async def _validate_ssrf(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate SSRF vulnerability with dynamic payloads."""
        from browser_use import Agent, Browser
        
        # Generate dynamic payloads using LLM
        generated_payloads = await self.payload_generator.generate_payloads(finding, num_payloads=5)
        
        if generated_payloads:
            gp = generated_payloads[0]
            payload = gp.payload
        elif finding.payload_hint:
            payload = finding.payload_hint
        else:
            payload = SSRF_PAYLOADS[0]["payload"]
        
        test_url = self._inject_payload(finding, payload)
        
        prompt_template = get_template_for_category("ssrf")
        task = format_prompt(
            prompt_template,
            url=test_url,
            param_name=finding.param_name or "",
            payload=payload,
            vuln_type="SSRF",
            message=finding.message,
        )
        
        browser = self._create_browser_session()
        
        try:
            await browser.start()
            await self._apply_cookies(browser)
            
            agent = Agent(
                task=task,
                llm=self.llm,
                browser=browser,
                use_vision=False,
                initial_actions=self.config.initial_actions,
                flash_mode=True,
            )
            
            try:
                history = await asyncio.wait_for(
                    agent.run(max_steps=self.max_steps),
                    timeout=self.timeout
                )
                result_text = history.final_result() or ""
            except asyncio.TimeoutError:
                result_text = "BLOCKED: Test timed out"
            except Exception as e:
                result_text = f"BLOCKED: Agent error - {str(e)[:100]}"
            
            is_vulnerable = _is_vulnerable(result_text)
            is_error = not result_text or result_text.strip() == ""
            
            if is_error:
                status = ValidationStatus.ERROR
                result_text = "ERROR: LLM agent failed - no result returned (check API key)"
            elif is_vulnerable:
                status = ValidationStatus.CONFIRMED
            elif "NEEDS_REVIEW" in result_text.upper():
                status = ValidationStatus.NEEDS_REVIEW
            else:
                status = ValidationStatus.FALSE_POSITIVE
            
            screenshot_path = None
            if is_vulnerable:
                screenshot_path = await self._save_screenshot(browser, finding.id)
            
            return ValidationResult(
                finding_id=finding.id,
                status=status,
                is_vulnerable=is_vulnerable,
                tested_url=test_url,
                tested_payload=payload,
                evidence=result_text,
                agent_reasoning=result_text,
                screenshot_path=screenshot_path,
            )
        finally:
            try:
                await browser.close()
            except Exception as e:
                logger.debug(f"Error stopping browser: {e}")
    
    # ========================================================================
    # Open Redirect Validation
    # ========================================================================
    
    async def _validate_open_redirect(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate Open Redirect vulnerability with dynamic payloads."""
        from browser_use import Agent, Browser
        
        # Generate dynamic payloads using LLM
        generated_payloads = await self.payload_generator.generate_payloads(finding, num_payloads=5)
        
        if generated_payloads:
            payload = generated_payloads[0].payload
        elif finding.payload_hint:
            payload = finding.payload_hint
        else:
            payload = REDIRECT_PAYLOADS[0]
        
        test_url = self._inject_payload(finding, payload)
        
        prompt_template = get_template_for_category("redirect")
        task = format_prompt(
            prompt_template,
            url=test_url,
            param_name=finding.param_name or "",
            payload=payload,
            vuln_type="Open Redirect",
            message=finding.message,
        )
        
        browser = self._create_browser_session()
        
        try:
            await browser.start()
            await self._apply_cookies(browser)
            
            agent = Agent(
                task=task,
                llm=self.llm,
                browser=browser,
                use_vision=False,
                initial_actions=self.config.initial_actions,
                flash_mode=True,
            )
            
            try:
                history = await asyncio.wait_for(
                    agent.run(max_steps=self.max_steps),
                    timeout=self.timeout
                )
                result_text = history.final_result() or ""
            except asyncio.TimeoutError:
                result_text = "BLOCKED: Test timed out"
            except Exception as e:
                result_text = f"BLOCKED: Agent error - {str(e)[:100]}"
            
            is_vulnerable = _is_vulnerable(result_text)
            is_error = not result_text or result_text.strip() == ""
            
            if is_error:
                status = ValidationStatus.ERROR
                result_text = "ERROR: LLM agent failed - no result returned (check API key)"
            elif is_vulnerable:
                status = ValidationStatus.CONFIRMED
            else:
                status = ValidationStatus.FALSE_POSITIVE
            
            return ValidationResult(
                finding_id=finding.id,
                status=status,
                is_vulnerable=is_vulnerable,
                tested_url=test_url,
                tested_payload=payload,
                evidence=result_text,
                agent_reasoning=result_text,
            )
        finally:
            try:
                await browser.close()
            except Exception as e:
                logger.debug(f"Error stopping browser: {e}")
    
    # ========================================================================
    # Access Control (IDOR, Auth Bypass)
    # ========================================================================
    
    async def _validate_access_control(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate access control vulnerabilities (IDOR, auth bypass) with dynamic payloads."""
        from browser_use import Agent, Browser
        
        # Generate dynamic payloads using LLM
        generated_payloads = await self.payload_generator.generate_payloads(finding, num_payloads=5)
        
        if generated_payloads:
            payload = generated_payloads[0].payload
        elif finding.payload_hint:
            payload = finding.payload_hint
        else:
            payload = "99999"  # Default IDOR payload
        
        test_url = self._inject_payload(finding, payload)
        
        prompt_template = get_template_for_category("access_control")
        task = format_prompt(
            prompt_template,
            url=test_url,
            param_name=finding.param_name or "",
            payload=payload,
            vuln_type=finding.vuln_type.value,
            message=finding.message,
        )
        
        browser = self._create_browser_session()
        
        try:
            await browser.start()
            await self._apply_cookies(browser)
            
            agent = Agent(
                task=task,
                llm=self.llm,
                browser=browser,
                use_vision=False,
                initial_actions=self.config.initial_actions,
                flash_mode=True,
            )
            
            try:
                history = await asyncio.wait_for(
                    agent.run(max_steps=self.max_steps),
                    timeout=self.timeout
                )
                result_text = history.final_result() or ""
            except asyncio.TimeoutError:
                result_text = "BLOCKED: Test timed out"
            except Exception as e:
                result_text = f"BLOCKED: Agent error - {str(e)[:100]}"
            
            is_vulnerable = _is_vulnerable(result_text)
            is_error = not result_text or result_text.strip() == ""
            
            if is_error:
                status = ValidationStatus.ERROR
                result_text = "ERROR: LLM agent failed - no result returned (check API key)"
            elif is_vulnerable:
                status = ValidationStatus.CONFIRMED
            else:
                status = ValidationStatus.FALSE_POSITIVE
            
            screenshot_path = None
            if is_vulnerable:
                screenshot_path = await self._save_screenshot(browser, finding.id)
            
            return ValidationResult(
                finding_id=finding.id,
                status=status,
                is_vulnerable=is_vulnerable,
                tested_url=test_url,
                tested_payload=payload,
                evidence=result_text,
                agent_reasoning=result_text,
                screenshot_path=screenshot_path,
            )
        finally:
            try:
                await browser.close()
            except Exception as e:
                logger.debug(f"Error stopping browser: {e}")
    
    # ========================================================================
    # Secrets Validation
    # ========================================================================
    
    async def _validate_secrets(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate secrets/credentials exposure."""
        from browser_use import Agent, Browser
        
        prompt_template = get_template_for_category("secrets")
        task = format_prompt(
            prompt_template,
            url=finding.url,
            param_name=finding.param_name or "",
            vuln_type=finding.vuln_type.value,
            message=finding.message,
            file_path=finding.file_path or "",
            line_number=finding.line_number,
        )
        
        browser = self._create_browser_session()
        
        try:
            await browser.start()
            
            agent = Agent(
                task=task,
                llm=self.llm,
                browser=browser,
                use_vision=False,
                flash_mode=True,
            )
            
            try:
                history = await asyncio.wait_for(
                    agent.run(max_steps=4),
                    timeout=self.timeout
                )
                result_text = history.final_result() or ""
            except asyncio.TimeoutError:
                result_text = "BLOCKED: Test timed out"
            except Exception as e:
                result_text = f"BLOCKED: Agent error - {str(e)[:100]}"
            
            is_vulnerable = _is_vulnerable(result_text)
            is_false_positive = "FALSE_POSITIVE" in result_text.upper()
            
            if is_vulnerable:
                status = ValidationStatus.CONFIRMED
            elif is_false_positive:
                status = ValidationStatus.FALSE_POSITIVE
            else:
                status = ValidationStatus.NEEDS_REVIEW
            
            return ValidationResult(
                finding_id=finding.id,
                status=status,
                is_vulnerable=is_vulnerable,
                tested_url=finding.url,
                evidence=result_text,
                agent_reasoning=result_text,
            )
        finally:
            try:
                await browser.close()
            except Exception as e:
                logger.debug(f"Error stopping browser: {e}")
    
    # ========================================================================
    # Missing Headers Validation
    # ========================================================================
    
    async def _validate_missing_headers(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate Missing Security Headers - uses HTTP request, not browser."""
        import httpx
        
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                response = await client.get(finding.url)
                
                missing = []
                present = []
                
                for header in SECURITY_HEADERS:
                    if header.lower() in [h.lower() for h in response.headers.keys()]:
                        present.append(header)
                    else:
                        missing.append(header)
                
                is_vulnerable = len(missing) > 0
                
                evidence = f"Missing headers: {', '.join(missing)}" if missing else "All security headers present"
                if present:
                    evidence += f"\nPresent headers: {', '.join(present)}"
                
                return ValidationResult(
                    finding_id=finding.id,
                    status=ValidationStatus.CONFIRMED if is_vulnerable else ValidationStatus.FALSE_POSITIVE,
                    is_vulnerable=is_vulnerable,
                    tested_url=finding.url,
                    http_status=response.status_code,
                    evidence=evidence,
                    response_snippet=str(dict(response.headers))[:500],
                )
        except Exception as e:
            return ValidationResult(
                finding_id=finding.id,
                status=ValidationStatus.ERROR,
                tested_url=finding.url,
                evidence=f"HTTP request failed: {str(e)}",
            )
    
    # ========================================================================
    # Crypto Validation
    # ========================================================================
    
    async def _validate_crypto(self, finding: NormalizedFinding) -> ValidationResult:
        """Validate cryptographic issues - typically static analysis only."""
        # Crypto issues are usually not dynamically testable
        # Return as needs_review for manual verification
        return ValidationResult(
            finding_id=finding.id,
            status=ValidationStatus.NEEDS_REVIEW,
            is_vulnerable=False,
            tested_url=finding.url,
            evidence=f"Crypto issue requires code review. Static finding: {finding.message}",
            agent_reasoning="Cryptographic vulnerabilities typically require code review rather than dynamic testing.",
        )
    
    # ========================================================================
    # Generic Validation
    # ========================================================================
    
    async def _validate_generic(self, finding: NormalizedFinding) -> ValidationResult:
        """Generic validation for unsupported/other vulnerability types."""
        from browser_use import Agent, Browser
        
        payload = finding.payload_hint or finding.witness_payload or ""
        test_url = self._inject_payload(finding, payload) if payload else finding.url
        
        prompt_template = get_template_for_category("other")
        task = format_prompt(
            prompt_template,
            url=test_url,
            param_name=finding.param_name or "",
            payload=payload,
            vuln_type=finding.vuln_type.value,
            message=finding.message,
        )
        
        browser = self._create_browser_session()
        
        try:
            await browser.start()
            await self._apply_cookies(browser)
            
            agent = Agent(
                task=task,
                llm=self.llm,
                browser=browser,
                use_vision=False,
                initial_actions=self.config.initial_actions,
                flash_mode=True,
            )
            
            try:
                history = await asyncio.wait_for(
                    agent.run(max_steps=self.max_steps),
                    timeout=self.timeout
                )
                result_text = history.final_result() or ""
            except asyncio.TimeoutError:
                result_text = "BLOCKED: Test timed out"
            except Exception as e:
                result_text = f"BLOCKED: Agent error - {str(e)[:100]}"
            
            is_vulnerable = _is_vulnerable(result_text)
            is_blocked = "BLOCKED" in result_text.upper()
            
            if is_vulnerable:
                status = ValidationStatus.CONFIRMED
            elif is_blocked:
                status = ValidationStatus.NEEDS_REVIEW
            else:
                status = ValidationStatus.FALSE_POSITIVE
            
            return ValidationResult(
                finding_id=finding.id,
                status=status,
                is_vulnerable=is_vulnerable,
                tested_url=test_url,
                tested_payload=payload,
                evidence=result_text,
                agent_reasoning=result_text,
            )
        finally:
            try:
                await browser.close()
            except Exception as e:
                logger.debug(f"Error stopping browser: {e}")
    
    # ========================================================================
    # Utility Methods
    # ========================================================================
    
    def _inject_payload(self, finding: NormalizedFinding, payload: str) -> str:
        """Inject payload into the URL based on param location."""
        parsed = urlparse(finding.url)
        
        # URL-encode the payload for safe transmission
        encoded_payload = quote(payload, safe='')
        
        if not finding.param_name:
            # No specific param, append to query string
            if parsed.query:
                new_query = f"{parsed.query}&test={encoded_payload}"
            else:
                new_query = f"test={encoded_payload}"
            return urlunparse(parsed._replace(query=new_query))
        
        if finding.param_location == "query":
            # Add/replace in query string
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[finding.param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        
        elif finding.param_location == "path":
            # Replace in path (e.g., /user/{id})
            new_path = parsed.path.replace(f"{{{finding.param_name}}}", encoded_payload)
            new_path = new_path.replace(f":{finding.param_name}", encoded_payload)
            return urlunparse(parsed._replace(path=new_path))
        
        # Default: append to query
        if parsed.query:
            new_query = f"{parsed.query}&{finding.param_name}={encoded_payload}"
        else:
            new_query = f"{finding.param_name}={encoded_payload}"
        return urlunparse(parsed._replace(query=new_query))
