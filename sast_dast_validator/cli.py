#!/usr/bin/env python3
"""
SAST-to-DAST Validator CLI

Takes static analysis findings (JSON) and dynamically validates them
using Browser-Use to reduce false positives.

Features:
- Parallel execution with configurable workers
- Multiple vulnerability type support
- Screenshot capture on confirmed vulnerabilities
- GIF recording for demos
- Cloud browser support
- Authentication support (cookies, login scripts)
- CI/CD integration (exit codes, SARIF output)
- Rate limiting to avoid WAF triggers

Usage:
    python -m browser_use.security.validator.cli --input findings.json --target http://localhost:3000 --output results.json

    # With parallel execution
    python -m browser_use.security.validator.cli -i findings.json -t http://localhost:3000 --workers 10 --parallel

    # With authentication
    python -m browser_use.security.validator.cli -i findings.json -t http://localhost:3000 --cookies cookies.json

    # For CI/CD with SARIF output
    python -m browser_use.security.validator.cli -i findings.json -t http://localhost:3000 --sarif results.sarif --fail-on-high

Example input JSON:
{
    "findings": [
        {
            "vuln_type": "xss",
            "url": "/search",
            "param_name": "q",
            "source_tool": "semgrep",
            "source_rule_id": "javascript.browser.security.xss"
        }
    ]
}
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import click

from sast_dast_validator.models import (
    SastInput,
    ValidationOutput,
    ValidationStatus,
)
from sast_dast_validator.normalizer import SastNormalizer
from sast_dast_validator.executor import DynamicValidator, ValidatorConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--input", "-i", "input_file",
    type=click.Path(exists=True),
    required=True,
    help="Path to JSON file with SAST findings (Semgrep or normalized format)"
)
@click.option(
    "--target", "-t",
    required=True,
    help="Target base URL (e.g., http://localhost:3000)"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output JSON file for results (default: stdout)"
)
@click.option(
    "--model", "-m",
    default="gpt-4o-mini",
    help="LLM model to use (default: gpt-4o-mini)"
)
@click.option(
    "--headless/--no-headless",
    default=True,
    help="Run browser in headless mode (default: headless)"
)
@click.option(
    "--timeout",
    default=90,
    type=int,
    help="Timeout per test in seconds (default: 90)"
)
@click.option(
    "--max-steps",
    default=6,
    type=int,
    help="Maximum agent steps per test (default: 6)"
)
@click.option(
    "--workers", "-w",
    default=1,
    type=int,
    help="Number of parallel workers (default: 1, increase if you have higher API rate limits)"
)
@click.option(
    "--delay",
    default=0.5,
    type=float,
    help="Delay between tests in seconds for rate limiting (default: 0.5)"
)
@click.option(
    "--cookies",
    type=click.Path(exists=True),
    help="Path to JSON file with cookies for authentication"
)
@click.option(
    "--screenshots/--no-screenshots",
    default=True,
    help="Capture screenshots on confirmed vulnerabilities (default: yes)"
)
@click.option(
    "--evidence-dir",
    type=click.Path(),
    help="Directory to save evidence files (screenshots, etc.)"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose logging"
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Minimal output (only results)"
)
def main(
    input_file: str,
    target: str,
    output: str | None,
    model: str,
    headless: bool,
    timeout: int,
    max_steps: int,
    workers: int,
    delay: float,
    cookies: str | None,
    screenshots: bool,
    evidence_dir: str | None,
    verbose: bool,
    quiet: bool,
):
    """
    Validate SAST findings dynamically using Browser-Use.
    
    Takes a JSON file with static analysis findings, tests each one
    against the target application, and reports which are confirmed
    vulnerabilities vs false positives.
    
    Examples:
    
        # Basic usage
        sast-dast -i semgrep.json -t http://localhost:3000
        
        # With authentication and multiple workers
        sast-dast -i findings.json -t http://app.local --workers 5 --cookies auth.json -o results.json
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Run async main
    exit_code = asyncio.run(_async_main(
        input_file=input_file,
        target=target,
        output=output,
        model=model,
        headless=headless,
        timeout=timeout,
        max_steps=max_steps,
        workers=workers,
        delay=delay,
        cookies_file=cookies,
        capture_screenshots=screenshots,
        evidence_dir=Path(evidence_dir) if evidence_dir else None,
        quiet=quiet,
    ))
    
    sys.exit(exit_code)


async def _async_main(
    input_file: str,
    target: str,
    output: str | None,
    model: str,
    headless: bool,
    timeout: int,
    max_steps: int,
    workers: int,
    delay: float,
    cookies_file: str | None,
    capture_screenshots: bool,
    evidence_dir: Path | None,
    quiet: bool,
) -> int:
    """Async main function. Returns exit code."""
    from browser_use import ChatOpenAI
    
    start_time = datetime.now(timezone.utc)
    
    if not quiet:
        _print_banner()
        logger.info(f"Input: {input_file}")
        logger.info(f"Target: {target}")
        logger.info(f"Model: {model}")
        logger.info(f"Workers: {workers}")
        logger.info(f"Headless: {headless}")
        logger.info("=" * 60)
    
    # Load and normalize findings
    logger.info("Loading SAST findings...")
    normalizer = SastNormalizer(target_base_url=target)
    
    try:
        sast_input = normalizer.normalize_file(input_file)
    except Exception as e:
        logger.error(f"Failed to load/normalize input file: {e}")
        return 2
    
    findings = sast_input.findings
    logger.info(f"Loaded {len(findings)} findings")
    
    # Check target connectivity before starting
    logger.info(f"Checking target connectivity: {target}")
    try:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(target, ssl=False) as resp:
                logger.info(f"✅ Target reachable (status: {resp.status})")
    except Exception as e:
        logger.error(f"❌ Cannot reach target {target}: {e}")
        logger.error("Make sure your target application is running!")
        logger.error("Example: Start your app with 'npm start' or 'python app.py'")
        return 3
    
    if not findings:
        logger.warning("No findings to validate!")
        return 0
    
    # Load cookies if provided
    cookies = None
    if cookies_file:
        try:
            with open(cookies_file) as f:
                cookies = json.load(f)
            logger.info(f"Loaded {len(cookies)} cookies from {cookies_file}")
        except Exception as e:
            logger.error(f"Failed to load cookies: {e}")
            return 2
    
    # Initialize LLM
    logger.info(f"Initializing LLM: {model}")
    llm = ChatOpenAI(model=model)
    
    # Create evidence directory if needed
    if evidence_dir:
        evidence_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize validator with config
    config = ValidatorConfig(
        llm=llm,
        headless=headless,
        timeout=timeout,
        max_steps=max_steps,
        workers=workers,
        delay=delay,
        capture_screenshots=capture_screenshots,
        cookies=cookies,
        evidence_dir=evidence_dir,
    )
    
    validator = DynamicValidator(config=config)
    
    # Progress callback
    def on_progress(completed: int, total: int, result):
        if not quiet:
            status_emoji = {
                ValidationStatus.CONFIRMED: "🔴",
                ValidationStatus.FALSE_POSITIVE: "✅",
                ValidationStatus.NEEDS_REVIEW: "🟡",
                ValidationStatus.ERROR: "❌",
                ValidationStatus.SKIPPED: "⏭️",
            }
            emoji = status_emoji.get(result.status, "?")
            pct = int(completed / total * 100)
            logger.info(f"[{completed}/{total}] {pct}% {emoji} {result.status.value}")
    
    # Run validation
    logger.info("Starting dynamic validation...")
    results = await validator.validate_all(
        findings,
        on_progress=on_progress,
    )
    
    # Build output
    end_time = datetime.now(timezone.utc)
    total_duration = (end_time - start_time).total_seconds()
    
    validation_output = ValidationOutput(
        results=results,
        target_url=target,
        tested_at=start_time,
        total_duration_seconds=total_duration,
    )
    validation_output.compute_summary()
    
    # Print summary
    if not quiet:
        _print_summary(validation_output)
    
    # Output results as JSON
    output_data = validation_output.model_dump(mode="json")
    
    if output:
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        logger.info(f"Results written to: {output}")
    else:
        print(json.dumps(output_data, indent=2, default=str))
    
    # Determine exit code
    exit_code = validation_output.get_exit_code()
    
    if exit_code != 0:
        logger.warning(f"⚠️  Exiting with code {exit_code} (vulnerabilities confirmed)")
    
    return exit_code


def _print_banner():
    """Print CLI banner."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║           🔍 SAST-to-DAST Dynamic Validator                  ║
║              Powered by Browser-Use                          ║
╚══════════════════════════════════════════════════════════════╝
"""
    logger.info(banner)


def _print_summary(output: ValidationOutput):
    """Print validation summary."""
    logger.info("=" * 60)
    logger.info("VALIDATION COMPLETE")
    logger.info("=" * 60)
    logger.info(f"Total tested:     {output.summary.get('total', 0)}")
    logger.info(f"🔴 Confirmed:      {output.summary.get('confirmed', 0)}")
    logger.info(f"✅ False Positive: {output.summary.get('false_positive', 0)}")
    logger.info(f"🟡 Needs Review:   {output.summary.get('needs_review', 0)}")
    logger.info(f"❌ Errors:         {output.summary.get('error', 0)}")
    logger.info(f"⏭️  Skipped:        {output.summary.get('skipped', 0)}")
    logger.info(f"⏱️  Duration:       {output.total_duration_seconds:.1f}s")
    logger.info("=" * 60)
    
    # List confirmed vulnerabilities
    confirmed = [r for r in output.results if r.status == ValidationStatus.CONFIRMED]
    if confirmed:
        logger.info("\n🔴 CONFIRMED VULNERABILITIES:")
        for r in confirmed:
            logger.info(f"  - {r.finding_id}: {r.tested_url}")
            if r.evidence:
                logger.info(f"    Evidence: {r.evidence[:80]}...")


if __name__ == "__main__":
    main()
