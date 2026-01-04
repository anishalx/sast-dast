"""
Rate Limit Handling Utilities

Multi-layered approach for handling OpenAI API rate limits:
1. Intelligent retry logic with exponential backoff
2. Rate-limit-specific delays (longer than other errors)
3. Error detection and classification
"""

import logging
import random
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for rate limit handling."""
    max_retries: int = 3
    stagger_delay: float = 2.0  # Delay between parallel agent starts
    rate_limit_base_delay: float = 30.0  # Base delay for rate limits
    rate_limit_increment: float = 15.0  # Increment per retry for rate limits
    rate_limit_max_delay: float = 120.0  # Maximum delay for rate limits
    other_error_base_delay: float = 2.0  # Base delay for other errors
    other_error_max_delay: float = 30.0  # Maximum delay for other errors
    jitter_range: float = 1.0  # Random jitter to add (0-1 seconds)


# Default configuration
DEFAULT_CONFIG = RateLimitConfig()


def is_rate_limit_error(error: Exception) -> bool:
    """
    Check if an error is specifically a rate limit error.
    
    Rate limit indicators for OpenAI:
    - HTTP 429 status code
    - "rate limit" in message
    - "too many requests" in message
    - "quota exceeded" in message
    """
    message = str(error).lower()
    
    rate_limit_patterns = [
        "rate limit",
        "rate_limit",
        "429",
        "too many requests",
        "quota exceeded",
        "rate exceeded",
        "requests per minute",
        "tokens per minute",
        "tpm limit",
        "rpm limit",
    ]
    
    return any(pattern in message for pattern in rate_limit_patterns)


def is_retryable_error(error: Exception) -> bool:
    """
    Check if an error should trigger a retry.
    
    Retryable errors:
    - Rate limits (with longer backoff)
    - Network/connection errors
    - Temporary API errors (500, 502, 503, 504)
    - Timeout errors
    
    Non-retryable errors:
    - Authentication errors (401, 403)
    - Invalid request errors (400)
    - Not found errors (404)
    """
    message = str(error).lower()
    
    # Rate limiting - always retryable
    if is_rate_limit_error(error):
        return True
    
    # Network/connection errors - retryable
    network_patterns = [
        "connection",
        "network",
        "timeout",
        "timed out",
        "temporarily unavailable",
        "service unavailable",
        "bad gateway",
        "gateway timeout",
    ]
    if any(pattern in message for pattern in network_patterns):
        return True
    
    # Server errors (5xx) - retryable
    server_error_patterns = ["500", "502", "503", "504", "internal server error"]
    if any(pattern in message for pattern in server_error_patterns):
        return True
    
    # Authentication errors - NOT retryable (invalid API key won't fix itself)
    auth_patterns = ["401", "403", "invalid_api_key", "invalid api key", "authentication"]
    if any(pattern in message for pattern in auth_patterns):
        return False
    
    # Default: not retryable
    return False


def get_retry_delay(
    error: Exception,
    attempt: int,
    config: Optional[RateLimitConfig] = None
) -> float:
    """
    Get retry delay based on error type and attempt number.
    
    Rate limits get longer delays:
    - Attempt 1: 30s
    - Attempt 2: 45s
    - Attempt 3: 60s
    - Maximum: 120s
    
    Other errors use exponential backoff:
    - Attempt 1: 2s
    - Attempt 2: 4s
    - Attempt 3: 8s
    - Maximum: 30s
    
    Args:
        error: The exception that occurred
        attempt: Current attempt number (1-based)
        config: Optional rate limit configuration
    
    Returns:
        Delay in seconds before retrying
    """
    if config is None:
        config = DEFAULT_CONFIG
    
    # Add random jitter to prevent thundering herd
    jitter = random.uniform(0, config.jitter_range)
    
    if is_rate_limit_error(error):
        # Rate limit: linear increase with higher base
        # 30s, 45s, 60s, ...
        delay = config.rate_limit_base_delay + ((attempt - 1) * config.rate_limit_increment)
        delay = min(delay, config.rate_limit_max_delay)
        logger.debug(f"Rate limit detected, delay: {delay}s (attempt {attempt})")
    else:
        # Other errors: exponential backoff
        # 2s, 4s, 8s, ...
        delay = config.other_error_base_delay * (2 ** (attempt - 1))
        delay = min(delay, config.other_error_max_delay)
        logger.debug(f"Retryable error, delay: {delay}s (attempt {attempt})")
    
    return delay + jitter


def format_retry_message(
    error: Exception,
    attempt: int,
    max_attempts: int,
    delay: float,
    context: str = ""
) -> str:
    """
    Format a user-friendly retry message.
    
    Args:
        error: The exception that occurred
        attempt: Current attempt number
        max_attempts: Maximum number of attempts
        delay: Delay before retry
        context: Optional context (e.g., "XSS validation")
    
    Returns:
        Formatted message string
    """
    error_type = "Rate limit" if is_rate_limit_error(error) else "Error"
    context_str = f" for {context}" if context else ""
    
    return (
        f"⚠️ {error_type}{context_str} (attempt {attempt}/{max_attempts})\n"
        f"    Error: {str(error)[:100]}\n"
        f"    Retrying in {delay:.1f}s..."
    )


class RetryExhausted(Exception):
    """Exception raised when all retry attempts are exhausted."""
    
    def __init__(self, original_error: Exception, attempts: int):
        self.original_error = original_error
        self.attempts = attempts
        super().__init__(
            f"All {attempts} retry attempts exhausted. "
            f"Original error: {original_error}"
        )
