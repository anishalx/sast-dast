"""
Security Validator Prompt Templates

Category-specific prompt templates for dynamic security testing.
"""

from pathlib import Path

PROMPTS_DIR = Path(__file__).parent


def get_prompt_template(template_name: str) -> str:
    """
    Load a prompt template by name.
    
    Args:
        template_name: Name of the template file (e.g., 'exploit_xss.md')
        
    Returns:
        The template content as a string
    """
    template_path = PROMPTS_DIR / template_name
    
    if not template_path.exists():
        # Fall back to generic template
        template_path = PROMPTS_DIR / "exploit_generic.md"
    
    return template_path.read_text()


def format_prompt(
    template_name: str,
    url: str = "",
    param_name: str = "",
    payload: str = "",
    marker: str = "",
    vuln_type: str = "",
    message: str = "",
    file_path: str = "",
    line_number: int | None = None,
    **kwargs
) -> str:
    """
    Load and format a prompt template with the given variables.
    
    Args:
        template_name: Name of the template file
        url: Target URL
        param_name: Parameter name to test
        payload: Test payload
        marker: Expected marker in response
        vuln_type: Vulnerability type
        message: Original finding message
        file_path: Source file path
        line_number: Line number in source
        **kwargs: Additional template variables
        
    Returns:
        Formatted prompt string
    """
    template = get_prompt_template(template_name)
    
    # Build replacements dict
    replacements = {
        "{url}": url,
        "{param_name}": param_name or "N/A",
        "{payload}": payload,
        "{marker}": marker or "TEST_MARKER",
        "{vuln_type}": vuln_type,
        "{message}": message,
        "{file_path}": file_path or "N/A",
        "{line_number}": str(line_number) if line_number else "N/A",
    }
    
    # Add any extra kwargs
    for key, value in kwargs.items():
        replacements[f"{{{key}}}"] = str(value) if value is not None else "N/A"
    
    # Apply replacements
    result = template
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    
    return result


# Template name mapping by category
CATEGORY_TEMPLATES = {
    "xss": "exploit_xss.md",
    "injection": "exploit_injection.md",
    "ssrf": "exploit_ssrf.md",
    "redirect": "exploit_redirect.md",
    "access_control": "exploit_access.md",
    "secrets": "exploit_secrets.md",
    "crypto": "exploit_secrets.md",  # Use secrets template
    "headers": "exploit_headers.md",
    "other": "exploit_generic.md",
}


def get_template_for_category(category: str) -> str:
    """Get the template filename for a vulnerability category."""
    return CATEGORY_TEMPLATES.get(category, "exploit_generic.md")
