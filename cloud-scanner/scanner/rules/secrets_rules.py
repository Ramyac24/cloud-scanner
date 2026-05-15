"""
secrets_rules.py
Regex patterns for detecting hardcoded secrets and credentials.
"""

import re
from dataclasses import dataclass


@dataclass
class SecretPattern:
    rule_id:     str
    name:        str
    pattern:     str           # compiled regex pattern string
    severity:    str           # CRITICAL | HIGH | MEDIUM
    description: str
    remediation: str
    # If True, run entropy check on captured group 1
    check_entropy: bool = False


# ── Pattern definitions ────────────────────────────────────────────────────────

SECRET_PATTERNS: list[SecretPattern] = [

    # AWS credentials
    SecretPattern(
        "SEC001", "AWS Access Key ID",
        r'(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
        "CRITICAL",
        "Hardcoded AWS Access Key ID detected. If committed to VCS this is a critical exposure.",
        "Remove immediately. Rotate the key in AWS IAM. Use environment variables or AWS Secrets Manager.",
    ),
    SecretPattern(
        "SEC002", "AWS Secret Access Key",
        r'(?i)aws.{0,20}secret.{0,20}["\']?([0-9a-zA-Z/+]{40})["\']?',
        "CRITICAL",
        "AWS Secret Access Key pattern detected.",
        "Remove and rotate. Use IAM roles, environment variables, or AWS Secrets Manager.",
        check_entropy=True,
    ),

    # Generic API keys
    SecretPattern(
        "SEC003", "Generic API Key",
        r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,64})["\']?',
        "HIGH",
        "Potential API key hardcoded in configuration.",
        "Move to environment variables or a secrets manager.",
        check_entropy=True,
    ),

    # Private keys
    SecretPattern(
        "SEC004", "Private Key (PEM)",
        r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "CRITICAL",
        "Private key material detected in file. This is a critical security risk.",
        "Never commit private keys. Use certificate stores or secrets managers.",
    ),

    # Passwords
    SecretPattern(
        "SEC005", "Hardcoded Password",
        r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\'$\s{][^"\'$\s]{5,})["\']',
        "HIGH",
        "Hardcoded password found in configuration.",
        "Use environment variables: password = var.db_password or a secrets manager reference.",
        check_entropy=True,
    ),

    # Database connection strings
    SecretPattern(
        "SEC006", "Database Connection String with Credentials",
        r'(?i)(postgres|mysql|mongodb|redis|mssql):\/\/[^:]+:[^@\s]+@',
        "CRITICAL",
        "Database connection string containing credentials detected.",
        "Use environment variables or Vault references for database URIs.",
    ),

    # GitHub tokens
    SecretPattern(
        "SEC007", "GitHub Personal Access Token",
        r'(?i)gh[pousr]_[0-9a-zA-Z]{36,255}',
        "CRITICAL",
        "GitHub Personal Access Token detected.",
        "Revoke immediately at github.com/settings/tokens. Use GitHub Actions secrets.",
    ),

    # Slack tokens / webhooks
    SecretPattern(
        "SEC008", "Slack Webhook / Token",
        r'(?i)(xox[baprs]-[0-9a-zA-Z\-]{10,}|https://hooks\.slack\.com/services/[A-Z0-9/]+)',
        "HIGH",
        "Slack API token or webhook URL detected.",
        "Rotate the Slack token/webhook. Store in environment variables.",
    ),

    # Google API keys
    SecretPattern(
        "SEC009", "Google API Key",
        r'AIza[0-9A-Za-z\-_]{35}',
        "HIGH",
        "Google API key detected.",
        "Restrict the key in Google Cloud Console and store in environment variables.",
    ),

    # JWT secrets
    SecretPattern(
        "SEC010", "JWT Secret / Signing Key",
        r'(?i)(jwt_secret|jwt_key|secret_key)\s*[=:]\s*["\']([^"\']{16,})["\']',
        "HIGH",
        "JWT signing secret hardcoded in configuration.",
        "Move JWT secrets to environment variables or a secrets manager.",
        check_entropy=True,
    ),

    # Terraform variable with sensitive default
    SecretPattern(
        "SEC011", "Terraform Variable with Hardcoded Sensitive Default",
        r'(?i)variable\s+["\']?(password|secret|key|token|credential)["\']?\s*\{[^}]*default\s*=\s*["\']([^"\'$\s]{6,})["\']',
        "HIGH",
        "Terraform variable for a sensitive field has a hardcoded default value.",
        "Remove the default value and mark the variable as sensitive = true.",
    ),

    # Stripe / payment keys
    SecretPattern(
        "SEC012", "Stripe API Key",
        r'(?i)(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}',
        "CRITICAL",
        "Stripe API key detected.",
        "Revoke and rotate at dashboard.stripe.com. Use environment variables.",
    ),

    # Generic high-entropy string assigned to sensitive variable
    SecretPattern(
        "SEC013", "High-Entropy Secret Assignment",
        r'(?i)(secret|token|key|password|credential|auth)\s*[=:]\s*["\']([A-Za-z0-9+/=]{32,})["\']',
        "MEDIUM",
        "High-entropy value assigned to a sensitive variable name.",
        "Verify this is not a real credential. Move secrets to environment variables.",
        check_entropy=True,
    ),
]


def get_compiled_patterns() -> list[tuple[SecretPattern, re.Pattern]]:
    """Return list of (SecretPattern, compiled_regex) pairs."""
    return [(sp, re.compile(sp.pattern, re.MULTILINE | re.DOTALL))
            for sp in SECRET_PATTERNS]


# ── Entropy helper ─────────────────────────────────────────────────────────────

import math

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. >3.5 is suspicious for a secret."""
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in counts.values())


ENTROPY_THRESHOLD = 3.5   # strings above this are likely real secrets
