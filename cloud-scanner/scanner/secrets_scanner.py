"""
secrets_scanner.py
Scans files for hardcoded secrets, credentials, and API keys.
Supports any text file: .tf, .env, .yaml, .json, .py, .sh, etc.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger("scanner.secrets")

from scanner.models import Finding, ScanResult, Severity, ScanType
from scanner.rules.secrets_rules import (
    get_compiled_patterns, shannon_entropy, ENTROPY_THRESHOLD
)

# File extensions to scan
SCAN_EXTENSIONS = {
    ".tf", ".tfvars", ".env", ".yaml", ".yml",
    ".json", ".sh", ".bash", ".py", ".rb",
    ".properties", ".conf", ".config", ".ini",
    ".toml", ".xml", ".php", ".js", ".ts",
}

# Files / directories to always skip
SKIP_NAMES = {
    ".git", ".venv", "node_modules", "__pycache__",
    ".terraform", "vendor", "dist", "build",
}

# Max file size to scan (bytes) — skip huge files
MAX_FILE_SIZE = 500_000


class SecretsScanner:
    """Scans files for hardcoded secrets using regex + entropy analysis."""

    def __init__(self):
        self._compiled = get_compiled_patterns()

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single file. Returns list of Finding objects."""
        findings = []

        if file_path.stat().st_size > MAX_FILE_SIZE:
            logger.debug(f"Skipping large file: {file_path}")
            return findings

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.debug(f"Cannot read {file_path}: {e}")
            return findings

        lines = content.split("\n")

        for pattern, compiled_re in self._compiled:
            for match in compiled_re.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                matched_text = match.group(0)

                # Entropy check if required
                if pattern.check_entropy:
                    # Extract candidate secret (last non-empty group)
                    secret_candidate = ""
                    for g in reversed(match.groups()):
                        if g:
                            secret_candidate = g
                            break
                    if secret_candidate and shannon_entropy(secret_candidate) < ENTROPY_THRESHOLD:
                        logger.debug(
                            f"Low entropy ({shannon_entropy(secret_candidate):.2f}) "
                            f"for pattern {pattern.rule_id} — skipping"
                        )
                        continue

                # Redact the finding evidence (show context but mask secret)
                evidence = self._redact(matched_text, match)
                line_ctx = lines[line_num - 1].strip()[:120] if line_num <= len(lines) else ""

                findings.append(Finding(
                    rule_id=pattern.rule_id,
                    title=pattern.name,
                    severity=Severity(pattern.severity),
                    scan_type=ScanType.SECRET,
                    file_path=str(file_path),
                    line_number=line_num,
                    resource=None,
                    description=pattern.description,
                    evidence=evidence or line_ctx,
                    remediation=pattern.remediation,
                ))

        return self._deduplicate(findings)

    def scan_directory(self, root: Path, result: ScanResult):
        """Recursively scan all supported files under root."""
        for file_path in root.rglob("*"):
            # Skip unwanted directories
            if any(skip in file_path.parts for skip in SKIP_NAMES):
                continue
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() not in SCAN_EXTENSIONS:
                continue

            findings = self.scan_file(file_path)
            for f in findings:
                result.add(f)
            if findings:
                result.files_scanned += 1

    @staticmethod
    def _redact(text: str, match: re.Match) -> str:
        """Partially redact the matched secret for safe display."""
        full = text.strip()
        # Find the secret portion (last capture group) and mask middle chars
        groups = [g for g in match.groups() if g]
        if groups:
            secret = groups[-1]
            if len(secret) > 8:
                visible = secret[:4] + "***" + secret[-4:]
                full = full.replace(secret, visible)
        if len(full) > 120:
            full = full[:117] + "..."
        return full

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings (same rule + same line)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.rule_id, f.file_path, f.line_number)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
