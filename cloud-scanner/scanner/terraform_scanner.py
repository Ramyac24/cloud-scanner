"""
terraform_scanner.py
Parses Terraform (.tf) files and evaluates security rules.

Uses python-hcl2 for parsing, with a regex fallback for malformed files.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger("scanner.terraform")

try:
    import hcl2
    HCL2_AVAILABLE = True
except ImportError:
    HCL2_AVAILABLE = False
    logger.warning("python-hcl2 not available — using regex fallback parser")

from scanner.models import Finding, ScanResult, Severity, ScanType
from scanner.rules.terraform_rules import ALL_RULES


# ── HCL parser ─────────────────────────────────────────────────────────────────

def _parse_hcl2(content: str) -> dict:
    """Parse HCL2 content using python-hcl2."""
    import io
    return hcl2.load(io.StringIO(content))


def _parse_regex_fallback(content: str) -> list[tuple[str, str, dict, int]]:
    """
    Fallback HCL parser using regex.
    Returns list of (resource_type, resource_name, attributes_dict, line_number).
    Handles common Terraform patterns well enough for security scanning.
    """
    results = []

    # Match: resource "TYPE" "NAME" { ... }
    resource_pattern = re.compile(
        r'^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
        re.MULTILINE,
    )

    lines = content.split("\n")
    line_starts = [sum(len(l) + 1 for l in lines[:i]) for i in range(len(lines))]

    for m in resource_pattern.finditer(content):
        rtype = m.group(1)
        rname = m.group(2)
        start = m.end()
        line_num = content[:m.start()].count("\n") + 1

        # Extract the block body (naive brace matching)
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1
        block_body = content[start:i - 1]
        attrs = _extract_attrs(block_body)
        results.append((rtype, rname, attrs, line_num))

    return results


def _extract_attrs(body: str) -> dict:
    """
    Lightweight attribute extractor from an HCL block body.
    Handles: key = "value", key = true/false, key = 123,
             nested blocks, lists of strings.
    """
    attrs = {}

    # Nested block: name { ... }
    nested_pattern = re.compile(r'(\w+)\s*\{([^{}]*)\}', re.DOTALL)
    for nm in nested_pattern.finditer(body):
        key  = nm.group(1)
        inner = _extract_attrs(nm.group(2))
        if key in attrs:
            if not isinstance(attrs[key], list):
                attrs[key] = [attrs[key]]
            attrs[key].append(inner)
        else:
            attrs[key] = inner

    # Scalar: key = "value" or key = true/false/number
    scalar_pattern = re.compile(
        r'(\w+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(true|false|null)|([\d.]+))',
    )
    for sm in scalar_pattern.finditer(body):
        key = sm.group(1)
        val = (sm.group(2) or sm.group(3) or sm.group(4) or sm.group(5))
        if val is not None and key not in attrs:
            attrs[key] = val

    # List: key = ["a", "b"]
    list_pattern = re.compile(r'(\w+)\s*=\s*\[([^\]]*)\]')
    for lm in list_pattern.finditer(body):
        key  = lm.group(1)
        items_raw = lm.group(2)
        items = re.findall(r'"([^"]*)"', items_raw)
        if items and key not in attrs:
            attrs[key] = items

    return attrs


def _hcl2_to_resource_list(parsed: dict) -> list[tuple[str, str, dict, int]]:
    """Convert hcl2 parsed dict to (rtype, rname, block, line) tuples."""
    results = []
    for resource_entry in parsed.get("resource", []):
        for rtype, instances in resource_entry.items():
            for rname, blocks in instances.items():
                block = blocks[0] if isinstance(blocks, list) else blocks
                results.append((rtype, rname, block, None))
    return results


# ── Main scanner ───────────────────────────────────────────────────────────────

class TerraformScanner:
    """Scans Terraform .tf files for security misconfigurations."""

    TF_EXTENSIONS = {".tf"}

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single .tf file. Returns list of Finding objects."""
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"Cannot read {file_path}: {e}")
            return findings

        resources = self._parse(content, file_path)

        for rtype, rname, block, line in resources:
            for rule_fn in ALL_RULES:
                try:
                    new_findings = rule_fn(rtype, rname, block,
                                           str(file_path), line)
                    findings.extend(new_findings)
                except Exception as e:
                    logger.debug(f"Rule {rule_fn.__name__} error on {rtype}.{rname}: {e}")

        return findings

    def scan_directory(self, root: Path, result: ScanResult):
        """Recursively scan all .tf files under root."""
        tf_files = list(root.rglob("*.tf"))
        for tf_file in tf_files:
            if ".terraform" in str(tf_file):
                continue   # skip provider cache
            logger.info(f"Scanning {tf_file}")
            findings = self.scan_file(tf_file)
            for f in findings:
                result.add(f)
            result.files_scanned += 1

    def _parse(self, content: str, file_path: Path) -> list[tuple]:
        """Try hcl2 first, fall back to regex."""
        if HCL2_AVAILABLE:
            try:
                parsed = _parse_hcl2(content)
                return _hcl2_to_resource_list(parsed)
            except Exception as e:
                logger.debug(f"hcl2 parse failed for {file_path}: {e} — using regex")
        return _parse_regex_fallback(content)
