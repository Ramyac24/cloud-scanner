"""
cli.py
Command-line interface for the Cloud Misconfiguration Scanner.

Usage
-----
python cli.py scan ./my-terraform-dir
python cli.py scan ./my-terraform-dir --ai
python cli.py scan ./my-terraform-dir --format html --output report.html
python cli.py scan ./my-terraform-dir --severity HIGH
python cli.py check-ai
python cli.py list-rules
"""

import sys
import os
import argparse
import logging
from pathlib import Path
from uuid import uuid4

from rich.console import Console

# Make project root importable
sys.path.insert(0, os.path.dirname(__file__))

from scanner.models import ScanResult, Severity
from scanner.terraform_scanner import TerraformScanner
from scanner.secrets_scanner import SecretsScanner
from ai.analyzer import analyze_findings_batch, check_ollama
import reporter

console = Console()

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)


# ── scan ───────────────────────────────────────────────────────────────────────

def cmd_scan(args):
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    target_path = Path(args.target).expanduser().resolve()
    if not target_path.exists():
        console.print(f"[red]Error: path does not exist: {target_path}[/red]")
        sys.exit(1)

    scan_id = str(uuid4())[:8]
    result  = ScanResult(scan_id=scan_id, target=str(target_path))

    console.print(f"\n[bold cyan]☁  Cloud Scanner[/bold cyan] — scanning [cyan]{target_path}[/cyan]")

    # ── Run scanners ──────────────────────────────────────────────────────────
    if args.terraform:
        tf_scanner = TerraformScanner()
        if target_path.is_file() and target_path.suffix == ".tf":
            for f in tf_scanner.scan_file(target_path):
                result.add(f)
            result.files_scanned += 1
        elif target_path.is_dir():
            tf_scanner.scan_directory(target_path, result)

    if args.secrets:
        sec_scanner = SecretsScanner()
        if target_path.is_file():
            for f in sec_scanner.scan_file(target_path):
                result.add(f)
        elif target_path.is_dir():
            sec_scanner.scan_directory(target_path, result)

    # ── Filter by severity ────────────────────────────────────────────────────
    display_findings = result.findings
    if args.severity:
        try:
            min_sev   = Severity(args.severity.upper())
            sev_order = list(Severity)
            min_idx   = sev_order.index(min_sev)
            display_findings = [
                f for f in result.findings
                if sev_order.index(f.severity) <= min_idx
            ]
        except ValueError:
            console.print(f"[yellow]Unknown severity '{args.severity}' — showing all[/yellow]")

    # ── AI analysis ───────────────────────────────────────────────────────────
    if args.ai:
        ok, msg = check_ollama(args.model)
        if ok:
            console.print(f"[green]🤖 {msg}[/green]")
            analyze_findings_batch(display_findings, model=args.model)
        else:
            console.print(f"[yellow]⚠  AI offline — {msg}[/yellow]")

    # ── Output ────────────────────────────────────────────────────────────────
    reporter.print_summary(result)

    if args.format == "terminal" or not args.output:
        result.findings = display_findings
        reporter.print_findings(result)

    if args.output:
        out_path = Path(args.output)
        ext = out_path.suffix.lower()
        if ext == ".html" or args.format == "html":
            reporter.save_html(result, out_path)
        else:
            reporter.save_json(result, out_path)
    elif args.format == "json":
        import json
        console.print_json(json.dumps(result.to_dict(), indent=2, default=str))
    elif args.format == "html":
        out_path = Path(f"report_{scan_id}.html")
        reporter.save_html(result, out_path)

    # Exit code 1 if CRITICAL/HIGH (useful for CI/CD)
    has_critical = any(f.severity in (Severity.CRITICAL, Severity.HIGH)
                       for f in result.findings)
    sys.exit(1 if has_critical else 0)


# ── check-ai ───────────────────────────────────────────────────────────────────

def cmd_check_ai(args):
    ok, msg = check_ollama(args.model)
    if ok:
        console.print(f"[green]✓ {msg}[/green]")
    else:
        console.print(f"[red]✗ {msg}[/red]")
        sys.exit(1)


# ── list-rules ─────────────────────────────────────────────────────────────────

def cmd_list_rules(args):
    from rich.table import Table
    from rich import box as rbox
    from scanner.rules.terraform_rules import ALL_RULES
    from scanner.rules.secrets_rules import SECRET_PATTERNS

    t = Table(title="Terraform Rules", box=rbox.SIMPLE, header_style="bold cyan")
    t.add_column("Rule ID")
    t.add_column("Name")
    t.add_column("Function")
    for fn in ALL_RULES:
        t.add_row("TFxxx", fn.__name__.replace("rule_", "").replace("_", " ").title(), fn.__name__)
    console.print(t)

    t2 = Table(title="Secret Patterns", box=rbox.SIMPLE, header_style="bold magenta")
    t2.add_column("Rule ID")
    t2.add_column("Name")
    t2.add_column("Severity")
    for sp in SECRET_PATTERNS:
        t2.add_row(sp.rule_id, sp.name, sp.severity)
    console.print(t2)


# ── Argument parser ────────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="☁  AI-Powered Cloud Misconfiguration Scanner",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan a directory or file")
    p_scan.add_argument("target", help="Path to directory or file to scan")
    p_scan.add_argument("--ai",       action="store_true", default=False,
                        help="Enable AI-powered explanations (requires Ollama)")
    p_scan.add_argument("--model", "-m", default="llama3.2",
                        help="Ollama model (default: llama3.2)")
    p_scan.add_argument("--severity", "-s", default="",
                        help="Min severity to display: CRITICAL|HIGH|MEDIUM|LOW|INFO")
    p_scan.add_argument("--output", "-o", default="",
                        help="Save report to file (.json or .html)")
    p_scan.add_argument("--format", "-f", default="terminal",
                        choices=["terminal", "json", "html"],
                        help="Output format (default: terminal)")
    p_scan.add_argument("--no-terraform", dest="terraform",
                        action="store_false", default=True,
                        help="Disable Terraform scanner")
    p_scan.add_argument("--no-secrets", dest="secrets",
                        action="store_false", default=True,
                        help="Disable secrets scanner")
    p_scan.add_argument("--verbose", "-v", action="store_true", default=False,
                        help="Show INFO-level logs")
    p_scan.set_defaults(func=cmd_scan)

    # ── check-ai ──────────────────────────────────────────────────────────────
    p_ai = sub.add_parser("check-ai", help="Check Ollama connectivity")
    p_ai.add_argument("--model", "-m", default="llama3.2")
    p_ai.set_defaults(func=cmd_check_ai)

    # ── list-rules ────────────────────────────────────────────────────────────
    p_rules = sub.add_parser("list-rules", help="List all scan rules")
    p_rules.set_defaults(func=cmd_list_rules)

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args   = parser.parse_args()
    args.func(args)