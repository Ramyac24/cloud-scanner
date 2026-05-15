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
"""

import sys
import os
import logging
from pathlib import Path
from uuid import uuid4

import typer
from rich.console import Console

# Make project root importable
sys.path.insert(0, os.path.dirname(__file__))

from scanner.models import ScanResult, Severity
from scanner.terraform_scanner import TerraformScanner
from scanner.secrets_scanner import SecretsScanner
from ai.analyzer import analyze_findings_batch, check_ollama
import reporter

app     = typer.Typer(help="☁  AI-Powered Cloud Misconfiguration Scanner")
console = Console()

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)


# ── scan command ───────────────────────────────────────────────────────────────

@app.command()
def scan(
    target: str = typer.Argument(..., help="Path to directory or file to scan"),
    ai: bool = typer.Option(False, "--ai",
        help="Enable AI-powered explanations and fix generation (requires Ollama)"),
    model: str = typer.Option("llama3.2", "--model", "-m",
        help="Ollama model to use for AI analysis"),
    severity: str = typer.Option("", "--severity", "-s",
        help="Filter output to this severity and above (CRITICAL|HIGH|MEDIUM|LOW|INFO)"),
    output: str = typer.Option("", "--output", "-o",
        help="Save report to file (auto-detects .json or .html from extension)"),
    format: str = typer.Option("terminal", "--format", "-f",
        help="Output format: terminal | json | html"),
    terraform: bool = typer.Option(True,  "--terraform/--no-terraform",
        help="Enable Terraform scanner"),
    secrets: bool = typer.Option(True, "--secrets/--no-secrets",
        help="Enable secrets scanner"),
    verbose: bool = typer.Option(False, "--verbose", "-v",
        help="Show INFO-level logs"),
):
    """Scan a directory or file for cloud misconfigurations and exposed secrets."""

    if verbose:
        logging.getLogger().setLevel(logging.INFO)

    target_path = Path(target).expanduser().resolve()
    if not target_path.exists():
        console.print(f"[red]Error: path does not exist: {target_path}[/red]")
        raise typer.Exit(1)

    scan_id = str(uuid4())[:8]
    result  = ScanResult(scan_id=scan_id, target=str(target_path))

    console.print(f"\n[bold cyan]☁  Cloud Scanner[/bold cyan] — scanning [cyan]{target_path}[/cyan]")

    # ── Run scanners ──────────────────────────────────────────────────────────
    if terraform:
        tf_scanner = TerraformScanner()
        if target_path.is_file() and target_path.suffix == ".tf":
            for f in tf_scanner.scan_file(target_path):
                result.add(f)
            result.files_scanned += 1
        elif target_path.is_dir():
            tf_scanner.scan_directory(target_path, result)

    if secrets:
        sec_scanner = SecretsScanner()
        if target_path.is_file():
            for f in sec_scanner.scan_file(target_path):
                result.add(f)
        elif target_path.is_dir():
            sec_scanner.scan_directory(target_path, result)

    # ── Filter by severity ────────────────────────────────────────────────────
    display_findings = result.findings
    if severity:
        try:
            min_sev = Severity(severity.upper())
            sev_order = list(Severity)
            min_idx   = sev_order.index(min_sev)
            display_findings = [
                f for f in result.findings
                if sev_order.index(f.severity) <= min_idx
            ]
        except ValueError:
            console.print(f"[yellow]Unknown severity '{severity}' — showing all[/yellow]")

    # ── AI analysis ───────────────────────────────────────────────────────────
    if ai:
        ok, msg = check_ollama(model)
        if ok:
            console.print(f"[green]🤖 {msg}[/green]")
            analyze_findings_batch(display_findings, model=model)
        else:
            console.print(f"[yellow]⚠  AI offline — {msg}[/yellow]")

    # ── Output ────────────────────────────────────────────────────────────────
    reporter.print_summary(result)

    if format == "terminal" or not output:
        # Filter the result object for display
        result.findings = display_findings
        reporter.print_findings(result)

    if output:
        out_path = Path(output)
        ext = out_path.suffix.lower()
        if ext == ".html" or format == "html":
            reporter.save_html(result, out_path)
        else:
            reporter.save_json(result, out_path)
    elif format == "json":
        import json
        console.print_json(json.dumps(result.to_dict(), indent=2, default=str))
    elif format == "html":
        out_path = Path(f"report_{scan_id}.html")
        reporter.save_html(result, out_path)

    # Exit code: 1 if any CRITICAL/HIGH findings (useful for CI/CD)
    has_critical = any(f.severity in (Severity.CRITICAL, Severity.HIGH)
                       for f in result.findings)
    raise typer.Exit(1 if has_critical else 0)


# ── check-ai command ───────────────────────────────────────────────────────────

@app.command(name="check-ai")
def check_ai(model: str = typer.Option("llama3.2", "--model", "-m")):
    """Check whether Ollama AI is reachable and the model is available."""
    ok, msg = check_ollama(model)
    if ok:
        console.print(f"[green]✓ {msg}[/green]")
    else:
        console.print(f"[red]✗ {msg}[/red]")
        raise typer.Exit(1)


# ── list-rules command ─────────────────────────────────────────────────────────

@app.command(name="list-rules")
def list_rules():
    """List all available scan rules."""
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


if __name__ == "__main__":
    app()
