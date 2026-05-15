"""
reporter.py
Rich terminal output and JSON/HTML report generation.
"""

import json
import logging
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.rule import Rule

from scanner.models import ScanResult, Finding, Severity

console = Console()
logger  = logging.getLogger("reporter")

SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


# ── Summary banner ─────────────────────────────────────────────────────────────

def print_summary(result: ScanResult):
    summary = result.summary
    total   = summary["total"]
    score   = summary["risk_score"]
    counts  = summary["by_severity"]

    score_color = "red" if score > 50 else ("yellow" if score > 20 else "green")

    console.print()
    console.print(Rule("[bold cyan]Cloud Misconfiguration Scanner — Results[/bold cyan]"))
    console.print()

    # Header panel
    console.print(Panel(
        f"[bold]Target:[/bold] {result.target}\n"
        f"[bold]Files scanned:[/bold] {result.files_scanned}\n"
        f"[bold]Findings:[/bold] {total}\n"
        f"[bold]Risk Score:[/bold] [{score_color}]{score}[/{score_color}]",
        title="[cyan]Scan Summary[/cyan]",
        border_style="cyan",
    ))

    # Severity breakdown
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count",    justify="right", width=8)
    table.add_column("Bar",      width=30)

    for sev in Severity:
        count = counts.get(sev.value, 0)
        bar   = "█" * min(count, 30) if count else ""
        table.add_row(
            f"{SEV_EMOJI[sev.value]} {sev.value}",
            str(count),
            f"[{sev.color()}]{bar}[/{sev.color()}]",
        )
    console.print(table)


# ── Finding detail ─────────────────────────────────────────────────────────────

def print_findings(result: ScanResult, max_per_severity: int = 99):
    findings = result.findings
    if not findings:
        console.print("[green]✓ No findings! Clean scan.[/green]")
        return

    # Sort: CRITICAL → INFO
    order = {s: i for i, s in enumerate(Severity)}
    findings_sorted = sorted(findings, key=lambda f: order[f.severity])

    current_sev = None
    count = 0

    for f in findings_sorted:
        if f.severity != current_sev:
            current_sev = f.severity
            count = 0
            console.print()
            console.print(Rule(
                f"[{f.severity.color()}]{SEV_EMOJI[f.severity.value]} {f.severity.value}[/{f.severity.color()}]"
            ))

        count += 1
        if count > max_per_severity:
            continue

        _print_finding(f)

    console.print()


def _print_finding(f: Finding):
    sev_color = f.severity.color()

    lines = [
        f"[bold]{f.rule_id}[/bold]  [{sev_color}]{f.title}[/{sev_color}]",
    ]
    if f.resource:
        lines.append(f"[dim]Resource:[/dim]  {f.resource}")
    lines.append(f"[dim]File:[/dim]      {f.file_path}" +
                 (f"  [dim]line {f.line_number}[/dim]" if f.line_number else ""))
    lines.append(f"[dim]Evidence:[/dim]  [italic]{f.evidence[:120]}[/italic]")

    if f.ai_explanation:
        lines.append(f"\n[cyan]🤖 AI:[/cyan] {f.ai_explanation}")
    else:
        lines.append(f"[dim]Description:[/dim] {f.description}")

    if f.ai_fix:
        lines.append(f"\n[green]🔧 Fix:[/green]\n[dim]{f.ai_fix[:400]}[/dim]")
    else:
        lines.append(f"[dim]Remediation:[/dim] {f.remediation}")

    if f.ai_risk_score:
        score_color = "red" if f.ai_risk_score >= 8 else ("yellow" if f.ai_risk_score >= 5 else "green")
        lines.append(f"[dim]Risk Score:[/dim] [{score_color}]{f.ai_risk_score}/10[/{score_color}]")

    console.print(Panel(
        "\n".join(lines),
        border_style=sev_color,
        padding=(0, 1),
    ))


# ── JSON report ────────────────────────────────────────────────────────────────

def save_json(result: ScanResult, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    console.print(f"[green]✓ JSON report saved → {output_path}[/green]")


# ── HTML report ────────────────────────────────────────────────────────────────

def save_html(result: ScanResult, output_path: Path):
    summary = result.summary
    counts  = summary["by_severity"]

    sev_colors = {
        "CRITICAL": "#ff4444",
        "HIGH":     "#ff8800",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#44aaff",
        "INFO":     "#888888",
    }

    findings_html = ""
    order = {s: i for i, s in enumerate(Severity)}
    for f in sorted(result.findings, key=lambda x: order[x.severity]):
        color = sev_colors.get(f.severity.value, "#888")
        ai_block = ""
        if f.ai_explanation:
            ai_block += f'<div class="ai-box"><b>🤖 AI Explanation:</b> {f.ai_explanation}</div>'
        if f.ai_fix:
            ai_block += f'<div class="fix-box"><b>🔧 Suggested Fix:</b><pre>{f.ai_fix[:600]}</pre></div>'

        findings_html += f"""
<div class="finding" style="border-left: 4px solid {color}">
  <div class="finding-header">
    <span class="rule-id">{f.rule_id}</span>
    <span class="severity" style="color:{color}">{SEV_EMOJI[f.severity.value]} {f.severity.value}</span>
    <span class="title">{f.title}</span>
  </div>
  <div class="meta">
    <span>📁 {f.file_path}{f" line {f.line_number}" if f.line_number else ""}</span>
    {"<span>📦 " + f.resource + "</span>" if f.resource else ""}
  </div>
  <div class="evidence"><code>{f.evidence[:200]}</code></div>
  <div class="description">{f.description}</div>
  {ai_block}
</div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cloud Scanner Report — {result.target}</title>
<style>
body {{ font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        background:#0d1117;color:#c9d1d9;margin:0;padding:20px }}
h1   {{ color:#58a6ff }}
.summary {{ display:flex;gap:16px;margin:16px 0 }}
.stat {{ background:#161b22;border:1px solid #30363d;border-radius:8px;
         padding:12px 20px;text-align:center }}
.stat-val {{ font-size:2rem;font-weight:700;color:#58a6ff }}
.stat-lbl {{ font-size:0.8rem;color:#8b949e }}
.finding {{ background:#161b22;border-radius:8px;margin:12px 0;padding:12px 16px }}
.finding-header {{ display:flex;align-items:center;gap:12px;margin-bottom:6px }}
.rule-id {{ background:#21262d;padding:2px 8px;border-radius:4px;font-family:monospace;font-size:0.85rem }}
.severity {{ font-weight:700;font-size:0.9rem }}
.title {{ font-weight:600 }}
.meta {{ font-size:0.8rem;color:#8b949e;margin:4px 0 }}
.evidence {{ background:#0d1117;padding:6px 10px;border-radius:4px;font-size:0.82rem;margin:6px 0 }}
.description {{ font-size:0.87rem;color:#8b949e }}
.ai-box {{ background:#0a2a1a;border-left:3px solid #3fb950;padding:8px 12px;margin:8px 0;border-radius:4px;font-size:0.87rem }}
.fix-box {{ background:#0a1a2a;border-left:3px solid #58a6ff;padding:8px 12px;margin:8px 0;border-radius:4px }}
.fix-box pre {{ margin:4px 0;font-size:0.82rem;white-space:pre-wrap;color:#c9d1d9 }}
</style>
</head>
<body>
<h1>☁ Cloud Misconfiguration Scanner</h1>
<p style="color:#8b949e">Target: <b style="color:#c9d1d9">{result.target}</b> &nbsp;|&nbsp;
  Scanned: {result.started_at[:19]} &nbsp;|&nbsp;
  Files: {result.files_scanned}</p>

<div class="summary">
  <div class="stat"><div class="stat-val">{summary["total"]}</div><div class="stat-lbl">Total Findings</div></div>
  <div class="stat"><div class="stat-val" style="color:#ff4444">{counts.get("CRITICAL",0)}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat"><div class="stat-val" style="color:#ff8800">{counts.get("HIGH",0)}</div><div class="stat-lbl">High</div></div>
  <div class="stat"><div class="stat-val" style="color:#ffcc00">{counts.get("MEDIUM",0)}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat"><div class="stat-val">{summary["risk_score"]}</div><div class="stat-lbl">Risk Score</div></div>
</div>

<h2 style="color:#58a6ff">Findings</h2>
{findings_html if findings_html else '<p style="color:#3fb950">✓ No findings detected.</p>'}
</body></html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    console.print(f"[green]✓ HTML report saved → {output_path}[/green]")
