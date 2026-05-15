"""
ai/analyzer.py
Ollama-powered AI analysis for cloud misconfigurations.

For each Finding, ARIA (our security AI) provides:
- A plain-English explanation of why this is dangerous
- A concrete, ready-to-use code fix
- A risk score from 1-10
"""

import json
import logging
import re
import threading
from typing import Optional

import ollama

logger = logging.getLogger("ai.analyzer")

DEFAULT_MODEL   = "llama3.2"
LLM_TIMEOUT     = 30     # seconds per finding
OFFLINE_PREFIX  = "[OFFLINE] "

SYSTEM_PROMPT = """
You are CloudSec-AI, an expert cloud security engineer specializing in
Terraform IaC security, AWS/GCP/Azure misconfigurations, secrets management,
and DevSecOps best practices.

Your job is to analyze cloud infrastructure security findings and provide:
1. A clear explanation of the security risk (why it matters, real-world impact)
2. A precise, copy-paste-ready code fix
3. A risk score from 1-10 (10 = most critical)

Be concise, technical, and actionable. Output ONLY valid JSON.
"""


# ── Core LLM call ─────────────────────────────────────────────────────────────

def _chat(user_prompt: str, model: str = DEFAULT_MODEL,
          temperature: float = 0.2, max_tokens: int = 600) -> str:
    """Thread-safe Ollama call with hard timeout."""
    result = [None]
    error  = [None]

    def _call():
        try:
            resp = ollama.chat(
                model=model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ],
                options={"temperature": temperature, "num_predict": max_tokens},
            )
            result[0] = resp["message"]["content"].strip()
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=_call, daemon=True)
    t.start()
    t.join(timeout=LLM_TIMEOUT)

    if result[0]:
        return result[0]
    if error[0]:
        return f"{OFFLINE_PREFIX}Ollama unavailable: {error[0]}"
    return f"{OFFLINE_PREFIX}Response timed out after {LLM_TIMEOUT}s."


def _parse_json(raw: str) -> Optional[dict]:
    """Extract JSON from LLM response (handles markdown fences and preamble)."""
    if not raw or raw.startswith(OFFLINE_PREFIX):
        return None
    raw = raw.strip()

    for attempt in [
        raw,
        re.sub(r'^```(?:json)?\s*|\s*```$', '', raw, flags=re.DOTALL).strip(),
    ]:
        try:
            return json.loads(attempt)
        except json.JSONDecodeError:
            pass

    match = re.search(r'\{[^{}]*\}', raw, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


# ── Public analysis functions ─────────────────────────────────────────────────

def analyze_finding(finding, model: str = DEFAULT_MODEL) -> dict:
    """
    Analyze a single Finding with the LLM.
    Returns dict with keys: explanation, fix, risk_score.
    """
    prompt = f"""
Analyze this cloud security finding and respond with ONLY a JSON object.

Finding:
  Rule ID:     {finding.rule_id}
  Title:       {finding.title}
  Severity:    {finding.severity.value}
  Type:        {finding.scan_type.value}
  File:        {finding.file_path}
  Resource:    {finding.resource or 'N/A'}
  Description: {finding.description}
  Evidence:    {finding.evidence}
  Static hint: {finding.remediation}

Respond with ONLY this JSON (no preamble, no markdown):
{{"explanation":"<2-3 sentences: what risk this creates and real-world attack scenario>","fix":"<exact corrected Terraform/config code snippet, ready to copy-paste>","risk_score":<integer 1-10>}}
"""
    raw    = _chat(prompt, model=model)
    parsed = _parse_json(raw)

    if parsed and "explanation" in parsed:
        try:
            parsed["risk_score"] = int(parsed.get("risk_score", finding.severity.score()))
        except (ValueError, TypeError):
            parsed["risk_score"] = finding.severity.score()
        return parsed

    # Offline / parse failure fallback
    return {
        "explanation": (
            raw.replace(OFFLINE_PREFIX, "").strip()[:400]
            if raw and not raw.startswith(OFFLINE_PREFIX)
            else f"AI offline. Static description: {finding.description}"
        ),
        "fix":        finding.remediation,
        "risk_score": finding.severity.score(),
    }


def analyze_findings_batch(findings: list,
                            model: str = DEFAULT_MODEL,
                            max_findings: int = 20,
                            only_high_plus: bool = True) -> None:
    """
    Enrich a list of Finding objects in-place with AI analysis.
    Skips LOW/INFO by default to save LLM calls.
    Caps at max_findings to avoid very long runs.
    """
    from scanner.models import Severity

    candidates = findings
    if only_high_plus:
        candidates = [f for f in findings
                      if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]

    candidates = candidates[:max_findings]

    logger.info(f"AI analyzing {len(candidates)} finding(s) with model '{model}'…")

    for i, finding in enumerate(candidates):
        logger.info(f"  [{i+1}/{len(candidates)}] {finding.rule_id} — {finding.title}")
        result = analyze_finding(finding, model=model)
        finding.ai_explanation = result.get("explanation")
        finding.ai_fix         = result.get("fix")
        finding.ai_risk_score  = result.get("risk_score")


def check_ollama(model: str = DEFAULT_MODEL) -> tuple[bool, str]:
    """Quick check whether Ollama is available."""
    result = [None]

    def _check():
        try:
            models = ollama.list()
            names = [m.get("name", "") for m in models.get("models", [])]
            if not names:
                result[0] = (False, "Ollama running but no models pulled. Run: ollama pull llama3.2")
                return
            if not any(model in n for n in names):
                result[0] = (False, f"Model '{model}' not found. Available: {', '.join(names)}")
                return
            result[0] = (True, f"CloudSec-AI online — model: {model}")
        except Exception as e:
            result[0] = (False, f"Ollama not reachable: {e}")

    t = threading.Thread(target=_check, daemon=True)
    t.start()
    t.join(timeout=5)
    return result[0] if result[0] else (False, "Ollama check timed out")
