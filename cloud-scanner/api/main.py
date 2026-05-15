"""
api/main.py
FastAPI REST interface for the Cloud Misconfiguration Scanner.

Endpoints
---------
POST /scan                    Scan uploaded files or a local path
GET  /scan/{scan_id}          Get results of a previous scan
POST /analyze/{scan_id}/{idx} AI-analyze a specific finding
GET  /rules                   List all available rules
GET  /health                  Health + Ollama status
"""

import sys, os, tempfile, shutil, logging
from pathlib import Path
from uuid import uuid4
from typing import Optional
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from scanner.models import ScanResult, Severity
from scanner.terraform_scanner import TerraformScanner
from scanner.secrets_scanner import SecretsScanner
from ai.analyzer import analyze_findings_batch, analyze_finding, check_ollama
import reporter as rpt

logger = logging.getLogger("api")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s")

# In-memory scan cache (production: use Redis/DB)
_scan_cache: dict[str, ScanResult] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Cloud Scanner API started")
    yield
    logger.info("API shutting down")


app = FastAPI(
    title="Cloud Misconfiguration Scanner API",
    description="AI-powered Terraform and secrets scanner with Ollama-backed fix generation.",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _run_scan(target: Path, scan_id: str,
              do_terraform: bool = True,
              do_secrets: bool = True) -> ScanResult:
    result = ScanResult(scan_id=scan_id, target=str(target))
    if do_terraform:
        tf = TerraformScanner()
        tf.scan_directory(target, result)
    if do_secrets:
        sec = SecretsScanner()
        sec.scan_directory(target, result)
    return result


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health():
    ok, msg = check_ollama()
    return {
        "status":   "ok",
        "ollama":   {"available": ok, "message": msg},
        "scans_cached": len(_scan_cache),
    }


@app.get("/rules", tags=["System"])
def list_rules():
    from scanner.rules.terraform_rules import ALL_RULES
    from scanner.rules.secrets_rules import SECRET_PATTERNS
    return {
        "terraform": [fn.__name__ for fn in ALL_RULES],
        "secrets":   [{"id": sp.rule_id, "name": sp.name,
                       "severity": sp.severity} for sp in SECRET_PATTERNS],
    }


@app.post("/scan/upload", status_code=201, tags=["Scan"])
async def scan_upload(
    files:      list[UploadFile] = File(...),
    ai:         bool = Query(False,   description="Enable AI analysis"),
    model:      str  = Query("llama3.2"),
    terraform:  bool = Query(True),
    secrets:    bool = Query(True),
):
    """Upload one or more files (.tf, .env, etc.) and scan them."""
    scan_id  = str(uuid4())[:8]
    tmp_dir  = Path(tempfile.mkdtemp(prefix=f"cloudscan_{scan_id}_"))

    try:
        for upload in files:
            dest = tmp_dir / (upload.filename or "uploaded_file")
            dest.write_bytes(await upload.read())

        result = _run_scan(tmp_dir, scan_id, terraform, secrets)

        if ai:
            analyze_findings_batch(result.findings, model=model)

        _scan_cache[scan_id] = result
        return result.to_dict()

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


class PathScanRequest(BaseModel):
    path:       str
    ai:         bool = False
    model:      str  = "llama3.2"
    terraform:  bool = True
    secrets:    bool = True


@app.post("/scan/path", status_code=201, tags=["Scan"])
def scan_path(req: PathScanRequest):
    """Scan a local filesystem path (server must have access)."""
    target = Path(req.path).expanduser().resolve()
    if not target.exists():
        raise HTTPException(404, detail=f"Path not found: {req.path}")

    scan_id = str(uuid4())[:8]
    result  = _run_scan(target, scan_id, req.terraform, req.secrets)

    if req.ai:
        analyze_findings_batch(result.findings, model=req.model)

    _scan_cache[scan_id] = result
    return result.to_dict()


@app.get("/scan/{scan_id}", tags=["Scan"])
def get_scan(scan_id: str,
             severity: Optional[str] = Query(None,
                description="Filter by minimum severity: CRITICAL|HIGH|MEDIUM|LOW|INFO")):
    """Retrieve results of a previous scan."""
    result = _scan_cache.get(scan_id)
    if not result:
        raise HTTPException(404, detail=f"Scan '{scan_id}' not found")

    data = result.to_dict()
    if severity:
        try:
            sev = Severity(severity.upper())
            order = list(Severity)
            idx   = order.index(sev)
            data["findings"] = [
                f for f in data["findings"]
                if order.index(Severity(f["severity"])) <= idx
            ]
        except ValueError:
            pass
    return data


@app.post("/scan/{scan_id}/analyze/{finding_idx}", tags=["AI"])
def analyze_one(scan_id: str, finding_idx: int,
                model: str = Query("llama3.2")):
    """AI-analyze a single finding by index."""
    result = _scan_cache.get(scan_id)
    if not result:
        raise HTTPException(404, detail=f"Scan '{scan_id}' not found")
    if finding_idx < 0 or finding_idx >= len(result.findings):
        raise HTTPException(400, detail=f"Finding index {finding_idx} out of range")

    finding = result.findings[finding_idx]
    ai_result = analyze_finding(finding, model=model)
    finding.ai_explanation = ai_result.get("explanation")
    finding.ai_fix         = ai_result.get("fix")
    finding.ai_risk_score  = ai_result.get("risk_score")

    return {
        "finding_idx":   finding_idx,
        "rule_id":       finding.rule_id,
        "ai_explanation": finding.ai_explanation,
        "ai_fix":        finding.ai_fix,
        "ai_risk_score": finding.ai_risk_score,
    }


@app.get("/scan/{scan_id}/report", response_class=HTMLResponse, tags=["Reports"])
def html_report(scan_id: str):
    """Return the scan results as an HTML report."""
    import io
    result = _scan_cache.get(scan_id)
    if not result:
        raise HTTPException(404, detail=f"Scan '{scan_id}' not found")

    tmp = Path(tempfile.mktemp(suffix=".html"))
    rpt.save_html(result, tmp)
    html = tmp.read_text()
    tmp.unlink(missing_ok=True)
    return HTMLResponse(content=html)
