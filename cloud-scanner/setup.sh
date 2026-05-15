#!/usr/bin/env bash
# =============================================================================
# setup.sh — One-click Mac setup for Cloud Misconfiguration Scanner
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo ""
echo -e "${CYAN}☁  Cloud Misconfiguration Scanner — Setup${NC}"
echo "============================================"
echo ""

# ── Step 1: Python version check ──────────────────────────────────────────────
info "Checking Python version…"
if ! command -v python3 &>/dev/null; then
    error "Python 3.9+ is required. Install from https://python.org or: brew install python3"
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 9 ]]; then
    error "Python 3.9+ required. Found: $PY_VER"
fi
success "Python $PY_VER"

# ── Step 2: Create virtual environment ────────────────────────────────────────
info "Creating virtual environment (.venv)…"
if [[ -d ".venv" ]]; then
    warn ".venv already exists — skipping creation"
else
    python3 -m venv .venv
    success "Virtual environment created"
fi

# Activate venv
source .venv/bin/activate
success "Virtual environment activated"

# ── Step 3: Upgrade pip ───────────────────────────────────────────────────────
info "Upgrading pip…"
pip install --upgrade pip --quiet
success "pip up to date"

# ── Step 4: Install dependencies ──────────────────────────────────────────────
info "Installing Python dependencies from requirements.txt…"
pip install -r requirements.txt --quiet
success "All dependencies installed"

# ── Step 5: Verify imports ────────────────────────────────────────────────────
info "Verifying core imports…"
python3 -c "
import typer, rich, fastapi, pydantic, ollama, yaml
from scanner.models import ScanResult, Finding, Severity
from scanner.terraform_scanner import TerraformScanner
from scanner.secrets_scanner import SecretsScanner
from ai.analyzer import check_ollama
import reporter
print('All imports OK')
" || error "Import check failed. Check requirements.txt and try again."
success "All imports verified"

# ── Step 6: Check Ollama (optional, non-fatal) ────────────────────────────────
echo ""
info "Checking Ollama (optional — needed only for --ai flag)…"
if command -v ollama &>/dev/null; then
    if ollama list &>/dev/null 2>&1; then
        if ollama list 2>/dev/null | grep -q "llama3.2"; then
            success "Ollama running + llama3.2 model found — AI features ready!"
        else
            warn "Ollama is running but llama3.2 not found."
            warn "Run:  ollama pull llama3.2"
        fi
    else
        warn "Ollama installed but not running. Start it with:  ollama serve"
    fi
else
    warn "Ollama not installed. AI features (--ai flag) will be skipped."
    warn "Install from: https://ollama.com  then run: ollama pull llama3.2"
fi

# ── Step 7: Quick smoke test on sample configs ───────────────────────────────
echo ""
info "Running smoke test on sample_configs/…"
python3 cli.py scan sample_configs/ --no-terraform --secrets 2>/dev/null | head -30 || true
echo ""
success "Smoke test complete"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Setup complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  ${CYAN}Quick start:${NC}"
echo ""
echo -e "  source .venv/bin/activate"
echo ""
echo -e "  # Scan sample vulnerable configs (no AI):"
echo -e "  python cli.py scan sample_configs/"
echo ""
echo -e "  # Scan with AI-powered explanations (requires Ollama):"
echo -e "  python cli.py scan sample_configs/ --ai"
echo ""
echo -e "  # Generate an HTML report:"
echo -e "  python cli.py scan sample_configs/ --format html --output report.html"
echo ""
echo -e "  # Filter to CRITICAL and HIGH only:"
echo -e "  python cli.py scan sample_configs/ --severity HIGH"
echo ""
echo -e "  # Start the REST API:"
echo -e "  uvicorn api.main:app --reload"
echo -e "  # → http://localhost:8000/docs"
echo ""
echo -e "  # List all built-in rules:"
echo -e "  python cli.py list-rules"
echo ""
