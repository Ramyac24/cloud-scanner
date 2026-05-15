# ☁ AI-Powered Cloud Misconfiguration Scanner

An AI-assisted CLI + REST API tool that scans **Terraform IaC files** and arbitrary config files for **hardcoded secrets**, misconfigurations, and security risks — with optional Ollama-backed explanations and fix generation.

---

## Features

- **Terraform scanner** — 10+ rules covering S3, security groups, IAM, RDS, EC2, EBS
- **Secrets scanner** — 13 patterns (AWS keys, GitHub tokens, Stripe keys, Slack tokens, etc.) with Shannon entropy filtering
- **AI analysis** — local LLM (Ollama / llama3.2) explains each finding and generates copy-paste fixes
- **Multiple output formats** — Rich terminal, JSON file, HTML report
- **REST API** — FastAPI with file upload, path scan, per-finding AI analysis, and HTML report endpoints
- **CI/CD ready** — exits with code `1` when CRITICAL/HIGH findings are present

---

## Project Structure

```
cloud-scanner/
├── cli.py                          # Typer CLI entrypoint
├── requirements.txt
├── setup.sh                        # One-click Mac setup
├── reporter.py                     # Terminal + JSON + HTML output
│
├── scanner/
│   ├── models.py                   # Finding, ScanResult, Severity
│   ├── terraform_scanner.py        # HCL2 + regex parser + rule runner
│   ├── secrets_scanner.py          # Regex + entropy scanner
│   └── rules/
│       ├── terraform_rules.py      # 10 Terraform rule functions
│       └── secrets_rules.py        # 13 SecretPattern definitions
│
├── ai/
│   └── analyzer.py                 # Ollama wrapper, JSON parser, batch analysis
│
├── api/
│   └── main.py                     # FastAPI REST interface
│
└── sample_configs/
    ├── main.tf                     # Intentionally vulnerable Terraform
    └── bad_secrets.env             # Fake hardcoded credentials (demo only)
```

---

## Quickstart

### 1. Setup (one command)

```bash
cd cloud-scanner
chmod +x setup.sh
./setup.sh
```

This creates a `.venv`, installs all dependencies, verifies imports, checks Ollama availability, and runs a smoke test.

### 2. Activate environment

```bash
source .venv/bin/activate
```

### 3. Scan the sample configs

```bash
# Full scan (Terraform + secrets), terminal output
python cli.py scan sample_configs/

# Only secrets, HIGH and above
python cli.py scan sample_configs/ --no-terraform --severity HIGH

# With AI-powered explanations (requires Ollama)
python cli.py scan sample_configs/ --ai

# Save an HTML report
python cli.py scan sample_configs/ --format html --output report.html

# Save JSON
python cli.py scan sample_configs/ --format json --output results.json
```

---

## CLI Reference

```
python cli.py scan <TARGET> [OPTIONS]

Arguments:
  TARGET          Path to a directory or .tf / .env file

Options:
  --ai            Enable AI analysis via Ollama (default: off)
  --model         Ollama model name (default: llama3.2)
  --severity      Filter output: CRITICAL | HIGH | MEDIUM | LOW | INFO
  --output        Save to file (.html or .json auto-detected)
  --format        terminal | json | html (default: terminal)
  --terraform / --no-terraform   Enable/disable Terraform scanner
  --secrets   / --no-secrets     Enable/disable secrets scanner
  --verbose       Show INFO-level logs

Other commands:
  python cli.py check-ai          Check Ollama connectivity + model
  python cli.py list-rules        List all built-in scan rules
```

---

## REST API

Start the server:

```bash
uvicorn api.main:app --reload
```

Interactive docs: http://localhost:8000/docs

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan/upload` | Upload files and scan them |
| `POST` | `/scan/path` | Scan a local filesystem path |
| `GET`  | `/scan/{id}` | Get cached scan results |
| `POST` | `/scan/{id}/analyze/{idx}` | AI-analyze one finding |
| `GET`  | `/scan/{id}/report` | HTML report (rendered) |
| `GET`  | `/rules` | List all rules |
| `GET`  | `/health` | Health + Ollama status |

### Example: upload and scan

```bash
curl -X POST "http://localhost:8000/scan/upload?ai=false" \
  -F "files=@sample_configs/main.tf" \
  -F "files=@sample_configs/bad_secrets.env"
```

### Example: scan a local path

```bash
curl -X POST "http://localhost:8000/scan/path" \
  -H "Content-Type: application/json" \
  -d '{"path": "./sample_configs", "ai": false}'
```

---

## AI Setup (Optional)

The scanner works fully offline — AI features are opt-in via `--ai`.

```bash
# Install Ollama
brew install ollama          # or download from https://ollama.com

# Start the Ollama server
ollama serve

# Pull the model (one-time, ~2 GB)
ollama pull llama3.2

# Verify
python cli.py check-ai
```

---

## Terraform Rules

| Rule ID | Resource | Issue |
|---------|----------|-------|
| TF001 | `aws_s3_bucket` | Public ACL (`public-read` / `public-read-write`) |
| TF002 | `aws_s3_bucket` | Server-side encryption not configured |
| TF003 | `aws_s3_bucket` | Versioning not enabled |
| TF010 | `aws_security_group` | All traffic open (port 0, protocol -1) |
| TF011–017 | `aws_security_group` | Dangerous ports open to world (SSH/RDP/Postgres/MySQL/Mongo/Redis/ES) |
| TF020 | `aws_iam_policy` | Wildcard Action (`*`) |
| TF021 | `aws_iam_policy` | Wildcard Resource (`*`) |
| TF030 | `aws_db_instance` | RDS publicly accessible |
| TF031 | `aws_db_instance` | RDS storage not encrypted |
| TF032 | `aws_db_instance` | RDS backup retention = 0 days |
| TF040 | `aws_instance` | EC2 public IP assigned |
| TF041 | `aws_instance` / `aws_ebs_volume` | EBS volume not encrypted |

## Secrets Rules

| Rule ID | Pattern |
|---------|---------|
| SEC001 | AWS Access Key ID (`AKIA…`) |
| SEC002 | AWS Secret Access Key |
| SEC003 | GitHub Personal Access Token (`ghp_…`) |
| SEC004 | Stripe Secret Key (`sk_live_…`) |
| SEC005 | Slack Webhook URL |
| SEC006 | Slack Bot Token (`xoxb-…`) |
| SEC007 | Twilio Auth Token |
| SEC008 | SendGrid API Key (`SG.…`) |
| SEC009 | Google API Key (`AIza…`) |
| SEC010 | Generic high-entropy password assignment |
| SEC011 | Private key block (`BEGIN RSA/EC/PRIVATE KEY`) |
| SEC012 | Connection string with embedded password |
| SEC013 | JWT / bearer token assignment |

---

## CI/CD Integration

The CLI exits with code `1` when any CRITICAL or HIGH finding is detected, making it drop-in ready for GitHub Actions, GitLab CI, or any shell-based pipeline:

```yaml
# .github/workflows/security.yml
- name: Scan Terraform configs
  run: |
    pip install -r requirements.txt
    python cli.py scan ./infra --severity HIGH
```

---

## Requirements

- Python 3.9+
- No cloud account required — all scanning is local
- Ollama (optional) for AI features
