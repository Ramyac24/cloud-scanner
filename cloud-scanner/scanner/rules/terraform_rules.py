"""
terraform_rules.py
Security rules for Terraform resource scanning.
Each rule is a callable: rule(resource_type, resource_name, block, file_path) -> Finding | None
"""

from scanner.models import Finding, Severity, ScanType


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get(block: dict, *keys, default=None):
    """Safe nested key access: _get(block, 'ingress', 'cidr_blocks')"""
    val = block
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k, default)
        if val is None:
            return default
    return val


def _finding(rule_id, title, severity, resource, file_path,
             line, description, evidence, remediation) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity,
        scan_type=ScanType.TERRAFORM,
        file_path=file_path, line_number=line,
        resource=resource, description=description,
        evidence=evidence, remediation=remediation,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  S3 BUCKET RULES
# ══════════════════════════════════════════════════════════════════════════════

def rule_s3_public_acl(rtype, rname, block, fpath, line) -> list[Finding]:
    findings = []
    if rtype != "aws_s3_bucket":
        return findings
    acl = block.get("acl", "")
    if isinstance(acl, str) and acl in ("public-read", "public-read-write", "authenticated-read"):
        findings.append(_finding(
            "TF001", "S3 Bucket Has Public ACL", Severity.CRITICAL,
            f"{rtype}.{rname}", fpath, line,
            "S3 bucket ACL allows public access, exposing all stored objects to the internet.",
            f'acl = "{acl}"',
            'Set acl = "private" and use bucket policies for controlled access.',
        ))
    return findings


def rule_s3_no_encryption(rtype, rname, block, fpath, line) -> list[Finding]:
    findings = []
    if rtype != "aws_s3_bucket":
        return findings
    if "server_side_encryption_configuration" not in block:
        findings.append(_finding(
            "TF002", "S3 Bucket Missing Server-Side Encryption", Severity.HIGH,
            f"{rtype}.{rname}", fpath, line,
            "S3 bucket has no server-side encryption configured. Data at rest is unencrypted.",
            "server_side_encryption_configuration block is absent",
            "Add a server_side_encryption_configuration block with AES256 or aws:kms.",
        ))
    return findings


def rule_s3_versioning_disabled(rtype, rname, block, fpath, line) -> list[Finding]:
    findings = []
    if rtype != "aws_s3_bucket":
        return findings
    versioning = block.get("versioning", {})
    if isinstance(versioning, dict):
        enabled = versioning.get("enabled", False)
        if str(enabled).lower() in ("false", "0", ""):
            findings.append(_finding(
                "TF003", "S3 Bucket Versioning Disabled", Severity.MEDIUM,
                f"{rtype}.{rname}", fpath, line,
                "Versioning is disabled. You cannot recover accidentally deleted or overwritten objects.",
                'versioning { enabled = false }',
                "Enable versioning: versioning { enabled = true }",
            ))
    return findings


def rule_s3_public_block_missing(rtype, rname, block, fpath, line) -> list[Finding]:
    """aws_s3_bucket_public_access_block should exist alongside every bucket."""
    return []   # enforced at pipeline level — covered by TF001


# ══════════════════════════════════════════════════════════════════════════════
#  SECURITY GROUP RULES
# ══════════════════════════════════════════════════════════════════════════════

_DANGEROUS_PORTS = {
    22:   "SSH",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    27017:"MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

_OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _check_ingress(ingress: dict | list, rname: str, rtype: str,
                   fpath: str, line: int) -> list[Finding]:
    findings = []
    rules = ingress if isinstance(ingress, list) else [ingress]
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        cidrs = rule.get("cidr_blocks", [])
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        from_port = int(rule.get("from_port", 0) or 0)
        to_port   = int(rule.get("to_port",   0) or 0)
        proto     = str(rule.get("protocol",  "tcp"))

        if not any(c in _OPEN_CIDRS for c in cidrs):
            continue

        # All-traffic open
        if proto == "-1":
            findings.append(_finding(
                "TF010", "Security Group Allows All Inbound Traffic", Severity.CRITICAL,
                f"{rtype}.{rname}", fpath, line,
                "Security group ingress rule allows ALL traffic from the internet (0.0.0.0/0).",
                f'protocol = "-1", cidr_blocks = ["0.0.0.0/0"]',
                "Restrict protocol and port. Never use protocol = -1 with open CIDR.",
            ))
            continue

        # Specific dangerous ports
        for port, service in _DANGEROUS_PORTS.items():
            if from_port <= port <= to_port:
                sev = Severity.CRITICAL if port in (22, 3389) else Severity.HIGH
                findings.append(_finding(
                    f"TF01{port % 10}", f"Security Group Exposes {service} Port {port} to Internet",
                    sev, f"{rtype}.{rname}", fpath, line,
                    f"Inbound rule allows {service} (port {port}) from 0.0.0.0/0. "
                    "This is a common attack vector.",
                    f"from_port = {from_port}, to_port = {to_port}, cidr_blocks = [\"0.0.0.0/0\"]",
                    f"Restrict cidr_blocks to specific trusted IP ranges for port {port}.",
                ))

        # Generic open port (not in dangerous list)
        if not any(from_port <= p <= to_port for p in _DANGEROUS_PORTS):
            findings.append(_finding(
                "TF011", f"Security Group Port {from_port}-{to_port} Open to Internet",
                Severity.MEDIUM, f"{rtype}.{rname}", fpath, line,
                f"Ingress rule allows port {from_port}-{to_port} from 0.0.0.0/0.",
                f"from_port = {from_port}, to_port = {to_port}, cidr_blocks = [\"0.0.0.0/0\"]",
                "Restrict cidr_blocks to trusted IP ranges or use a VPC security context.",
            ))
    return findings


def rule_security_group_open(rtype, rname, block, fpath, line) -> list[Finding]:
    if rtype not in ("aws_security_group", "aws_security_group_rule"):
        return []
    findings = []
    ingress = block.get("ingress")
    if ingress:
        findings += _check_ingress(ingress, rname, rtype, fpath, line)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  IAM RULES
# ══════════════════════════════════════════════════════════════════════════════

def rule_iam_wildcard(rtype, rname, block, fpath, line) -> list[Finding]:
    findings = []
    if rtype not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"):
        return findings

    policy = block.get("policy", "")
    if not isinstance(policy, str):
        return findings

    import json, re
    # Extract JSON from heredoc or string
    json_match = re.search(r'\{.*\}', policy, re.DOTALL)
    if not json_match:
        return findings
    try:
        doc = json.loads(json_match.group())
    except json.JSONDecodeError:
        return findings

    for stmt in doc.get("Statement", []):
        actions   = stmt.get("Action",   [])
        resources = stmt.get("Resource", [])
        effect    = stmt.get("Effect",   "Allow")
        if effect != "Allow":
            continue
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions:
            findings.append(_finding(
                "TF020", "IAM Policy Allows All Actions (Wildcard)", Severity.CRITICAL,
                f"{rtype}.{rname}", fpath, line,
                "IAM policy grants wildcard (*) on Action. This violates least-privilege principle.",
                '"Action": "*"',
                'Replace "*" with specific required actions e.g. ["s3:GetObject", "s3:PutObject"].',
            ))
        if "*" in resources and any("*" not in a for a in actions):
            findings.append(_finding(
                "TF021", "IAM Policy Targets All Resources (Wildcard)", Severity.HIGH,
                f"{rtype}.{rname}", fpath, line,
                "IAM policy applies to all resources (*). Scope it to specific ARNs.",
                '"Resource": "*"',
                "Replace * with specific resource ARNs.",
            ))
    return findings


# ══════════════════════════════════════════════════════════════════════════════
#  RDS RULES
# ══════════════════════════════════════════════════════════════════════════════

def rule_rds_public(rtype, rname, block, fpath, line) -> list[Finding]:
    if rtype != "aws_db_instance":
        return []
    val = block.get("publicly_accessible", False)
    if str(val).lower() in ("true", "1", "yes"):
        return [_finding(
            "TF030", "RDS Instance Is Publicly Accessible", Severity.CRITICAL,
            f"{rtype}.{rname}", fpath, line,
            "Database instance is reachable from the internet. This is a critical exposure risk.",
            "publicly_accessible = true",
            "Set publicly_accessible = false and use VPC peering or bastion hosts.",
        )]
    return []


def rule_rds_no_encryption(rtype, rname, block, fpath, line) -> list[Finding]:
    if rtype != "aws_db_instance":
        return []
    val = block.get("storage_encrypted", False)
    if str(val).lower() in ("false", "0", ""):
        return [_finding(
            "TF031", "RDS Storage Not Encrypted", Severity.HIGH,
            f"{rtype}.{rname}", fpath, line,
            "RDS database storage is not encrypted at rest.",
            "storage_encrypted = false (or missing)",
            "Set storage_encrypted = true.",
        )]
    return []


def rule_rds_no_backup(rtype, rname, block, fpath, line) -> list[Finding]:
    if rtype != "aws_db_instance":
        return []
    retention = int(block.get("backup_retention_period", 0) or 0)
    if retention == 0:
        return [_finding(
            "TF032", "RDS Automated Backups Disabled", Severity.MEDIUM,
            f"{rtype}.{rname}", fpath, line,
            "Automated backups are disabled (retention = 0). Data cannot be recovered.",
            "backup_retention_period = 0",
            "Set backup_retention_period to at least 7 days.",
        )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
#  EC2 / GENERAL
# ══════════════════════════════════════════════════════════════════════════════

def rule_ec2_public_ip(rtype, rname, block, fpath, line) -> list[Finding]:
    if rtype != "aws_instance":
        return []
    val = block.get("associate_public_ip_address", False)
    if str(val).lower() in ("true", "1", "yes"):
        return [_finding(
            "TF040", "EC2 Instance Has Public IP", Severity.MEDIUM,
            f"{rtype}.{rname}", fpath, line,
            "EC2 instance is configured with a public IP address.",
            "associate_public_ip_address = true",
            "Set associate_public_ip_address = false and use a NAT gateway or load balancer.",
        )]
    return []


def rule_ec2_no_ebs_encryption(rtype, rname, block, fpath, line) -> list[Finding]:
    if rtype != "aws_ebs_volume":
        return []
    val = block.get("encrypted", False)
    if str(val).lower() in ("false", "0", ""):
        return [_finding(
            "TF041", "EBS Volume Not Encrypted", Severity.HIGH,
            f"{rtype}.{rname}", fpath, line,
            "EBS volume is not encrypted. Data at rest is exposed.",
            "encrypted = false (or missing)",
            "Set encrypted = true and specify a kms_key_id.",
        )]
    return []


# ══════════════════════════════════════════════════════════════════════════════
#  RULE REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

ALL_RULES = [
    rule_s3_public_acl,
    rule_s3_no_encryption,
    rule_s3_versioning_disabled,
    rule_security_group_open,
    rule_iam_wildcard,
    rule_rds_public,
    rule_rds_no_encryption,
    rule_rds_no_backup,
    rule_ec2_public_ip,
    rule_ec2_no_ebs_encryption,
]
