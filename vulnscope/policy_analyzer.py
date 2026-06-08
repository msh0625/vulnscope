"""
Zero-trust policy analyzer.
Analyzes IAM policies, nginx configs, k8s RBAC, and firewall rules
against zero-trust principles using Claude API.
"""
import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from anthropic import Anthropic

client = Anthropic()

# Supported policy file types
SUPPORTED_EXTENSIONS = {
    ".json": "JSON (IAM Policy / k8s RBAC)",
    ".yaml": "YAML (k8s RBAC / Docker Compose)",
    ".yml":  "YAML (k8s RBAC / Docker Compose)",
    ".conf": "Nginx / Apache config",
    ".hcl":  "Terraform / HCL",
    ".tf":   "Terraform",
    ".ini":  "INI config",
    ".toml": "TOML config",
}

ZERO_TRUST_PRINCIPLES = """
Zero-Trust principles to evaluate against:
1. Verify explicitly — always authenticate and authorize based on all available data points
2. Use least privilege access — limit user access with Just-In-Time and Just-Enough-Access
3. Assume breach — minimize blast radius, segment access, encrypt everything, use analytics
4. Never trust the network location — internal ≠ trusted
5. Continuous verification — not one-time at login
"""


@dataclass
class PolicyFinding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    principle_violated: str
    description: str
    location: str          # e.g. "Line 12" or "Statement[2]"
    recommendation: str


@dataclass
class PolicyAnalysisResult:
    filename: str
    policy_type: str
    zero_trust_score: int   # 0-100
    findings: list[PolicyFinding] = field(default_factory=list)
    summary: str = ""
    hardened_config: str = ""  # Claude-suggested improved config snippet


def detect_policy_type(filename: str, content: str) -> str:
    """Detect what kind of policy file this is."""
    name = filename.lower()

    if "nginx" in name or "server {" in content or "location /" in content:
        return "nginx"
    if "kind: Role" in content or "kind: ClusterRole" in content:
        return "k8s-rbac"
    if "kind: NetworkPolicy" in content:
        return "k8s-networkpolicy"
    if '"Statement"' in content and '"Action"' in content:
        return "aws-iam"
    if "resource" in content and "provider" in content and ".tf" in name:
        return "terraform"
    if "docker" in name or "services:" in content:
        return "docker-compose"
    return "generic-config"


def _build_policy_prompt(filename: str, policy_type: str, content: str) -> str:
    return f"""You are a senior zero-trust security architect performing a policy review.

## File: {filename}
## Detected type: {policy_type}

{ZERO_TRUST_PRINCIPLES}

## Policy content:
```
{content[:6000]}
```

Analyze this configuration against zero-trust principles and respond in this EXACT format:

### Zero-trust score
A single integer from 0 to 100 representing how well this config aligns with zero-trust (100 = perfect).

### Policy type
One sentence describing what this config does.

### Findings
List each finding as:
[SEVERITY] | [PRINCIPLE VIOLATED] | [LOCATION] | [DESCRIPTION] | [RECOMMENDATION]

Use severity: CRITICAL, HIGH, MEDIUM, or LOW.
Principle violated: one of "Verify explicitly", "Least privilege", "Assume breach", "No implicit trust", "Continuous verification".
Location: line number or section name if identifiable.
Example:
HIGH | Least privilege | Statement[1] | Wildcard action "*" grants excessive permissions | Replace with specific actions: s3:GetObject, s3:PutObject

### Summary
2-3 sentences summarizing the overall security posture and biggest risks.

### Hardened config
Provide a corrected/improved version of the most critical section only (not the entire file). Keep it concise.
"""


def _parse_policy_response(filename: str, policy_type: str, raw: str) -> PolicyAnalysisResult:
    result = PolicyAnalysisResult(filename=filename, policy_type=policy_type, zero_trust_score=50)

    lines = raw.splitlines()
    current_section = None
    buffer: list[str] = []

    def flush():
        nonlocal buffer
        text = "\n".join(buffer).strip()
        buffer = []
        return text

    for line in lines:
        lower = line.lower().strip("# ").strip()

        if lower.startswith("zero-trust score"):
            current_section = "score"
            buffer = []
        elif lower.startswith("policy type"):
            if current_section == "score":
                text = flush()
                # Extract first integer
                for word in text.split():
                    clean = word.strip(".,")
                    if clean.isdigit():
                        result.zero_trust_score = max(0, min(100, int(clean)))
                        break
            current_section = "type"
            buffer = []
        elif lower.startswith("findings"):
            if current_section == "type":
                result.policy_type = flush() or policy_type
            current_section = "findings"
            buffer = []
        elif lower.startswith("summary"):
            if current_section == "findings":
                _parse_findings(flush(), result)
            current_section = "summary"
            buffer = []
        elif lower.startswith("hardened config"):
            if current_section == "summary":
                result.summary = flush()
            current_section = "hardened"
            buffer = []
        else:
            if current_section:
                buffer.append(line)

    # flush last section
    if current_section == "hardened":
        result.hardened_config = flush()
    elif current_section == "summary":
        result.summary = flush()
    elif current_section == "findings":
        _parse_findings(flush(), result)

    return result


def _parse_findings(text: str, result: PolicyAnalysisResult):
    for line in text.splitlines():
        line = line.strip().lstrip("-•*").strip()
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 5:
            continue
        result.findings.append(PolicyFinding(
            severity=parts[0].upper(),
            principle_violated=parts[1],
            location=parts[2],
            description=parts[3],
            recommendation=parts[4],
        ))


def analyze_policy_file(filepath: str) -> PolicyAnalysisResult:
    """Analyze a local policy/config file against zero-trust principles."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    content = path.read_text(encoding="utf-8", errors="replace")
    policy_type = detect_policy_type(path.name, content)
    prompt = _build_policy_prompt(path.name, policy_type, content)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text
    return _parse_policy_response(path.name, policy_type, raw)


def analyze_policy_text(name: str, content: str) -> PolicyAnalysisResult:
    """Analyze a policy from a string (for testing or piped input)."""
    policy_type = detect_policy_type(name, content)
    prompt = _build_policy_prompt(name, policy_type, content)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text
    return _parse_policy_response(name, policy_type, raw)
