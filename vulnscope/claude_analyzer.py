"""
Claude API-powered vulnerability analyzer.
Fetches source code from vulnerable packages and performs deep analysis.
"""

import os
import requests
from dataclasses import dataclass, field
from typing import Optional
from anthropic import Anthropic

GITHUB_API = "https://api.github.com"
RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
TIMEOUT = 10
MAX_FILE_SIZE = 50_000  # 50KB per file to stay within token limits

client = Anthropic()  # reads ANTHROPIC_API_KEY from env automatically


@dataclass
class AnalysisResult:
    package: str
    cve_ids: list[str]
    attack_vectors: list[str] = field(default_factory=list)
    affected_functions: list[str] = field(default_factory=list)
    exploit_scenario: str = ""
    remediation: str = ""
    severity_reasoning: str = ""
    zero_day_risks: list[str] = field(default_factory=list)


def _fetch_npm_source(package: str, version: Optional[str]) -> dict[str, str]:
    """Fetch key source files from an npm package via GitHub."""
    # Try to find the GitHub repo from npm registry
    try:
        resp = requests.get(
            f"https://registry.npmjs.org/{package}",
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        repo_url = data.get("repository", {}).get("url", "") or data.get("homepage", "")
        # Clean git+https://github.com/... -> owner/repo
        repo_url = repo_url.replace("git+", "").replace(".git", "")
        if "github.com" not in repo_url:
            return {}

        parts = repo_url.split("github.com/")[-1].split("/")
        if len(parts) < 2:
            return {}
        owner, repo = parts[0], parts[1]
    except Exception:
        return {}

    return _fetch_repo_files(owner, repo)


def _fetch_repo_files(owner: str, repo: str, max_files: int = 5) -> dict[str, str]:
    """Fetch JS/Python source files from a GitHub repo."""
    files: dict[str, str] = {}
    try:
        # Get default branch
        resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            timeout=TIMEOUT,
        )
        branch = resp.json().get("default_branch", "main")

        # Get file tree
        tree_resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
            timeout=TIMEOUT,
        )
        tree = tree_resp.json().get("tree", [])

        # Pick interesting source files (not tests, not minified)
        candidates = [
            f
            for f in tree
            if f.get("type") == "blob"
            and any(f["path"].endswith(ext) for ext in [".js", ".py", ".ts"])
            and not any(
                x in f["path"]
                for x in ["test", "spec", "min.js", "node_modules", "__pycache__"]
            )
            and f.get("size", 0) < MAX_FILE_SIZE
        ][:max_files]

        for file_info in candidates:
            url = RAW_URL.format(
                owner=owner, repo=repo, branch=branch, path=file_info["path"]
            )
            content_resp = requests.get(url, timeout=TIMEOUT)
            if content_resp.status_code == 200:
                files[file_info["path"]] = content_resp.text[:MAX_FILE_SIZE]

    except Exception:
        pass

    return files


def _build_prompt(
    package: str, cve_ids: list[str], summaries: list[str], source_files: dict[str, str]
) -> str:
    files_section = ""
    if source_files:
        files_section = "\n\n## Source code\n"
        for path, content in source_files.items():
            files_section += f"\n### {path}\n```\n{content[:8000]}\n```\n"
    else:
        files_section = "\n\n## Source code\nSource code could not be retrieved. Analyze based on CVE descriptions only.\n"

    cve_section = "\n".join(
        f"- {cid}: {summary}" for cid, summary in zip(cve_ids, summaries)
    )

    return f"""You are a senior security researcher performing a deep vulnerability analysis.

## Package: {package}

## Known CVEs
{cve_section}
{files_section}

Analyze the above and respond in this EXACT format (keep the headers):

### Attack vectors
List each distinct attack vector as a bullet point. Be specific (e.g. "Unauthenticated HTTP POST to /api/upload with crafted multipart body").

### Affected functions
List the specific function names or code paths involved.

### Exploit scenario
Write a concrete 3-5 sentence exploit scenario. Describe what an attacker does step by step.

### Remediation
Specific fix recommendation with code example if possible.

### Severity reasoning
Why this severity level is correct given the actual impact and exploitability.

### Additional risks
Any related vulnerabilities or risks NOT covered by the listed CVEs that you spotted in the source code. If none, write "None identified."
"""


def analyze_package(
    package: str,
    cve_ids: list[str],
    summaries: list[str],
    ecosystem: str,
) -> AnalysisResult:
    """
    Run Claude analysis on a vulnerable package.
    Fetches source code and generates deep vulnerability report.
    """
    # Fetch source
    source_files: dict[str, str] = {}
    if ecosystem == "npm":
        source_files = _fetch_npm_source(package, None)

    prompt = _build_prompt(package, cve_ids, summaries, source_files)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text
    return _parse_response(package, cve_ids, raw)


def _parse_response(package: str, cve_ids: list[str], raw: str) -> AnalysisResult:
    """Parse Claude's structured response into an AnalysisResult."""
    result = AnalysisResult(package=package, cve_ids=cve_ids)

    sections = {
        "attack vectors": "attack_vectors",
        "affected functions": "affected_functions",
        "exploit scenario": "exploit_scenario",
        "remediation": "remediation",
        "severity reasoning": "severity_reasoning",
        "additional risks": "zero_day_risks",
    }

    current = None
    buffer: list[str] = []

    def flush(section_key: str, lines: list[str]):
        text = "\n".join(lines).strip()
        if not text:
            return
        attr = sections[section_key]
        if attr in ("attack_vectors", "affected_functions", "zero_day_risks"):
            items = [
                l.lstrip("-•*").strip()
                for l in text.splitlines()
                if l.strip() and l.strip() not in ("-", "•", "*")
            ]
            setattr(result, attr, items)
        else:
            setattr(result, attr, text)

    for line in raw.splitlines():
        lower = line.lower().strip("# ").strip()
        matched = next((k for k in sections if lower.startswith(k)), None)
        if matched:
            if current:
                flush(current, buffer)
            current = matched
            buffer = []
        elif current:
            buffer.append(line)

    if current:
        flush(current, buffer)

    return result
