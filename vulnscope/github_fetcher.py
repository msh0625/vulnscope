"""
Fetches dependency files from a public GitHub repository.
Uses GitHub raw content API (no auth required for public repos).
"""
import re
import requests
from typing import Optional

TIMEOUT = 10
RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
GITHUB_API = "https://api.github.com/repos/{owner}/{repo}"

DEPENDENCY_FILES = [
    "requirements.txt",
    "package.json",
    "pyproject.toml",
]

DEFAULT_BRANCHES = ["main", "master"]


def parse_github_url(url: str) -> tuple[str, str]:
    """Parse GitHub URL into (owner, repo)."""
    match = re.search(r"github\.com[:/]([^/]+)/([^/\s\.]+)", url)
    if not match:
        raise ValueError(f"Cannot parse GitHub URL: {url}")
    return match.group(1), match.group(2).removesuffix(".git")


def get_default_branch(owner: str, repo: str) -> str:
    try:
        resp = requests.get(
            GITHUB_API.format(owner=owner, repo=repo),
            timeout=TIMEOUT,
            headers={"Accept": "application/vnd.github.v3+json"},
        )
        resp.raise_for_status()
        return resp.json().get("default_branch", "main")
    except requests.RequestException:
        return "main"


def fetch_file(owner: str, repo: str, branch: str, path: str) -> Optional[str]:
    url = RAW_URL.format(owner=owner, repo=repo, branch=branch, path=path)
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.text
    except requests.RequestException:
        pass
    return None


def fetch_dependency_files(github_url: str) -> dict[str, str]:
    """
    Fetch all known dependency files from a GitHub repo.
    Returns {filename: content}.
    """
    owner, repo = parse_github_url(github_url)
    branch = get_default_branch(owner, repo)

    found = {}
    for filename in DEPENDENCY_FILES:
        content = fetch_file(owner, repo, branch, filename)
        if content:
            found[filename] = content
    return found
