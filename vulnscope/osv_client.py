"""
OSV (Open Source Vulnerabilities) API client.
Docs: https://osv.dev/docs/
"""
import requests
from dataclasses import dataclass, field
from typing import Optional
from .parser import Dependency

OSV_API = "https://api.osv.dev/v1"
TIMEOUT = 10


@dataclass
class Vuln:
    vuln_id: str          # e.g. CVE-2023-1234 or GHSA-xxxx
    summary: str
    severity: str         # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    fixed_version: Optional[str]
    aliases: list[str] = field(default_factory=list)

    @property
    def cve_id(self) -> Optional[str]:
        for a in self.aliases:
            if a.startswith("CVE-"):
                return a
        if self.vuln_id.startswith("CVE-"):
            return self.vuln_id
        return None


def _extract_severity(osv_data: dict) -> str:
    # Try database_specific.severity first (GitHub)
    db = osv_data.get("database_specific", {})
    sev = db.get("severity", "")
    if sev:
        return sev.upper()
    # Try severity array (CVSS)
    for s in osv_data.get("severity", []):
        score = s.get("score", "")
        if "CRITICAL" in score.upper():
            return "CRITICAL"
        if "HIGH" in score.upper():
            return "HIGH"
        if "MEDIUM" in score.upper():
            return "MEDIUM"
        if "LOW" in score.upper():
            return "LOW"
    return "UNKNOWN"


def _extract_fixed_version(osv_data: dict, ecosystem: str) -> Optional[str]:
    for affected in osv_data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        for r in affected.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def query_osv(dep: Dependency) -> list[Vuln]:
    """Query OSV for a single dependency. Returns list of Vuln."""
    payload: dict = {
        "package": {
            "name": dep.name,
            "ecosystem": dep.ecosystem,
        }
    }
    if dep.version:
        payload["version"] = dep.version

    try:
        resp = requests.post(f"{OSV_API}/query", json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        return []

    vulns = []
    for v in data.get("vulns", []):
        vulns.append(Vuln(
            vuln_id=v.get("id", "UNKNOWN"),
            summary=v.get("summary", "No summary available."),
            severity=_extract_severity(v),
            fixed_version=_extract_fixed_version(v, dep.ecosystem),
            aliases=v.get("aliases", []),
        ))
    return vulns


def batch_query_osv(deps: list[Dependency]) -> dict[str, list[Vuln]]:
    """Query OSV for a list of dependencies. Returns {dep_name: [Vuln]}."""
    results = {}
    for dep in deps:
        vulns = query_osv(dep)
        if vulns:
            results[dep.name] = vulns
    return results
