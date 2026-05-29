"""
Dependency file parsers for various ecosystems.
Supports: requirements.txt, package.json, Pipfile, pyproject.toml
"""
import re
import json
from dataclasses import dataclass
from typing import Optional


@dataclass
class Dependency:
    name: str
    version: Optional[str]
    ecosystem: str  # "PyPI" | "npm"

    def __str__(self):
        return f"{self.name}=={self.version}" if self.version else self.name


def parse_requirements_txt(content: str) -> list[Dependency]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle ==, >=, <=, ~=, !=
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!~]+\s*([^\s,;]+))?", line)
        if match:
            name = match.group(1)
            version = match.group(2)
            # Clean version string
            if version:
                version = re.sub(r"[><=!~]", "", version).strip()
            deps.append(Dependency(name=name, version=version or None, ecosystem="PyPI"))
    return deps


def parse_package_json(content: str) -> list[Dependency]:
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for name, version_spec in all_deps.items():
        # Clean semver prefixes: ^1.2.3 -> 1.2.3
        version = re.sub(r"^[\^~>=<]", "", version_spec).strip()
        version = version.split(" ")[0] if version else None
        deps.append(Dependency(name=name, version=version or None, ecosystem="npm"))
    return deps


def parse_pyproject_toml(content: str) -> list[Dependency]:
    """Basic TOML parser for [tool.poetry.dependencies] and [project] sections."""
    deps = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if re.match(r"\[tool\.poetry\.dependencies\]|\[project\]", line):
            in_deps = True
            continue
        if line.startswith("[") and in_deps:
            in_deps = False
        if in_deps and "=" in line and not line.startswith("#"):
            parts = line.split("=", 1)
            name = parts[0].strip()
            version_raw = parts[1].strip().strip('"').strip("'")
            version = re.sub(r"[^0-9\.]", "", version_raw.split(",")[0]) or None
            if name and name.lower() != "python":
                deps.append(Dependency(name=name, version=version, ecosystem="PyPI"))
    return deps


PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "pyproject.toml": parse_pyproject_toml,
}
