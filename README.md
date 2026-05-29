# vulnscope 🔍

**AI-assisted vulnerability scanner for open source projects**

Scans any public GitHub repository for known CVEs in its dependencies by querying the [OSV (Open Source Vulnerabilities)](https://osv.dev) database. Supports Python and Node.js ecosystems out of the box.

---

## Features

- 🔎 **Dependency scanning** — parses `requirements.txt`, `package.json`, `pyproject.toml`
- 🛡️ **CVE lookup** — queries OSV.dev in real-time for known vulnerabilities
- 📊 **Severity ranking** — CRITICAL / HIGH / MEDIUM / LOW with fix version hints
- 🚀 **Zero config** — just point it at a GitHub URL

---

## Quickstart

```bash
# Install
pip install -e .

# Scan a repository
vulnscope scan https://github.com/owner/repo
```

Example output:

```
╭──────────────────────────────────────────╮
│ vulnscope  OSS Vulnerability Scanner     │
│ Target: https://github.com/owner/repo    │
╰──────────────────────────────────────────╯

Scanning 42 dependencies against OSV database...

┌─ django (3 issues) ──────────────────────────────────────┐
│ ID               │ Severity │ Summary              │ Fix  │
│ CVE-2023-36053   │ HIGH     │ ReDoS in EmailVal..  │ 4.2.3│
│ CVE-2023-41164   │ HIGH     │ Potential DoS via... │ 4.2.5│
│ GHSA-xxx-xxx     │ MEDIUM   │ ...                  │ 3.2.1│
└──────────────────────────────────────────────────────────┘
```

---

## Roadmap

- [ ] **Week 2** — Claude API integration for pattern-based zero-day analysis
- [ ] **Week 3** — Zero-trust policy analyzer (IAM, RBAC, nginx config)
- [ ] **Week 4** — Automated CVE report generation & responsible disclosure templates

---

## Supported ecosystems

| File              | Ecosystem |
|-------------------|-----------|
| `requirements.txt`| PyPI      |
| `pyproject.toml`  | PyPI      |
| `package.json`    | npm       |

---

## Contributing

PRs welcome. If you find a false negative (a vulnerability we missed), please open an issue.

---

## License

MIT
