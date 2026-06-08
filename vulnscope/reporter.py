"""
Terminal report renderer using Rich.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from .osv_client import Vuln

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "UNKNOWN":  "dim",
}


def severity_badge(sev: str) -> Text:
    color = SEVERITY_COLORS.get(sev.upper(), "dim")
    return Text(f" {sev} ", style=f"bold {color}")


def print_header(repo_url: str):
    console.print(Panel.fit(
        f"[bold cyan]vulnscope[/bold cyan]  [dim]OSS Vulnerability Scanner[/dim]\n"
        f"[dim]Target:[/dim] [white]{repo_url}[/white]",
        border_style="cyan",
    ))


def print_summary(total_deps: int, vulnerable: int, total_vulns: int):
    color = "red" if vulnerable > 0 else "green"
    console.print(
        f"\n[bold]Scan complete.[/bold] "
        f"Checked [cyan]{total_deps}[/cyan] dependencies — "
        f"[{color}]{vulnerable} vulnerable[/{color}], "
        f"[red]{total_vulns} total CVEs found[/red]\n"
    )


def print_results(results: dict[str, list[Vuln]], deps_count: int):
    if not results:
        console.print("[bold green]✓ No known vulnerabilities found.[/bold green]\n")
        return

    total_vulns = sum(len(v) for v in results.values())
    print_summary(deps_count, len(results), total_vulns)

    for pkg_name, vulns in results.items():
        table = Table(
            title=f"[bold white]{pkg_name}[/bold white]  [dim]({len(vulns)} issue{'s' if len(vulns) > 1 else ''})[/dim]",
            box=box.ROUNDED,
            border_style="dim",
            show_header=True,
            header_style="bold",
            expand=True,
        )
        table.add_column("ID", style="cyan", no_wrap=True, width=20)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Summary", ratio=1)
        table.add_column("Fix", style="green", width=14)

        for v in sorted(vulns, key=lambda x: (
            ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"].index(x.severity)
            if x.severity in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"] else 99
        )):
            display_id = v.cve_id or v.vuln_id
            fix = v.fixed_version or "[dim]—[/dim]"
            table.add_row(
                display_id,
                severity_badge(v.severity),
                v.summary[:120] + ("…" if len(v.summary) > 120 else ""),
                fix,
            )

        console.print(table)
        console.print()


def print_error(msg: str):
    console.print(f"[bold red]Error:[/bold red] {msg}")


def print_info(msg: str):
    console.print(f"[dim]{msg}[/dim]")


def print_analysis(analysis) -> None:
    """Print Claude's deep analysis result."""
    from rich.rule import Rule

    console.print()
    console.print(Rule(f"[bold cyan]Claude Analysis — {analysis.package}[/bold cyan]", style="cyan"))

    if analysis.attack_vectors:
        console.print("\n[bold]Attack vectors[/bold]")
        for v in analysis.attack_vectors:
            console.print(f"  [red]▸[/red] {v}")

    if analysis.affected_functions:
        console.print("\n[bold]Affected functions[/bold]")
        for f in analysis.affected_functions:
            console.print(f"  [yellow]▸[/yellow] {f}")

    if analysis.exploit_scenario:
        console.print("\n[bold]Exploit scenario[/bold]")
        console.print(f"  {analysis.exploit_scenario}")

    if analysis.remediation:
        console.print("\n[bold]Remediation[/bold]")
        console.print(f"  [green]{analysis.remediation}[/green]")

    if analysis.severity_reasoning:
        console.print("\n[bold]Severity reasoning[/bold]")
        console.print(f"  [dim]{analysis.severity_reasoning}[/dim]")

    if analysis.zero_day_risks and analysis.zero_day_risks != ["None identified."]:
        console.print("\n[bold yellow]⚠ Additional risks (not in CVE list)[/bold yellow]")
        for r in analysis.zero_day_risks:
            console.print(f"  [yellow]▸[/yellow] {r}")

    console.print()


def print_policy_analysis(result) -> None:
    """Print zero-trust policy analysis result."""
    from rich.rule import Rule
    from rich.table import Table
    from rich import box

    console.print()
    console.print(Rule(f"[bold magenta]Zero-Trust Analysis — {result.filename}[/bold magenta]", style="magenta"))
    console.print(f"[dim]Type:[/dim] {result.policy_type}")

    # Score bar
    score = result.zero_trust_score
    filled = int(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    if score >= 70:
        color = "green"
    elif score >= 40:
        color = "yellow"
    else:
        color = "red"
    console.print(f"\n[bold]Zero-Trust Score[/bold]  [{color}]{bar}[/{color}]  [{color}]{score}/100[/{color}]\n")

    # Findings table
    if result.findings:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(result.findings, key=lambda f: sev_order.get(f.severity, 9))

        table = Table(
            title=f"[bold white]Findings ({len(result.findings)})[/bold white]",
            box=box.ROUNDED,
            border_style="dim",
            expand=True,
        )
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Principle", width=20)
        table.add_column("Location", width=16)
        table.add_column("Issue", ratio=1)
        table.add_column("Fix", ratio=1)

        sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        for f in sorted_findings:
            color = sev_colors.get(f.severity, "dim")
            table.add_row(
                f"[{color}]{f.severity}[/{color}]",
                f.principle_violated,
                f"[dim]{f.location}[/dim]",
                f.description,
                f"[green]{f.recommendation}[/green]",
            )
        console.print(table)
    else:
        console.print("[bold green]✓ No zero-trust violations found.[/bold green]")

    # Summary
    if result.summary:
        console.print(f"\n[bold]Summary[/bold]\n  {result.summary}\n")

    # Hardened config
    if result.hardened_config:
        console.print("[bold magenta]Hardened config suggestion:[/bold magenta]")
        console.print(result.hardened_config)

    console.print()
