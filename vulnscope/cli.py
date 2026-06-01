"""
vulnscope — AI-assisted OSS vulnerability scanner
Usage: vulnscope scan <github_url> [--analyze]
"""

import typer
from .github_fetcher import fetch_dependency_files
from .parser import PARSERS
from .osv_client import batch_query_osv
from .reporter import (
    console,
    print_header,
    print_results,
    print_error,
    print_info,
    print_analysis,
)

app = typer.Typer(
    name="vulnscope",
    help="OSS Vulnerability Scanner — finds CVEs in GitHub project dependencies",
    add_completion=False,
    no_args_is_help=True,
)


@app.command("scan")
def scan(
    repo_url: str = typer.Argument(..., help="GitHub repository URL to scan"),
    analyze: bool = typer.Option(
        False,
        "--analyze",
        "-a",
        help="Run Claude AI deep analysis on vulnerable packages",
    ),
    top: int = typer.Option(
        3, "--top", "-t", help="Number of packages to analyze with Claude (default: 3)"
    ),
):
    """
    Scan a GitHub repository for known CVEs in its dependencies.

    Examples:\n
        vulnscope scan https://github.com/owner/repo\n
        vulnscope scan https://github.com/owner/repo --analyze\n
        vulnscope scan https://github.com/owner/repo --analyze --top 5
    """
    print_header(repo_url)

    # 1. Fetch dependency files
    print_info("Fetching dependency files...")
    try:
        files = fetch_dependency_files(repo_url)
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)

    if not files:
        print_error(
            "No supported dependency files found (requirements.txt, package.json, pyproject.toml)"
        )
        raise typer.Exit(1)

    print_info(f"Found: {', '.join(files.keys())}")

    # 2. Parse dependencies
    all_deps = []
    for filename, content in files.items():
        parser = PARSERS.get(filename)
        if parser:
            deps = parser(content)
            all_deps.extend(deps)
            print_info(f"Parsed {len(deps)} dependencies from {filename}")

    if not all_deps:
        print_error("No dependencies found in the files.")
        raise typer.Exit(1)

    console.print(
        f"\n[bold]Scanning [cyan]{len(all_deps)}[/cyan] dependencies against OSV database...[/bold]\n"
    )

    # 3. Query OSV
    with console.status("[bold cyan]Querying OSV.dev...[/bold cyan]"):
        results = batch_query_osv(all_deps)

    # 4. Print CVE report
    print_results(results, len(all_deps))

    # 5. Claude deep analysis (optional)
    if analyze and results:
        from .claude_analyzer import analyze_package

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        sorted_pkgs = sorted(
            results.items(),
            key=lambda x: min(
                severity_order.index(v.severity) if v.severity in severity_order else 99
                for v in x[1]
            ),
        )

        targets = sorted_pkgs[:top]
        console.print(
            f"[bold cyan]Running Claude analysis on top {len(targets)} vulnerable packages...[/bold cyan]\n"
        )

        ecosystem = "npm"
        for dep in all_deps:
            if dep.name == targets[0][0]:
                ecosystem = dep.ecosystem
                break

        for pkg_name, vulns in targets:
            cve_ids = [v.cve_id or v.vuln_id for v in vulns]
            summaries = [v.summary for v in vulns]

            with console.status(f"[bold cyan]Analyzing {pkg_name}...[/bold cyan]"):
                try:
                    analysis = analyze_package(pkg_name, cve_ids, summaries, ecosystem)
                    print_analysis(analysis)
                except Exception as e:
                    print_error(f"Analysis failed for {pkg_name}: {e}")


@app.command("version")
def version():
    """Show vulnscope version."""
    console.print("[bold cyan]vulnscope[/bold cyan] v0.2.0")


def main():
    app()


if __name__ == "__main__":
    main()
