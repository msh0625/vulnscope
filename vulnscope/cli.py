"""
vulnscope — AI-assisted OSS vulnerability scanner
Usage: python -m vulnscope scan <github_url>
"""
import sys
import typer
from typing import Optional
from .github_fetcher import fetch_dependency_files, parse_github_url
from .parser import PARSERS
from .osv_client import batch_query_osv
from .reporter import console, print_header, print_results, print_error, print_info

app = typer.Typer(
    name="vulnscope",
    help="OSS Vulnerability Scanner — finds CVEs in GitHub project dependencies",
    add_completion=False,
)


@app.command()
def scan(
    repo_url: str = typer.Argument(..., help="GitHub repository URL to scan"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Show all deps, not just vulnerable ones"),
):
    """
    Scan a GitHub repository for known CVEs in its dependencies.
    
    Example:
        vulnscope scan https://github.com/owner/repo
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
        print_error("No supported dependency files found (requirements.txt, package.json, pyproject.toml)")
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

    console.print(f"\n[bold]Scanning [cyan]{len(all_deps)}[/cyan] dependencies against OSV database...[/bold]\n")

    # 3. Query OSV
    with console.status("[bold cyan]Querying OSV.dev...[/bold cyan]"):
        results = batch_query_osv(all_deps)

    # 4. Print report
    print_results(results, len(all_deps))


def main():
    app()


# Allow: python -m vulnscope <url>  (shorthand, no subcommand needed)
@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context):
    pass


if __name__ == "__main__":
    main()
