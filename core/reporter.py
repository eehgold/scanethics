"""
Reporter — centralised real-time terminal output using Rich.
All scanners call these helpers instead of printing directly.
"""

from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()


# ── Generic helpers ─────────────────────────────────────────────────────────

def banner(title: str, subtitle: str = ""):
    content = Text(title, style="bold white")
    if subtitle:
        content.append(f"\n{subtitle}", style="dim")
    console.print(Panel(content, style="cyan", box=box.DOUBLE))


def section(name: str):
    console.rule(f"[bold cyan]{name}[/bold cyan]")


def info(msg: str):
    console.print(f"[bold blue][*][/bold blue] {msg}")


def success(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")


def warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def error(msg: str):
    console.print(f"[bold red][-][/bold red] {msg}")


def finding(label: str, value: str, severity: str = "info"):
    colour = {
        "info": "cyan",
        "low": "blue",
        "medium": "yellow",
        "high": "red",
        "critical": "bold red",
    }.get(severity, "white")
    console.print(f"  [{colour}]{label}[/{colour}]: {value}")


# ── Structured table output ──────────────────────────────────────────────────

def port_table(results: list[dict]):
    """Render a table of open ports.

    Each dict: {"port": int, "state": str, "service": str, "banner": str}
    """
    table = Table(title="Open Ports", box=box.ROUNDED, style="cyan")
    table.add_column("Port", style="bold white", justify="right")
    table.add_column("State", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Banner", style="dim")

    for r in results:
        table.add_row(
            str(r.get("port", "")),
            r.get("state", "open"),
            r.get("service", "?"),
            r.get("banner", ""),
        )
    console.print(table)


def findings_table(title: str, results: list[dict], columns: list[tuple]):
    """Generic findings table.

    columns: list of (header, key, style)
    """
    table = Table(title=title, box=box.ROUNDED, style="cyan")
    for header, _, style in columns:
        table.add_column(header, style=style)

    for r in results:
        table.add_row(*[str(r.get(key, "")) for _, key, _ in columns])

    console.print(table)


# ── Scan summary ─────────────────────────────────────────────────────────────

def summary(scan_results: dict):
    section("SCAN SUMMARY")
    for scanner_name, data in scan_results.items():
        count = data.get("count", len(data.get("findings", [])))
        status = "[green]OK[/green]" if data.get("success") else "[red]ERROR[/red]"
        console.print(f"  {status}  [bold]{scanner_name}[/bold] — {count} finding(s)")
    console.print(f"\n[dim]Completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")


# ── Analysis report ───────────────────────────────────────────────────────────

_SEV_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold blue",
    "INFO":     "dim cyan",
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def analysis_report(report) -> None:
    """Render the full post-scan analysis from an AnalysisReport object."""
    from rich.padding import Padding

    console.print()
    console.rule("[bold magenta]ANALYSE INTELLIGENTE DES RÉSULTATS[/bold magenta]")
    console.print()

    # ── Risk score panel ─────────────────────────────────────────────────────
    real = report.all_real_findings
    crit  = sum(1 for f in real if f.severity == "CRITICAL")
    high  = sum(1 for f in real if f.severity == "HIGH")
    med   = sum(1 for f in real if f.severity == "MEDIUM")
    low   = sum(1 for f in real if f.severity == "LOW")

    if crit > 0:
        risk_label = "[bold white on red] RISQUE CRITIQUE [/bold white on red]"
    elif high > 0:
        risk_label = "[bold red] RISQUE ÉLEVÉ [/bold red]"
    elif med > 0:
        risk_label = "[bold yellow] RISQUE MODÉRÉ [/bold yellow]"
    else:
        risk_label = "[bold green] RISQUE FAIBLE [/bold green]"

    score_text = Text()
    score_text.append(f"  Cible : {report.target}\n", style="bold white")
    score_text.append(f"  Findings réels : {len(real)}   ", style="white")
    score_text.append(f"CRITICAL:{crit}  ", style="bold red" if crit else "dim")
    score_text.append(f"HIGH:{high}  ",     style="red"      if high else "dim")
    score_text.append(f"MEDIUM:{med}  ",    style="yellow"   if med  else "dim")
    score_text.append(f"LOW:{low}",         style="blue"     if low  else "dim")

    if report.wildcard_ip:
        score_text.append(f"\n  [!] Wildcard DNS détecté → {report.wildcard_ip} (sous-domaines à vérifier manuellement)", style="dim yellow")

    console.print(Panel(score_text, title=risk_label, style="magenta", box=box.HEAVY))
    console.print()

    # ── Findings grouped by category ─────────────────────────────────────────
    all_f = sorted(real, key=lambda f: (_SEV_ORDER.get(f.severity, 99), f.category))

    if not all_f:
        console.print("  [green]Aucun finding critique détecté.[/green]\n")
    else:
        table = Table(box=box.ROUNDED, style="magenta", show_lines=True, expand=True)
        table.add_column("Sév.",      style="bold", width=10, justify="center")
        table.add_column("Catégorie", style="cyan", width=14)
        table.add_column("Finding",   style="white")
        table.add_column("Action recommandée", style="yellow")

        for f in all_f:
            sev_style = _SEV_STYLE.get(f.severity, "white")
            table.add_row(
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.category,
                f"[bold]{f.title}[/bold]\n[dim]{f.detail}[/dim]",
                f.action or "—",
            )
        console.print(table)

    # ── False positives log ───────────────────────────────────────────────────
    noise = [f for f in report.all_real_findings + _get_fp(report) if f.false_positive]
    if noise:
        console.print()
        console.print("[dim]── Faux positifs filtrés ─────────────────────────────────────────────[/dim]")
        for f in noise:
            console.print(f"  [dim]• {f.title} — {f.detail}[/dim]")
            if f.action:
                console.print(f"    [dim cyan]→ {f.action}[/dim cyan]")

    console.print()


def _get_fp(report) -> list:
    """Collect false-positive findings from all categories."""
    all_f = (
        report.port_findings
        + report.dir_findings
        + report.web_findings
        + report.sub_findings
    )
    return [f for f in all_f if f.false_positive]
