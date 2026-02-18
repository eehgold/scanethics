#!/usr/bin/env python3
"""
scanethics — white-hat reconnaissance & vulnerability scanning framework
=========================================================================

Usage:
    python main.py <target> [options]

Examples:
    python main.py 192.168.1.1
    python main.py example.com
    python main.py https://example.com --only ports web
    python main.py example.com --ports 80,443,8080 --no-crtsh
"""

import argparse
import json
import sys
import warnings
from datetime import datetime
from pathlib import Path

# Suppress insecure-request warnings (we verify=False for flexibility)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ── Path fix so sub-packages can import from core ────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from core.target import Target
from core.analyzer import Analyzer
import core.reporter as reporter

from scanners.port_scanner.scanner import PortScanner
from scanners.dir_fuzzer.scanner   import DirFuzzer
from scanners.web_vuln.scanner     import WebVulnScanner
from scanners.subdomain.scanner    import SubdomainScanner

# Map CLI name → scanner class
SCANNERS = {
    "ports":     PortScanner,
    "dirs":      DirFuzzer,
    "web":       WebVulnScanner,
    "subdomains": SubdomainScanner,
}

DISCLAIMER = (
    "[bold red]DISCLAIMER:[/bold red] "
    "This tool is for [bold]authorized[/bold] security testing only.\n"
    "Scanning systems without explicit permission is illegal.\n"
    "By using this tool you confirm you have written authorisation."
)


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanethics",
        description="White-hat reconnaissance & vulnerability scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("target", help="IP address or URL to scan")

    scan_group = p.add_mutually_exclusive_group()
    scan_group.add_argument(
        "--only",
        nargs="+",
        choices=list(SCANNERS.keys()),
        metavar="SCANNER",
        help=f"Run only specific scanners: {', '.join(SCANNERS.keys())}",
    )
    scan_group.add_argument(
        "--skip",
        nargs="+",
        choices=list(SCANNERS.keys()),
        metavar="SCANNER",
        help="Skip specific scanners",
    )

    p.add_argument(
        "--ports",
        help="Comma-separated ports for port scanner (default: top 1000)",
        default=None,
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Override default timeout (seconds) for all scanners",
    )
    p.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Override number of worker threads",
    )
    p.add_argument(
        "--wordlist",
        default=None,
        help="Custom wordlist path for directory fuzzer",
    )
    p.add_argument(
        "--no-crtsh",
        action="store_true",
        help="Disable crt.sh lookup in subdomain scanner",
    )
    p.add_argument(
        "--output",
        default=None,
        help="Save JSON results to file (default: reports/<target>_<timestamp>.json)",
    )
    p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the disclaimer confirmation prompt",
    )
    return p


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    reporter.banner(
        "scanethics",
        "white-hat recon & vuln scanning framework",
    )

    # Disclaimer gate
    if not args.yes:
        reporter.console.print(f"\n{DISCLAIMER}\n")
        try:
            answer = input("Proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            reporter.error("Aborted.")
            sys.exit(0)

    # Build target
    target = Target(args.target)
    ip = target.resolve()

    reporter.info(f"Target   : [bold]{target.base_url}[/bold]")
    reporter.info(f"Hostname : {target.hostname}")
    reporter.info(f"Resolved : {ip or '[red]FAILED[/red]'}")
    reporter.info(f"Scheme   : {target.scheme}")

    if ip is None:
        reporter.error("Cannot resolve hostname — check the target and your DNS.")
        sys.exit(1)

    # Determine which scanners to run
    if args.only:
        active_scanners = {k: v for k, v in SCANNERS.items() if k in args.only}
    elif args.skip:
        active_scanners = {k: v for k, v in SCANNERS.items() if k not in args.skip}
    else:
        active_scanners = SCANNERS

    reporter.info(f"Scanners : {', '.join(active_scanners.keys())}")
    reporter.console.print()

    # Build shared options
    shared_opts: dict = {}
    if args.timeout is not None:
        shared_opts["timeout"] = args.timeout
    if args.threads is not None:
        shared_opts["max_workers"] = args.threads
        shared_opts["workers"] = args.threads

    # Per-scanner overrides
    scanner_opts: dict[str, dict] = {k: dict(shared_opts) for k in SCANNERS}

    if args.ports:
        try:
            scanner_opts["ports"]["ports"] = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            reporter.error("--ports must be comma-separated integers, e.g. 80,443,8080")
            sys.exit(1)

    if args.wordlist:
        scanner_opts["dirs"]["wordlist"] = args.wordlist

    if args.no_crtsh:
        scanner_opts["subdomains"]["use_crtsh"] = False

    # Run scanners
    all_results: dict[str, dict] = {}
    start_time = datetime.now()

    for key, ScannerClass in active_scanners.items():
        scanner = ScannerClass(target, **scanner_opts.get(key, {}))
        try:
            result = scanner.run()
        except KeyboardInterrupt:
            reporter.warning(f"\n[{key}] Interrupted by user.")
            result = {"success": False, "findings": [], "errors": ["interrupted"], "count": 0}
        except Exception as exc:
            reporter.error(f"[{key}] Unhandled error: {exc}")
            result = {"success": False, "findings": [], "errors": [str(exc)], "count": 0}

        all_results[key] = result
        reporter.console.print()  # blank line between scanners

    # Raw scanner summary
    reporter.summary(all_results)

    # ── Post-scan intelligence analysis ──────────────────────────────────────
    reporter.console.print()
    reporter.info("Analyse intelligente des résultats en cours …")
    analysis = Analyzer(target, all_results).run()
    reporter.analysis_report(analysis)

    # Save results
    output_path = args.output
    if output_path is None:
        ts = start_time.strftime("%Y%m%d_%H%M%S")
        safe_target = target.hostname.replace(".", "_")
        reports_dir = Path(__file__).parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        output_path = str(reports_dir / f"{safe_target}_{ts}.json")

    # Serialise analysis findings for the JSON report
    analysis_payload = {
        "wildcard_dns":     analysis.wildcard_ip,
        "risk_score":       {
            "critical": analysis.critical_count,
            "high":     analysis.high_count,
            "total_real_findings": len(analysis.all_real_findings),
        },
        "findings": [
            {
                "category":      f.category,
                "severity":      f.severity,
                "title":         f.title,
                "detail":        f.detail,
                "action":        f.action,
                "false_positive": f.false_positive,
            }
            for f in (
                analysis.port_findings
                + analysis.dir_findings
                + analysis.web_findings
                + analysis.sub_findings
            )
        ],
    }

    payload = {
        "target":    str(target),
        "hostname":  target.hostname,
        "resolved":  ip,
        "scanned_at": start_time.isoformat(),
        "analysis":  analysis_payload,
        "raw_results": all_results,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    reporter.success(f"Rapport sauvegardé → {output_path}")


if __name__ == "__main__":
    main()
