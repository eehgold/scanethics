"""
DirFuzzer — brute-force directories, admin pages and sensitive files.

Uses requests + ThreadPoolExecutor. Fully Python, no external tools.
"""

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.base_scanner import BaseScanner
from core.target import Target
import core.reporter as reporter

WORDLIST_PATH = Path(__file__).parent / "wordlists" / "common.txt"

INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}
HIGH_VALUE_CODES  = {200, 201, 204}
AUTH_CODES        = {401, 403}

# Paths that are especially interesting if they respond
HIGH_VALUE_PATHS = {
    "admin", "administrator", "wp-admin", "phpmyadmin", "adminer",
    "cpanel", "dashboard", "panel", "manager", "controlpanel",
    ".env", ".git", ".git/HEAD", "wp-config.php", "config.php",
    "phpinfo.php", "info.php", "backup", "dump.sql", "db.sql",
    "server-status", "actuator", "actuator/env",
}


def _make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.2, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; scanethics/1.0; +security-audit)",
        "Accept": "*/*",
    })
    return session


class DirFuzzer(BaseScanner):
    name = "Directory Fuzzer"
    description = "Brute-force hidden paths, admin pages and sensitive files"

    def __init__(self, target: Target, **options):
        super().__init__(target, **options)
        self.wordlist  = options.get("wordlist", str(WORDLIST_PATH))
        self.timeout   = options.get("timeout", 5)
        self.workers   = options.get("workers", 30)
        self.extensions = options.get("extensions", ["", ".php", ".html", ".txt", ".bak"])

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        reporter.section(f"DIRECTORY FUZZER — {self.target.base_url}")

        paths = self._load_wordlist()
        urls  = self._build_urls(paths)

        reporter.info(f"Fuzzing {len(urls)} paths with {self.workers} threads …")

        findings = []
        errors   = []
        session  = _make_session()

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._probe, session, url, path): (url, path)
                       for url, path in urls}
            for future in as_completed(futures):
                url, path = futures[future]
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                        self._print_finding(result)
                except Exception as exc:
                    errors.append(str(exc))

        findings.sort(key=lambda r: (r["status"], r["url"]))

        # Detect HTTP → HTTPS redirect flood (false positive)
        if findings:
            redirect_count = sum(1 for f in findings if f["status"] in (301, 302, 307, 308))
            redirect_ratio = redirect_count / len(findings)
            if redirect_ratio > 0.85:
                reporter.warning(
                    f"[bold yellow]WARNING[/bold yellow]: {redirect_count}/{len(findings)} results "
                    f"are 3xx redirects -- the server redirects all HTTP traffic to HTTPS.\n"
                    f"  -> These results are [bold]false positives[/bold]. Re-run the scan on HTTPS:\n"
                    f"    [bold cyan]python main.py https://{self.target.hostname} --only dirs[/bold cyan]"
                )
                # Still store them but flag them
                for f in findings:
                    f["note"] = f.get("note", "") + " [FALSE POSITIVE -- HTTP->HTTPS redirect]"

        if findings:
            reporter.findings_table(
                "Discovered Paths",
                findings,
                [
                    ("Status", "status", "bold green"),
                    ("URL",    "url",    "white"),
                    ("Size",   "size",   "dim"),
                    ("Note",   "note",   "yellow"),
                ],
            )
        else:
            reporter.warning("No interesting paths found.")

        return self._result(findings, errors=errors)

    # ── Private ───────────────────────────────────────────────────────────────

    def _load_wordlist(self) -> list[str]:
        with open(self.wordlist, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def _build_urls(self, paths: list[str]) -> list[tuple[str, str]]:
        urls = []
        base = self.target.base_url.rstrip("/")
        for path in paths:
            for ext in self.extensions:
                # Avoid double-extension on paths that already have one
                if ext and "." in path:
                    continue
                full_path = path + ext
                urls.append((f"{base}/{full_path}", full_path))
        return urls

    def _probe(self, session: requests.Session, url: str, path: str) -> dict | None:
        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)
            if resp.status_code not in INTERESTING_CODES:
                return None

            size = len(resp.content)
            note = ""
            if path.lower() in HIGH_VALUE_PATHS:
                note = "HIGH VALUE"
            elif resp.status_code in AUTH_CODES:
                note = "auth-protected"
            elif resp.status_code in (301, 302, 307, 308):
                note = f"→ {resp.headers.get('Location', '?')}"

            return {
                "url":    url,
                "path":   path,
                "status": resp.status_code,
                "size":   size,
                "note":   note,
            }
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None

    def _print_finding(self, r: dict):
        code    = r["status"]
        url     = r["url"]
        note    = r["note"]

        if code in HIGH_VALUE_CODES and r["path"].lower() in HIGH_VALUE_PATHS:
            reporter.finding(f"[{code}] CRITICAL", f"{url}  {note}", severity="critical")
        elif code in HIGH_VALUE_CODES:
            reporter.finding(f"[{code}]", f"{url}  {note}", severity="medium")
        elif code in AUTH_CODES:
            reporter.finding(f"[{code}]", f"{url}  {note}", severity="low")
        else:
            reporter.finding(f"[{code}]", f"{url}  {note}", severity="info")
