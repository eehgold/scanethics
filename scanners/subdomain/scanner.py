"""
SubdomainScanner — enumerate subdomains via DNS resolution.

Strategy:
  1. DNS brute-force with a built-in wordlist (pure socket / dnspython)
  2. Certificate Transparency logs query (crt.sh — public API, no key needed)

No external tools required.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.base_scanner import BaseScanner
from core.target import Target
import core.reporter as reporter

# Built-in subdomain wordlist (common subdomains)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "dev", "staging", "api", "admin", "blog", "shop", "forum", "portal",
    "beta", "alpha", "cdn", "media", "static", "assets", "img", "images",
    "vpn", "remote", "intranet", "internal", "private", "secure", "login",
    "auth", "sso", "iam", "oauth", "git", "gitlab", "github", "svn", "hg",
    "jenkins", "ci", "cd", "build", "deploy", "docs", "wiki", "kb", "help",
    "support", "status", "monitor", "grafana", "kibana", "prometheus", "elk",
    "mysql", "db", "database", "redis", "mongo", "elastic", "solr",
    "backup", "bak", "old", "new", "v1", "v2", "v3", "app", "apps",
    "mobile", "android", "ios", "web", "ws", "wss", "socket", "chat",
    "download", "downloads", "upload", "uploads", "files", "storage", "s3",
    "office", "crm", "erp", "jira", "confluence", "bitbucket", "trello",
    "dev1", "dev2", "test1", "test2", "stage", "prod", "production",
    "sandbox", "demo", "preview", "review", "canary",
    "mx", "mx1", "mx2", "smtp1", "smtp2", "relay", "gateway",
    "firewall", "proxy", "lb", "loadbalancer", "haproxy", "nginx",
    "k8s", "kubernetes", "docker", "registry", "harbor",
    "uat", "qa", "pre-prod", "preprod", "hotfix", "release",
]

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"


class SubdomainScanner(BaseScanner):
    name = "Subdomain Scanner"
    description = "Enumerate subdomains via DNS brute-force and Certificate Transparency logs"

    def __init__(self, target: Target, **options):
        super().__init__(target, **options)
        self.workers = options.get("workers", 50)
        self.timeout = options.get("timeout", 2.0)
        self.use_crtsh = options.get("use_crtsh", True)

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        if self.target.is_ip:
            reporter.warning("Target is an IP address — subdomain enumeration skipped.")
            return self._result([])

        reporter.section(f"SUBDOMAIN SCANNER — {self.target.hostname}")

        findings: list[dict] = []
        errors:   list[str]  = []

        # 1. DNS brute-force
        reporter.info(f"DNS brute-force with {len(SUBDOMAIN_WORDLIST)} prefixes …")
        dns_results = self._dns_bruteforce()
        findings += dns_results

        # 2. Certificate Transparency
        if self.use_crtsh:
            reporter.info("Querying crt.sh Certificate Transparency logs …")
            try:
                ct_results = self._crtsh_lookup()
                # Merge: avoid duplicates already found via DNS
                known = {r["subdomain"] for r in findings}
                for r in ct_results:
                    if r["subdomain"] not in known:
                        findings.append(r)
            except Exception as exc:
                errors.append(f"crt.sh query failed: {exc}")
                reporter.warning(f"crt.sh unreachable: {exc}")

        if findings:
            # Try to resolve CT-found subdomains that weren't DNS-resolved yet
            for f in findings:
                if not f.get("ip"):
                    f["ip"] = self._resolve(f["subdomain"]) or ""

            reporter.findings_table(
                "Discovered Subdomains",
                findings,
                [
                    ("Subdomain", "subdomain", "bold cyan"),
                    ("IP",        "ip",        "yellow"),
                    ("Source",    "source",    "dim"),
                ],
            )
        else:
            reporter.warning("No subdomains discovered.")

        return self._result(findings, errors=errors)

    # ── Private ───────────────────────────────────────────────────────────────

    def _resolve(self, hostname: str) -> str | None:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _dns_bruteforce(self) -> list[dict]:
        results = []
        domain  = self.target.hostname
        # Strip leading www. if present to avoid www.www.
        if domain.startswith("www."):
            domain = domain[4:]

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {
                pool.submit(self._check_subdomain, f"{prefix}.{domain}"): prefix
                for prefix in SUBDOMAIN_WORDLIST
            }
            for future in as_completed(futures):
                prefix = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        reporter.success(f"Found: {result['subdomain']}  →  {result['ip']}")
                except Exception:
                    pass

        return results

    def _check_subdomain(self, fqdn: str) -> dict | None:
        ip = self._resolve(fqdn)
        if ip:
            return {"subdomain": fqdn, "ip": ip, "source": "DNS brute-force"}
        return None

    def _crtsh_lookup(self) -> list[dict]:
        domain = self.target.hostname
        if domain.startswith("www."):
            domain = domain[4:]

        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()

        seen: set[str] = set()
        results: list[dict] = []

        for entry in data:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lstrip("*.")
                if not name or name in seen:
                    continue
                if not name.endswith(domain):
                    continue
                seen.add(name)
                results.append({"subdomain": name, "ip": "", "source": "crt.sh CT log"})
                reporter.info(f"CT log: {name}")

        return results
