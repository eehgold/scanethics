"""
WebVulnScanner — analyse HTTP responses for common misconfigurations and
information disclosure.

Checks performed (pure Python / requests, no external tools):
  1. Missing / weak security headers
  2. Server & technology fingerprinting (Server, X-Powered-By, X-AspNet-Version …)
  3. Cookie flags (HttpOnly, Secure, SameSite)
  4. HTTPS / HSTS enforcement
  5. Directory listing detection
  6. Error-page information leakage
  7. CORS misconfiguration
  8. HTTP methods allowed (OPTIONS probe)
  9. Clickjacking (X-Frame-Options / CSP frame-ancestors)
 10. Content-Type sniffing (X-Content-Type-Options)
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.base_scanner import BaseScanner
from core.target import Target
import core.reporter as reporter

# Security headers we expect to see
EXPECTED_HEADERS = {
    "Strict-Transport-Security":  ("high",   "HSTS not set — HTTP downgrade possible"),
    "Content-Security-Policy":    ("medium", "CSP missing — XSS risk increased"),
    "X-Frame-Options":            ("medium", "Clickjacking protection absent"),
    "X-Content-Type-Options":     ("low",    "MIME-sniffing protection absent"),
    "Referrer-Policy":            ("low",    "Referrer-Policy not set"),
    "Permissions-Policy":         ("low",    "Permissions-Policy not set"),
    "X-XSS-Protection":          ("info",   "X-XSS-Protection header absent (deprecated but informative)"),
}

# Headers that disclose technology
DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Varnish", "Via", "X-Backend",
    "X-Forwarded-For", "X-Real-Ip",
]

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def _make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; scanethics/1.0; +security-audit)",
    })
    return session


class WebVulnScanner(BaseScanner):
    name = "Web Vulnerability Scanner"
    description = "Detect HTTP misconfigurations, info disclosure and weak security headers"

    def __init__(self, target: Target, **options):
        super().__init__(target, **options)
        self.timeout = options.get("timeout", 8)

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        reporter.section(f"WEB VULN SCANNER — {self.target.base_url}")
        session  = _make_session()
        findings = []
        errors   = []

        try:
            resp = session.get(
                self.target.base_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False,
            )
        except requests.exceptions.RequestException as exc:
            reporter.error(f"Could not reach target: {exc}")
            return self._result([], errors=[str(exc)], success=False)

        # If we followed a redirect, report the final URL
        final_url = resp.url
        if final_url != self.target.base_url:
            reporter.info(f"Redirigé vers : [bold]{final_url}[/bold]")

        reporter.info(f"Response: HTTP {resp.status_code}  |  {len(resp.content)} bytes")

        findings += self._check_security_headers(resp)
        findings += self._check_disclosure_headers(resp)
        findings += self._check_https(resp)
        findings += self._check_cookies(resp)
        findings += self._check_cors(resp, session)
        findings += self._check_http_methods(session)
        findings += self._check_directory_listing(resp)
        findings += self._check_error_leakage(session)

        if findings:
            reporter.findings_table(
                "Web Vulnerability Findings",
                findings,
                [
                    ("Severity", "severity", "bold"),
                    ("Check",    "check",    "yellow"),
                    ("Detail",   "detail",   "white"),
                ],
            )
        else:
            reporter.success("No obvious web vulnerabilities detected.")

        return self._result(findings, errors=errors)

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_security_headers(self, resp: requests.Response) -> list[dict]:
        findings = []
        headers  = {k.lower(): v for k, v in resp.headers.items()}
        for header, (severity, msg) in EXPECTED_HEADERS.items():
            if header.lower() not in headers:
                findings.append({"severity": severity.upper(), "check": f"Missing {header}", "detail": msg})
                reporter.finding(f"Missing {header}", msg, severity=severity)
        return findings

    def _check_disclosure_headers(self, resp: requests.Response) -> list[dict]:
        findings = []
        for header in DISCLOSURE_HEADERS:
            value = resp.headers.get(header)
            if value:
                findings.append({"severity": "LOW", "check": f"Header: {header}", "detail": value})
                reporter.finding(f"Info disclosure → {header}", value, severity="low")
        return findings

    def _check_https(self, resp: requests.Response) -> list[dict]:
        findings = []
        final_url = resp.url
        redirected_to_https = final_url.startswith("https://")

        if self.target.scheme == "http" and not redirected_to_https:
            # Genuinely no HTTPS
            findings.append({
                "severity": "HIGH",
                "check": "No HTTPS",
                "detail": "Target does not enforce HTTPS — traffic is in cleartext",
            })
            reporter.finding("No HTTPS", "cleartext traffic possible", severity="high")
        elif self.target.scheme == "http" and redirected_to_https:
            # HTTP redirects to HTTPS — note it but it's not a critical issue
            reporter.info("HTTP redirige vers HTTPS (correct), mais analyse les headers HTTPS ci-dessous.")

        hsts = resp.headers.get("Strict-Transport-Security", "")
        if not hsts:
            # Already reported by _check_security_headers, skip duplicate
            pass
        elif "includeSubDomains" not in hsts:
            findings.append({
                "severity": "LOW",
                "check": "HSTS incomplet",
                "detail": "includeSubDomains absent du header HSTS",
            })
        return findings

    def _check_cookies(self, resp: requests.Response) -> list[dict]:
        findings = []
        for cookie in resp.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "_rest", {}).get("HttpOnly"):
                # requests parses HttpOnly into _rest
                if "httponly" not in str(cookie).lower():
                    issues.append("HttpOnly missing")
            if not cookie.secure:
                issues.append("Secure flag missing")
            if "samesite" not in str(getattr(cookie, "_rest", {})).lower():
                issues.append("SameSite not set")
            if issues:
                detail = f"Cookie '{cookie.name}': {', '.join(issues)}"
                findings.append({"severity": "MEDIUM", "check": "Insecure Cookie", "detail": detail})
                reporter.finding("Insecure Cookie", detail, severity="medium")
        return findings

    def _check_cors(self, resp: requests.Response, session: requests.Session) -> list[dict]:
        findings = []
        try:
            r = session.options(
                self.target.base_url,
                headers={"Origin": "https://evil.example.com"},
                timeout=self.timeout,
                verify=False,
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                findings.append({"severity": "MEDIUM", "check": "CORS wildcard", "detail": "ACAO: *"})
                reporter.finding("CORS wildcard", "Access-Control-Allow-Origin: *", severity="medium")
            if acao == "https://evil.example.com":
                sev = "critical" if acac.lower() == "true" else "high"
                findings.append({"severity": sev.upper(), "check": "CORS origin reflection", "detail": f"ACAO reflects arbitrary origin. Credentials: {acac}"})
                reporter.finding("CORS origin reflection", f"ACAO reflects evil.example.com | Credentials: {acac}", severity=sev)
        except Exception:
            pass
        return findings

    def _check_http_methods(self, session: requests.Session) -> list[dict]:
        findings = []
        try:
            r = session.options(self.target.base_url, timeout=self.timeout, verify=False)
            allowed = r.headers.get("Allow", "")
            dangerous = DANGEROUS_METHODS & {m.strip().upper() for m in allowed.split(",")}
            if dangerous:
                detail = f"Allowed: {', '.join(dangerous)}"
                findings.append({"severity": "MEDIUM", "check": "Dangerous HTTP methods", "detail": detail})
                reporter.finding("Dangerous HTTP methods", detail, severity="medium")
        except Exception:
            pass
        return findings

    def _check_directory_listing(self, resp: requests.Response) -> list[dict]:
        findings = []
        indicators = ["Index of /", "Directory listing for", "Parent Directory", "[PARENTDIR]"]
        body = resp.text
        for indicator in indicators:
            if indicator in body:
                findings.append({"severity": "HIGH", "check": "Directory listing", "detail": f"Indicator found: '{indicator}'"})
                reporter.finding("Directory listing enabled", indicator, severity="high")
                break
        return findings

    def _check_error_leakage(self, session: requests.Session) -> list[dict]:
        """Request a non-existent path and look for framework/stack traces."""
        findings = []
        probe_url = f"{self.target.base_url}/scanethics-probe-404-{id(self)}"
        try:
            r = session.get(probe_url, timeout=self.timeout, verify=False, allow_redirects=False)
            body = r.text.lower()
            leaks = {
                "stack trace": ["traceback", "stack trace", "at java.", "at org.", "at com."],
                "framework version": ["laravel", "symfony", "django", "rails", "express", "asp.net"],
                "SQL error": ["sql syntax", "mysql_fetch", "ora-", "pg_query", "sqlite_"],
                "PHP error": ["fatal error", "warning:", "notice:", "parse error"],
            }
            for category, patterns in leaks.items():
                if any(p in body for p in patterns):
                    matched = next(p for p in patterns if p in body)
                    findings.append({"severity": "HIGH", "check": "Error leakage", "detail": f"{category} detected in 404 page ('{matched}')"})
                    reporter.finding(f"Error leakage — {category}", f"Detected in error page", severity="high")
        except Exception:
            pass
        return findings
