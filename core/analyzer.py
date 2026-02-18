"""
Analyzer — post-scan intelligence engine.

After all scanners finish, the Analyzer:
  1. Detects wildcard DNS (flags subdomain false positives)
  2. Identifies notable / dangerous services on open ports
  3. Detects HTTP→HTTPS redirect flood in dir-fuzzer results
  4. Filters real web-vuln findings from scanner noise
  5. Produces a prioritised list of actionable recommendations
"""

import random
import socket
import string
from dataclasses import dataclass, field


# ── Known high-value / dangerous services ────────────────────────────────────

NOTABLE_PORTS: dict[int, dict] = {
    21:    {"service": "FTP",           "severity": "HIGH",     "note": "FTP cleartext — credentials sniffable. Check for anonymous login."},
    22:    {"service": "SSH",           "severity": "MEDIUM",   "note": "SSH exposed. Check version (banner) for known CVEs."},
    23:    {"service": "Telnet",        "severity": "CRITICAL", "note": "Telnet = cleartext. Credentials capturable on the network."},
    25:    {"service": "SMTP",          "severity": "MEDIUM",   "note": "SMTP exposed. Test open relay, user enumeration (VRFY/EXPN)."},
    3306:  {"service": "MySQL",         "severity": "HIGH",     "note": "Database publicly exposed. Direct access possible."},
    5432:  {"service": "PostgreSQL",    "severity": "HIGH",     "note": "Database publicly exposed."},
    6379:  {"service": "Redis",         "severity": "CRITICAL", "note": "Redis often has no auth → RCE via cron/SSH keys. CVE-2022-0543."},
    9200:  {"service": "Elasticsearch", "severity": "HIGH",     "note": "Elasticsearch often has no auth → full data dump possible."},
    9300:  {"service": "Elasticsearch", "severity": "HIGH",     "note": "Elasticsearch cluster port — unauthenticated access likely."},
    11211: {"service": "Memcached",     "severity": "HIGH",     "note": "Memcached no auth → cache dump. Also used for DRDoS amplification."},
    27017: {"service": "MongoDB",       "severity": "CRITICAL", "note": "MongoDB often has no auth. Full dump via mongo shell."},
    5900:  {"service": "VNC",           "severity": "HIGH",     "note": "VNC exposed. Brute-force possible, sometimes no password required."},
    3389:  {"service": "RDP",           "severity": "HIGH",     "note": "RDP exposed. BlueKeep (CVE-2019-0708), DejaBlue, brute-force."},
    4444:  {"service": "Metasploit",    "severity": "CRITICAL", "note": "Default Metasploit port — system may already be compromised!"},
    8888:  {"service": "Jupyter",       "severity": "CRITICAL", "note": "Jupyter Notebook often has no auth → arbitrary code execution."},
    9090:  {"service": "Prometheus",    "severity": "MEDIUM",   "note": "Prometheus metrics exposed — system information disclosure."},
    15672: {"service": "RabbitMQ Mgmt", "severity": "MEDIUM",   "note": "RabbitMQ management UI. Default credentials: guest/guest."},
    2375:  {"service": "Docker API",    "severity": "CRITICAL", "note": "Docker API without TLS → container escape, root RCE on host."},
    2376:  {"service": "Docker TLS",    "severity": "HIGH",     "note": "Docker TLS API. Check if client certificate is required."},
    8080:  {"service": "HTTP alt",      "severity": "LOW",      "note": "Alternate HTTP server. May expose a proxy or dev app."},
    8443:  {"service": "HTTPS alt",     "severity": "LOW",      "note": "Alternate HTTPS. Often an admin panel or staging app."},
    10000: {"service": "Webmin",        "severity": "CRITICAL", "note": "Webmin (web-based server admin). CVE-2019-15107 = unauthenticated RCE. Visit https://host:10000"},
    1433:  {"service": "MSSQL",         "severity": "HIGH",     "note": "SQL Server publicly exposed. Brute-force sa/admin, xp_cmdshell possible."},
    1521:  {"service": "Oracle DB",     "severity": "HIGH",     "note": "Oracle DB exposed. Brute-force SID, TNS poisoning."},
    5984:  {"service": "CouchDB",       "severity": "HIGH",     "note": "CouchDB — often accessible without auth at /_all_dbs."},
    7474:  {"service": "Neo4j",         "severity": "MEDIUM",   "note": "Neo4j browser exposed. Cypher injection possible."},
    8983:  {"service": "Apache Solr",   "severity": "HIGH",     "note": "Solr Log4Shell (CVE-2021-44228) if version < 8.11.1."},
    61616: {"service": "ActiveMQ",      "severity": "CRITICAL", "note": "ActiveMQ CVE-2023-46604 = unauthenticated RCE (widely exploited)."},
    50070: {"service": "Hadoop HDFS",   "severity": "HIGH",     "note": "Hadoop NameNode UI — file access without auth possible."},
    1883:  {"service": "MQTT",          "severity": "MEDIUM",   "note": "MQTT broker. Often no auth → subscribe to all topics."},
}

# High-value subdomain prefixes (real services, not wildcard noise)
HIGH_VALUE_SUBDOMAINS = {
    "admin", "administrator", "cpanel", "whm", "webmin", "plesk", "panel",
    "manager", "manage", "console", "control", "controlpanel", "dashboard",
    "dev", "development", "staging", "stage", "beta", "alpha", "test", "qa",
    "uat", "old", "legacy", "backup",
    "gitlab", "git", "svn", "hg", "jenkins", "ci", "build", "nexus",
    "api", "api-dev", "api-staging", "graphql",
    "vpn", "remote", "rdp", "ssh",
    "intranet", "internal", "private", "secret", "secure",
    "iam", "sso", "auth", "oauth", "login",
    "kibana", "grafana", "prometheus", "elk", "logs",
    "docker", "registry", "k8s", "kubernetes",
    "db", "database", "mysql", "redis", "mongo", "elastic",
    "shop", "store", "checkout", "payment",
}


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class AnalysisFinding:
    category:    str
    severity:    str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title:       str
    detail:      str
    action:      str = ""     # what to do next
    false_positive: bool = False


@dataclass
class AnalysisReport:
    target:          str
    wildcard_ip:     str | None             # None if no wildcard DNS
    port_findings:   list[AnalysisFinding] = field(default_factory=list)
    dir_findings:    list[AnalysisFinding] = field(default_factory=list)
    web_findings:    list[AnalysisFinding] = field(default_factory=list)
    sub_findings:    list[AnalysisFinding] = field(default_factory=list)
    noise_log:       list[str]             = field(default_factory=list)

    @property
    def all_real_findings(self) -> list[AnalysisFinding]:
        all_f = self.port_findings + self.dir_findings + self.web_findings + self.sub_findings
        return [f for f in all_f if not f.false_positive]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.all_real_findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.all_real_findings if f.severity == "HIGH")


# ── Analyzer ─────────────────────────────────────────────────────────────────

class Analyzer:
    def __init__(self, target, results: dict):
        self.target  = target
        self.results = results

    def run(self) -> AnalysisReport:
        wildcard_ip = self._detect_wildcard_dns()
        report = AnalysisReport(target=str(self.target), wildcard_ip=wildcard_ip)

        report.port_findings = self._analyze_ports()
        report.dir_findings  = self._analyze_dirs()
        report.web_findings  = self._analyze_web()
        report.sub_findings  = self._analyze_subdomains(wildcard_ip)

        return report

    # ── Wildcard DNS ──────────────────────────────────────────────────────────

    def _detect_wildcard_dns(self) -> str | None:
        if self.target.is_ip:
            return None
        domain = self.target.hostname
        # Generate a random subdomain that cannot exist
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        probe = f"{rand}.{domain}"
        try:
            ip = socket.gethostbyname(probe)
            return ip   # wildcard confirmed
        except socket.gaierror:
            return None

    # ── Ports ─────────────────────────────────────────────────────────────────

    def _analyze_ports(self) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        port_results = self.results.get("ports", {})
        if not port_results.get("success"):
            return findings

        for entry in port_results.get("findings", []):
            port    = entry.get("port")
            banner  = entry.get("banner", "")
            service = entry.get("service", "unknown")

            info = NOTABLE_PORTS.get(port)
            if info:
                findings.append(AnalysisFinding(
                    category = "Port",
                    severity = info["severity"],
                    title    = f"Port {port} open — {info['service']}",
                    detail   = info["note"],
                    action   = f"Investigate: https://{self.target.hostname}:{port}  |  Banner: {banner[:100] or 'N/A'}",
                ))
            else:
                # Unknown service on non-standard port — still worth noting
                if port not in (80, 443):
                    findings.append(AnalysisFinding(
                        category = "Port",
                        severity = "LOW",
                        title    = f"Port {port} open — unknown service",
                        detail   = banner[:120] if banner else "No banner retrieved.",
                        action   = f"Manually identify the service on port {port}.",
                    ))

        return findings

    # ── Directory fuzzer ──────────────────────────────────────────────────────

    def _analyze_dirs(self) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        dir_results = self.results.get("dirs", {})
        if not dir_results.get("success"):
            return findings

        all_entries = dir_results.get("findings", [])
        if not all_entries:
            return findings

        # Detect HTTP → HTTPS redirect flood (false positive)
        redirect_count = sum(1 for e in all_entries if e.get("status") in (301, 302, 307, 308))
        redirect_ratio = redirect_count / len(all_entries) if all_entries else 0

        if redirect_ratio > 0.85:
            findings.append(AnalysisFinding(
                category       = "DirFuzzer",
                severity       = "INFO",
                title          = "False positives — global HTTP → HTTPS redirect",
                detail         = (
                    f"{redirect_count}/{len(all_entries)} paths returned a 3xx redirect. "
                    "The server redirects all HTTP traffic to HTTPS, making these results unreliable."
                ),
                action         = f"Re-run the fuzzer directly on HTTPS: python main.py https://{self.target.hostname} --only dirs",
                false_positive = True,
            ))
            return findings  # No point analysing the rest — all noise

        # Real analysis: filter interesting status codes
        real_200 = [e for e in all_entries if e.get("status") == 200]
        auth_403 = [e for e in all_entries if e.get("status") in (401, 403)]

        sensitive_paths = {
            ".env", ".env.backup", ".env.local", ".git", ".git/HEAD", ".git/config",
            "wp-config.php", "config.php", "phpinfo.php", "info.php",
            "backup", "dump.sql", "db.sql", "database.sql", "server-status",
            "actuator/env", "actuator/health", ".htpasswd",
        }

        for entry in real_200:
            path = entry.get("path", "")
            url  = entry.get("url", "")
            size = entry.get("size", 0)

            if path.lower() in sensitive_paths:
                findings.append(AnalysisFinding(
                    category = "DirFuzzer",
                    severity = "CRITICAL",
                    title    = f"Sensitive file accessible: /{path}",
                    detail   = f"HTTP 200 — {size} bytes. This file should not be publicly accessible.",
                    action   = f"Access {url} and inspect the content immediately.",
                ))
            else:
                findings.append(AnalysisFinding(
                    category = "DirFuzzer",
                    severity = "MEDIUM",
                    title    = f"Path discovered: /{path}",
                    detail   = f"HTTP 200 — {size} bytes.",
                    action   = f"Manually inspect: {url}",
                ))

        for entry in auth_403:
            path = entry.get("path", "")
            url  = entry.get("url", "")
            findings.append(AnalysisFinding(
                category = "DirFuzzer",
                severity = "LOW",
                title    = f"Protected resource detected: /{path}",
                detail   = f"HTTP {entry.get('status')} — access denied but existence confirmed.",
                action   = f"Attempt to bypass authentication or brute-force: {url}",
            ))

        return findings

    # ── Web vulnerabilities ───────────────────────────────────────────────────

    def _analyze_web(self) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        web_results = self.results.get("web", {})
        if not web_results.get("success"):
            return findings

        port_findings_data = self.results.get("ports", {}).get("findings", [])
        open_ports = {e["port"] for e in port_findings_data}
        has_https_port = 443 in open_ports

        for entry in web_results.get("findings", []):
            check    = entry.get("check", "")
            severity = entry.get("severity", "INFO")
            detail   = entry.get("detail", "")

            # Filter false positive: "No HTTPS" when port 443 is open
            if check == "No HTTPS" and has_https_port:
                findings.append(AnalysisFinding(
                    category       = "WebVuln",
                    severity       = "INFO",
                    title          = "HTTP without HTTPS — false positive",
                    detail         = "The scanner analysed http:// but port 443 is open. The site correctly redirects to HTTPS.",
                    action         = "Re-run WebVuln directly on https:// for accurate analysis.",
                    false_positive = True,
                ))
                continue

            action = _web_vuln_action(check)
            findings.append(AnalysisFinding(
                category = "WebVuln",
                severity = severity,
                title    = check,
                detail   = detail,
                action   = action,
            ))

        return findings

    # ── Subdomains ────────────────────────────────────────────────────────────

    def _analyze_subdomains(self, wildcard_ip: str | None) -> list[AnalysisFinding]:
        findings: list[AnalysisFinding] = []
        sub_results = self.results.get("subdomains", {})
        if not sub_results.get("success"):
            return findings

        all_subs = sub_results.get("findings", [])
        if not all_subs:
            return findings

        if wildcard_ip:
            # Wildcard confirmed — distinguish "same wildcard IP" from genuinely different IPs
            wildcard_noise = [s for s in all_subs if s.get("ip") == wildcard_ip]
            real_subs      = [s for s in all_subs if s.get("ip") != wildcard_ip]

            if wildcard_noise:
                findings.append(AnalysisFinding(
                    category       = "Subdomains",
                    severity       = "INFO",
                    title          = f"Wildcard DNS detected → {wildcard_ip}",
                    detail         = (
                        f"{len(wildcard_noise)} subdomains resolve to {wildcard_ip} due to a "
                        f"*.{self.target.hostname} wildcard record — their existence as actual services is unconfirmed."
                    ),
                    action         = "Manually verify the high-value subdomains listed below.",
                    false_positive = True,
                ))

            # Among wildcard-IP subs, highlight the high-value ones for manual check
            for sub in wildcard_noise:
                prefix = sub["subdomain"].split(".")[0].lower()
                if prefix in HIGH_VALUE_SUBDOMAINS:
                    findings.append(AnalysisFinding(
                        category = "Subdomains",
                        severity = "MEDIUM",
                        title    = f"Subdomain to verify (wildcard): {sub['subdomain']}",
                        detail   = f"Resolves to {sub['ip']} (wildcard) but prefix '{prefix}' suggests a potentially real service.",
                        action   = f"Open https://{sub['subdomain']} in a browser to confirm.",
                    ))

            # Subdomains with a DIFFERENT IP — definitely real
            for sub in real_subs:
                findings.append(AnalysisFinding(
                    category = "Subdomains",
                    severity = "HIGH",
                    title    = f"Real subdomain (different IP): {sub['subdomain']}",
                    detail   = f"IP: {sub['ip']} ≠ wildcard {wildcard_ip} — this service actually exists.",
                    action   = f"Scan this subdomain separately: python main.py {sub['subdomain']}",
                ))

        else:
            # No wildcard — every resolved subdomain is real
            for sub in all_subs:
                prefix = sub["subdomain"].split(".")[0].lower()
                sev = "HIGH" if prefix in HIGH_VALUE_SUBDOMAINS else "LOW"
                findings.append(AnalysisFinding(
                    category = "Subdomains",
                    severity = sev,
                    title    = f"Subdomain: {sub['subdomain']}",
                    detail   = f"IP: {sub['ip']}  |  source: {sub.get('source', '?')}",
                    action   = f"Scan: python main.py {sub['subdomain']}" if sev == "HIGH" else "",
                ))

        return findings


# ── Web vuln action hints ─────────────────────────────────────────────────────

def _web_vuln_action(check: str) -> str:
    hints = {
        "Missing Strict-Transport-Security": (
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "
            "to the server HTTP headers."
        ),
        "Missing Content-Security-Policy": (
            "Define a strict CSP. Impact: XSS, third-party script injection."
        ),
        "Missing X-Frame-Options": (
            "Add 'X-Frame-Options: DENY' or use CSP 'frame-ancestors none'. "
            "Test clickjacking with a basic iframe."
        ),
        "Missing X-Content-Type-Options": (
            "Add 'X-Content-Type-Options: nosniff'."
        ),
        "Directory listing": (
            "Disable directory indexing (Apache: Options -Indexes, Nginx: autoindex off)."
        ),
        "CORS wildcard": (
            "Replace Access-Control-Allow-Origin: * with an explicit allowed domain."
        ),
        "CORS origin reflection": (
            "CRITICAL: the server reflects any origin. "
            "Combined with Allow-Credentials: true → cross-origin session hijacking."
        ),
        "Dangerous HTTP methods": (
            "Disable PUT/DELETE/TRACE in server config. "
            "TRACE enables XST (Cross-Site Tracing) attacks."
        ),
        "Error leakage": (
            "Configure generic error pages. "
            "Stack traces reveal the technology stack and aid targeted attacks."
        ),
        "Insecure Cookie": (
            "Add HttpOnly, Secure and SameSite=Strict flags to all session cookies."
        ),
    }
    for key, hint in hints.items():
        if key.lower() in check.lower():
            return hint
    return ""
