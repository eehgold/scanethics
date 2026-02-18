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
    21:    {"service": "FTP",           "severity": "HIGH",     "note": "FTP en clair — credentials sniffables. Cherche anonymous login."},
    22:    {"service": "SSH",           "severity": "MEDIUM",   "note": "SSH exposé. Vérifie la version (bannière) pour CVEs connus."},
    23:    {"service": "Telnet",        "severity": "CRITICAL", "note": "Telnet = clair text. Credentials capturables en réseau."},
    25:    {"service": "SMTP",          "severity": "MEDIUM",   "note": "SMTP exposé. Teste open relay, user enumeration (VRFY/EXPN)."},
    3306:  {"service": "MySQL",         "severity": "HIGH",     "note": "Base de données exposée publiquement. Accès direct possible."},
    5432:  {"service": "PostgreSQL",    "severity": "HIGH",     "note": "Base de données exposée publiquement."},
    6379:  {"service": "Redis",         "severity": "CRITICAL", "note": "Redis souvent sans auth → RCE via cron/SSH keys. CVE-2022-0543."},
    9200:  {"service": "Elasticsearch", "severity": "HIGH",     "note": "Elasticsearch souvent sans auth → dump de données complet."},
    9300:  {"service": "Elasticsearch", "severity": "HIGH",     "note": "Port cluster Elasticsearch — accès non authentifié probable."},
    11211: {"service": "Memcached",     "severity": "HIGH",     "note": "Memcached sans auth → dump cache. Utilisé aussi pour DRDoS."},
    27017: {"service": "MongoDB",       "severity": "CRITICAL", "note": "MongoDB souvent sans auth. Dump complet via mongo shell."},
    5900:  {"service": "VNC",           "severity": "HIGH",     "note": "VNC exposé. Brute-force possible, parfois sans mot de passe."},
    3389:  {"service": "RDP",           "severity": "HIGH",     "note": "RDP exposé. BlueKeep (CVE-2019-0708), DejaBlue, brute-force."},
    4444:  {"service": "Metasploit",    "severity": "CRITICAL", "note": "Port Metasploit par défaut — système peut déjà être compromis!"},
    8888:  {"service": "Jupyter",       "severity": "CRITICAL", "note": "Jupyter Notebook souvent sans auth → exécution de code arbitraire."},
    9090:  {"service": "Prometheus",    "severity": "MEDIUM",   "note": "Prometheus metrics exposées — fuite d'infos système."},
    15672: {"service": "RabbitMQ Mgmt", "severity": "MEDIUM",   "note": "Interface RabbitMQ. Credentials par défaut : guest/guest."},
    2375:  {"service": "Docker API",    "severity": "CRITICAL", "note": "Docker API non TLS → container escape, RCE root sur l'hôte."},
    2376:  {"service": "Docker TLS",    "severity": "HIGH",     "note": "Docker API TLS. Vérifie si le certificat client est requis."},
    8080:  {"service": "HTTP alt",      "severity": "LOW",      "note": "Serveur HTTP alternatif. Peut exposer un proxy ou app de dev."},
    8443:  {"service": "HTTPS alt",     "severity": "LOW",      "note": "HTTPS alternatif. Souvent panel admin ou app de staging."},
    10000: {"service": "Webmin",        "severity": "CRITICAL", "note": "Webmin (admin serveur web). CVE-2019-15107 = RCE non authentifié. Accède à https://host:10000"},
    1433:  {"service": "MSSQL",         "severity": "HIGH",     "note": "SQL Server exposé. Brute-force sa/admin, xp_cmdshell possible."},
    1521:  {"service": "Oracle DB",     "severity": "HIGH",     "note": "Oracle DB exposée. Brute-force SID, TNS poisoning."},
    5984:  {"service": "CouchDB",       "severity": "HIGH",     "note": "CouchDB — souvent accessible sans auth sur /_all_dbs."},
    7474:  {"service": "Neo4j",         "severity": "MEDIUM",   "note": "Neo4j browser exposé. Cypher injection possible."},
    8983:  {"service": "Apache Solr",   "severity": "HIGH",     "note": "Solr Log4Shell (CVE-2021-44228) si version < 8.11.1."},
    61616: {"service": "ActiveMQ",      "severity": "CRITICAL", "note": "ActiveMQ CVE-2023-46604 = RCE non authentifié (très exploité)."},
    50070: {"service": "Hadoop HDFS",   "severity": "HIGH",     "note": "Hadoop NameNode UI — accès fichiers sans auth possible."},
    1883:  {"service": "MQTT",          "severity": "MEDIUM",   "note": "Broker MQTT. Souvent sans auth → subscribe à tous les topics."},
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
                    title    = f"Port {port} ouvert — {info['service']}",
                    detail   = info["note"],
                    action   = f"Investigate: https://{self.target.hostname}:{port}  |  Banner: {banner[:100] or 'N/A'}",
                ))
            else:
                # Unknown service on non-standard port — still worth noting
                if port not in (80, 443):
                    findings.append(AnalysisFinding(
                        category = "Port",
                        severity = "LOW",
                        title    = f"Port {port} ouvert — service inconnu",
                        detail   = banner[:120] if banner else "Aucune bannière récupérée.",
                        action   = f"Identifier le service manuellement sur le port {port}.",
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
                title          = "Faux positifs — redirection HTTP → HTTPS globale",
                detail         = (
                    f"{redirect_count}/{len(all_entries)} chemins retournent un redirect 3xx. "
                    "Le serveur redirige tout le trafic HTTP vers HTTPS, rendant les résultats non fiables."
                ),
                action         = f"Relancer le fuzzer directement sur HTTPS : python main.py https://{self.target.hostname} --only dirs",
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
                    title    = f"Fichier sensible accessible : /{path}",
                    detail   = f"HTTP 200 — {size} octets. Ce fichier ne devrait pas être public.",
                    action   = f"Accède à {url} et vérifie le contenu immédiatement.",
                ))
            else:
                findings.append(AnalysisFinding(
                    category = "DirFuzzer",
                    severity = "MEDIUM",
                    title    = f"Chemin découvert : /{path}",
                    detail   = f"HTTP 200 — {size} octets.",
                    action   = f"Examiner manuellement : {url}",
                ))

        for entry in auth_403:
            path = entry.get("path", "")
            url  = entry.get("url", "")
            findings.append(AnalysisFinding(
                category = "DirFuzzer",
                severity = "LOW",
                title    = f"Ressource protégée détectée : /{path}",
                detail   = f"HTTP {entry.get('status')} — accès refusé mais existence confirmée.",
                action   = f"Tenter de contourner l'authentification ou brute-forcer : {url}",
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
                    title          = "HTTP sans HTTPS — faux positif",
                    detail         = "Le scanner a analysé http:// mais le port 443 est ouvert. Le site redirige bien vers HTTPS.",
                    action         = "Relancer WebVuln directement sur https:// pour une analyse précise.",
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
                    title          = f"Wildcard DNS détecté → {wildcard_ip}",
                    detail         = (
                        f"{len(wildcard_noise)} sous-domaines résolvent vers {wildcard_ip} à cause d'un enregistrement "
                        f"*.{self.target.hostname} → leur existence en tant que service est non confirmée."
                    ),
                    action         = "Vérifier manuellement les sous-domaines à haute valeur listés ci-dessous.",
                    false_positive = True,
                ))

            # Among wildcard-IP subs, highlight the high-value ones for manual check
            for sub in wildcard_noise:
                prefix = sub["subdomain"].split(".")[0].lower()
                if prefix in HIGH_VALUE_SUBDOMAINS:
                    findings.append(AnalysisFinding(
                        category = "Subdomains",
                        severity = "MEDIUM",
                        title    = f"Sous-domaine à vérifier (wildcard) : {sub['subdomain']}",
                        detail   = f"Résout vers {sub['ip']} (wildcard) mais le préfixe '{prefix}' suggère un service réel potentiel.",
                        action   = f"Ouvrir https://{sub['subdomain']} dans un navigateur pour confirmer.",
                    ))

            # Subdomains with a DIFFERENT IP — definitely real
            for sub in real_subs:
                findings.append(AnalysisFinding(
                    category = "Subdomains",
                    severity = "HIGH",
                    title    = f"Sous-domaine réel (IP différente) : {sub['subdomain']}",
                    detail   = f"IP : {sub['ip']} ≠ wildcard {wildcard_ip} — ce service existe vraiment.",
                    action   = f"Scanner ce sous-domaine séparément : python main.py {sub['subdomain']}",
                ))

        else:
            # No wildcard — every resolved subdomain is real
            for sub in all_subs:
                prefix = sub["subdomain"].split(".")[0].lower()
                sev = "HIGH" if prefix in HIGH_VALUE_SUBDOMAINS else "LOW"
                findings.append(AnalysisFinding(
                    category = "Subdomains",
                    severity = sev,
                    title    = f"Sous-domaine : {sub['subdomain']}",
                    detail   = f"IP : {sub['ip']}  |  source : {sub.get('source', '?')}",
                    action   = f"Scanner : python main.py {sub['subdomain']}" if sev == "HIGH" else "",
                ))

        return findings


# ── Web vuln action hints ─────────────────────────────────────────────────────

def _web_vuln_action(check: str) -> str:
    hints = {
        "Missing Strict-Transport-Security": (
            "Ajouter 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "
            "dans les headers HTTP du serveur."
        ),
        "Missing Content-Security-Policy": (
            "Définir une CSP restrictive. Impact : XSS, injection de scripts tiers."
        ),
        "Missing X-Frame-Options": (
            "Ajouter 'X-Frame-Options: DENY' ou utiliser CSP 'frame-ancestors none'. "
            "Tester le clickjacking avec un iframe basique."
        ),
        "Missing X-Content-Type-Options": (
            "Ajouter 'X-Content-Type-Options: nosniff'."
        ),
        "Directory listing": (
            "Désactiver l'indexation de répertoire (Apache: Options -Indexes, Nginx: autoindex off)."
        ),
        "CORS wildcard": (
            "Remplacer Access-Control-Allow-Origin: * par un domaine explicite autorisé."
        ),
        "CORS origin reflection": (
            "CRITIQUE : le serveur reflète n'importe quelle origine. "
            "Combiné à Allow-Credentials: true → vol de session cross-origin."
        ),
        "Dangerous HTTP methods": (
            "Désactiver PUT/DELETE/TRACE dans la config du serveur. "
            "TRACE active les attaques XST (Cross-Site Tracing)."
        ),
        "Error leakage": (
            "Configurer des pages d'erreur génériques. "
            "Les stack traces révèlent la stack technique et facilitent le ciblage."
        ),
        "Insecure Cookie": (
            "Ajouter les flags HttpOnly, Secure et SameSite=Strict à tous les cookies de session."
        ),
    }
    for key, hint in hints.items():
        if key.lower() in check.lower():
            return hint
    return ""
