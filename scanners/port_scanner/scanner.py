"""
PortScanner — discover open TCP ports and grab service banners.

Uses only the standard library (socket + concurrent.futures).
Default range: top 1000 common ports. Configurable via options.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.base_scanner import BaseScanner
from core.target import Target
import core.reporter as reporter

# fmt: off
TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888,
    # extended common ports
    20, 69, 79, 88, 102, 119, 137, 138, 161, 162, 194, 389, 636, 873,
    990, 992, 1080, 1194, 1433, 1521, 1883, 2049, 2121, 2222, 2375, 2376,
    3000, 3128, 3306, 4000, 4243, 4443, 4444, 4848, 5000, 5432, 5672,
    5984, 6000, 6379, 6443, 7000, 7001, 7070, 7443, 7474, 7777, 8000,
    8001, 8008, 8009, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8088,
    8090, 8161, 8180, 8443, 8500, 8888, 8983, 9000, 9001, 9042, 9090,
    9092, 9200, 9300, 9418, 9999, 10000, 11211, 15672, 16379, 27017,
    27018, 27019, 28017, 50070, 61616,
]
# fmt: on

COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 119: "nntp", 135: "msrpc", 137: "netbios-ns",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 194: "irc", 389: "ldap",
    443: "https", 445: "smb", 636: "ldaps", 873: "rsync", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "dev-server", 3306: "mysql",
    3389: "rdp", 4444: "metasploit", 5000: "upnp/flask", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 8888: "jupyter", 9200: "elasticsearch",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
}


class PortScanner(BaseScanner):
    name = "Port Scanner"
    description = "Discover open TCP ports and grab service banners"

    def __init__(self, target: Target, **options):
        super().__init__(target, **options)
        self.ports = options.get("ports", TOP_1000_PORTS)
        self.timeout = options.get("timeout", 1.0)
        self.max_workers = options.get("max_workers", 150)
        self.banner_timeout = options.get("banner_timeout", 2.0)

    # ── Public ────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        reporter.section(f"PORT SCANNER — {self.target.hostname}")
        reporter.info(f"Scanning {len(self.ports)} ports with {self.max_workers} threads …")

        open_ports = self._scan_ports()

        if not open_ports:
            reporter.warning("No open ports found.")
            return self._result([])

        reporter.success(f"Found {len(open_ports)} open port(s). Grabbing banners …")
        findings = [self._enrich(p) for p in open_ports]
        reporter.port_table(findings)
        return self._result(findings)

    # ── Private ───────────────────────────────────────────────────────────────

    def _scan_ports(self) -> list[int]:
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._check_port, p): p for p in self.ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        reporter.success(f"Port {port}/tcp OPEN")
                except Exception:
                    pass
        return sorted(open_ports)

    def _check_port(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            return s.connect_ex((self.target.hostname, port)) == 0

    def _grab_banner(self, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.banner_timeout)
                s.connect((self.target.hostname, port))
                # Send HTTP probe for web ports
                if port in (80, 8080, 8000, 8008, 8888):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + self.target.hostname.encode() + b"\r\n\r\n")
                else:
                    s.sendall(b"\r\n")
                banner = s.recv(1024).decode(errors="replace").strip()
                return banner[:200]  # cap length
        except Exception:
            return ""

    def _enrich(self, port: int) -> dict:
        service = COMMON_SERVICES.get(port, "unknown")
        banner = self._grab_banner(port)
        return {
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner,
        }
