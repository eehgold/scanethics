# scanethics

> White-hat reconnaissance & vulnerability scanning framework — pure Python, no external tools required.

Built as part of a cybersecurity studies project. The goal is simple: provide a **target IP or URL** and get a structured, intelligent report of potential attack surfaces.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**.
Scanning systems without explicit written permission is **illegal** and unethical.
By using this tool, you confirm that you have authorization to test the target.

---

## Features

| Scanner | Method | What it finds |
|---|---|---|
| **Port Scanner** | `socket` TCP | Open ports, service banners |
| **Directory Fuzzer** | `requests` | `/admin`, `.env`, `.git`, hidden pages |
| **Web Vuln Scanner** | `requests` | Missing headers, CORS, cookies, error leaks |
| **Subdomain Scanner** | DNS + crt.sh | Subdomains via brute-force & CT logs |
| **Intelligent Analyzer** | Post-scan | Filters false positives, detects wildcard DNS, maps CVEs |

### Analyzer highlights

- Detects **wildcard DNS** and separates real subdomains from noise
- Maps open ports to **known dangerous services** with CVE notes (Webmin, Redis, MongoDB, Docker API, ActiveMQ…)
- Detects **HTTP→HTTPS redirect floods** in dir-fuzzer results (false positives)
- Produces a **risk score** (CRITICAL / HIGH / MEDIUM / LOW) with **actionable recommendations**
- Everything is **pure Python** — no nmap, gobuster, nikto or other system tools needed

---

## Installation

```bash
git clone https://github.com/<your-username>/scanethics.git
cd scanethics
pip install -r requirements.txt
```

**Requirements:** Python 3.10+

Dependencies (all installable via pip):
- [`rich`](https://github.com/Textualize/rich) — terminal output
- [`requests`](https://docs.python-requests.org/) — HTTP scanning
- [`dnspython`](https://www.dnspython.org/) — DNS resolution

---

## Usage

```bash
# Full scan (all modules)
python main.py example.com

# Scan a specific IP
python main.py 192.168.1.1

# Force HTTPS target (recommended after an initial HTTP scan)
python main.py https://example.com

# Run only specific scanners
python main.py example.com --only ports web

# Skip a scanner
python main.py example.com --skip subdomains

# Custom port list
python main.py example.com --ports 80,443,8080,8443,10000

# Custom thread count and timeout
python main.py example.com --threads 100 --timeout 3

# Custom wordlist for directory fuzzing
python main.py example.com --wordlist /path/to/wordlist.txt

# Disable crt.sh lookup (offline mode)
python main.py example.com --no-crtsh

# Skip disclaimer prompt (for scripting)
python main.py example.com -y

# Save report to a specific file
python main.py example.com --output /tmp/report.json
```

---

## Output

### Real-time terminal output

Color-coded findings are printed live as each scanner runs.

```
[*] Target   : http://example.com
[*] Resolved : 93.184.216.34

──────────────── PORT SCANNER ────────────────
[+] Port 80/tcp OPEN
[+] Port 443/tcp OPEN
[+] Port 10000/tcp OPEN
...

══ ANALYSE INTELLIGENTE DES RÉSULTATS ══

╔══════════════════ RISQUE CRITIQUE ═════════════════╗
║  Cible : http://example.com                        ║
║  Findings réels : 5   CRITICAL:1  HIGH:2  MEDIUM:2 ║
╚════════════════════════════════════════════════════╝

┌──────────┬──────────┬────────────────────────┬──────────────────────────┐
│  Sév.    │ Catégorie│ Finding                │ Action recommandée       │
├──────────┼──────────┼────────────────────────┼──────────────────────────┤
│ CRITICAL │ Port     │ Port 10000 — Webmin    │ CVE-2019-15107 RCE …     │
│ HIGH     │ WebVuln  │ Missing HSTS           │ Ajouter le header …      │
│ MEDIUM   │ WebVuln  │ Missing CSP            │ Définir une CSP …        │
└──────────┴──────────┴────────────────────────┴──────────────────────────┘

── Faux positifs filtrés ──
• HTTP → HTTPS redirect flood — Relancer sur https://
• No HTTPS (false positive) — Port 443 ouvert
```

### JSON report

Each scan automatically saves a structured JSON report to `reports/`:

```
reports/
  example_com_20260218_194717.json
```

The JSON contains:
- `analysis` — intelligent findings, risk score, wildcard DNS status
- `raw_results` — raw scanner output for each module

---

## Architecture

```
scanethics/
├── main.py                          # CLI entry point
├── requirements.txt
├── core/
│   ├── target.py                    # Parse & validate IP or URL
│   ├── reporter.py                  # Rich terminal output
│   ├── base_scanner.py              # Abstract base class for scanners
│   └── analyzer.py                  # Post-scan intelligence engine
├── scanners/
│   ├── port_scanner/scanner.py      # TCP port + banner grabbing
│   ├── dir_fuzzer/
│   │   ├── scanner.py               # HTTP path brute-force
│   │   └── wordlists/common.txt     # ~150 high-value paths
│   ├── web_vuln/scanner.py          # HTTP header & config checks
│   └── subdomain/scanner.py         # DNS brute-force + crt.sh CT logs
└── reports/                         # Auto-generated JSON reports
```

### Adding a new scanner

1. Create `scanners/my_scanner/scanner.py`
2. Inherit from `BaseScanner` and implement `run() -> dict`
3. Register it in the `SCANNERS` dict in `main.py`

```python
from core.base_scanner import BaseScanner

class MyScanner(BaseScanner):
    name = "My Scanner"
    description = "What it does"

    def run(self) -> dict:
        findings = []
        # ... your logic
        return self._result(findings)
```

---

## Roadmap

- [ ] SSL/TLS certificate analysis (expiry, weak ciphers, misconfigured SANs)
- [ ] WAF detection
- [ ] CMS fingerprinting (WordPress, Drupal, Joomla version detection)
- [ ] HTTP parameter fuzzing (basic SQLi / XSS probes)
- [ ] HTML report export

---

## License

MIT — free to use, study and modify.
