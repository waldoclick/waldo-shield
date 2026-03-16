# waldo-shield

Vulnerability assessment tool for the waldo.click platform.

Scans `waldoclick.dev` (staging) and `waldo.click` (prod) for security issues across HTTP headers, SSL/TLS, DNS, open ports, technology fingerprinting, and common vulnerabilities.

## Structure

```
waldo-shield/
├── src/
│   ├── scanner.py        # Main entry point
│   ├── requirements.txt  # Python dependencies
│   └── modules/
│       ├── headers.py         # HTTP security headers
│       ├── ssl_tls.py         # SSL/TLS analysis
│       ├── dns_analysis.py    # DNS records (SPF, DMARC, CAA, DNSSEC)
│       ├── port_scan.py       # Open port detection
│       ├── tech_detection.py  # Technology fingerprinting
│       └── vulnerabilities.py # Common vulnerability checks
├── reports/              # Scan output (gitignored)
└── SECURITY_PROGRESS.md  # Remediation log
```

## Usage

```bash
pip install -r src/requirements.txt

# Scan all modules
python src/scanner.py https://api.waldoclick.dev

# Scan specific modules
python src/scanner.py https://api.waldoclick.dev --modules headers,ssl,dns

# Custom output file
python src/scanner.py https://api.waldoclick.dev --output reports/my_report.json
```

## Modules

| Module | Flag | Description |
|--------|------|-------------|
| HTTP Headers | `headers` | Checks security headers (CSP, HSTS, CORP, etc.) |
| SSL/TLS | `ssl` | Certificate validity, expiry, protocol versions |
| DNS | `dns` | SPF, DMARC, CAA, DNSSEC |
| Port Scan | `ports` | Detects unexpected open ports |
| Technologies | `tech` | Fingerprints frameworks, admin panels |
| Vulnerabilities | `vulns` | Exposed files, open redirects, sensitive paths |

## Targets

| Environment | URLs |
|-------------|------|
| Staging | `api.waldoclick.dev` · `dashboard.waldoclick.dev` · `www.waldoclick.dev` |
| Prod | `api.waldo.click` · `dashboard.waldo.click` · `www.waldo.click` |
