# Network Health & DNS Security Auditor

A lightweight command-line utility written in Python to inspect basic DNS resolution, TLS/HTTPS certificate validity, and email authentication posture (`SPF`, `DKIM`, `DMARC`) across one or more domains.

## Key Features
- **DNS Resolution Check:** Verifies IPv4 (`A`) and IPv6 (`AAAA`) reachability.
- **TLS Certificate Inspection:** Checks HTTPS connectivity, negotiated TLS protocol version, and days remaining before certificate expiration.
- **Email Authentication Audit:** Evaluates `SPF`, `DMARC` policy strength (`none`, `quarantine`, `reject`), and common `DKIM` selectors (when `dnspython` is installed).
- **JSON & CLI Reporting:** Supports human-readable terminal output or structured JSON for automation pipelines.

## Usage

### Basic run (standard library only)
```bash
python3 dns_auditor.py example.com
```
### Full DNS & email security checks (with dnspython)
```bash
pip install dnspython
python3 dns_auditor.py example.com example.org --json
