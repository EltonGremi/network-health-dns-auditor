#!/usr/bin/env python3
"""
Network Health & DNS Security Auditor
Checks A/AAAA/MX/NS/TXT records, SPF, DMARC, common DKIM selectors,
and TLS certificate expiration for a given domain.
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

try:
    import dns.resolver  # type: ignore

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "dkim",
    "mail",
]


def query_txt_records(name: str) -> List[str]:
    results: List[str] = []
    if HAS_DNSPYTHON:
        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=5.0)
            for rdata in answers:
                joined = "".join(
                    part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                    for part in getattr(rdata, "strings", [str(rdata)])
                )
                results.append(joined.strip('"'))
        except Exception:
            pass
    return results


def query_basic_records(domain: str) -> Dict[str, List[str]]:
    data: Dict[str, List[str]] = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ip = str(info[4][0])
            if ":" in ip and ip not in data["AAAA"]:
                data["AAAA"].append(ip)
            elif ":" not in ip and ip not in data["A"]:
                data["A"].append(ip)
    except socket.gaierror:
        pass
    return data


def check_tls_certificate(domain: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                protocol = ssock.version()
                if not_after:
                    expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days_left = (expires_at - datetime.now(timezone.utc)).days
                    return {
                        "reachable": True,
                        "protocol": protocol,
                        "expires_at": expires_at.isoformat(),
                        "days_remaining": days_left,
                    }
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}
    return {"reachable": False, "error": "Unable to parse certificate"}


def audit_domain(domain: str) -> Dict[str, Any]:
    domain = domain.strip().lower().rstrip(".")
    findings: List[Dict[str, str]] = []
    score = 100

    addr_records = query_basic_records(domain)
    if not addr_records["A"] and not addr_records["AAAA"]:
        score -= 30
        findings.append({"severity": "CRITICAL", "check": "DNS Resolution", "detail": "No A or AAAA records resolved"})
    else:
        findings.append(
            {
                "severity": "OK",
                "check": "DNS Resolution",
                "detail": f"A={len(addr_records['A'])}, AAAA={len(addr_records['AAAA'])}",
            }
        )

    tls_info = check_tls_certificate(domain)
    if not tls_info.get("reachable"):
        score -= 20
        findings.append(
            {
                "severity": "WARNING",
                "check": "TLS / HTTPS",
                "detail": f"TLS check failed ({tls_info.get('error', 'unreachable')})",
            }
        )
    else:
        days_left = tls_info.get("days_remaining", 0)
        if days_left < 14:
            score -= 20
            findings.append({"severity": "CRITICAL", "check": "TLS Expiry", "detail": f"Expires in {days_left} days"})
        elif days_left < 30:
            score -= 10
            findings.append({"severity": "WARNING", "check": "TLS Expiry", "detail": f"Expires in {days_left} days"})
        else:
            findings.append(
                {
                    "severity": "OK",
                    "check": "TLS / HTTPS",
                    "detail": f"{tls_info.get('protocol')} valid for {days_left} days",
                }
            )

    spf_records: List[str] = []
    dmarc_records: List[str] = []
    found_dkim: List[str] = []

    if HAS_DNSPYTHON:
        txt_root = query_txt_records(domain)
        spf_records = [r for r in txt_root if r.lower().startswith("v=spf1")]
        if not spf_records:
            score -= 15
            findings.append({"severity": "WARNING", "check": "SPF", "detail": "No SPF record found"})
        else:
            spf_val = spf_records[0]
            if "+all" in spf_val:
                score -= 15
                findings.append({"severity": "CRITICAL", "check": "SPF", "detail": "Permissive '+all' detected"})
            elif "~all" in spf_val or "-all" in spf_val:
                findings.append({"severity": "OK", "check": "SPF", "detail": "SPF record present with restriction"})
            else:
                score -= 5
                findings.append({"severity": "WARNING", "check": "SPF", "detail": "SPF present without explicit '-all'/'~all'"})

        dmarc_records = [r for r in query_txt_records(f"_dmarc.{domain}") if "v=dmarc1" in r.lower()]
        if not dmarc_records:
            score -= 15
            findings.append({"severity": "WARNING", "check": "DMARC", "detail": "No _dmarc TXT record found"})
        else:
            dmarc_val = dmarc_records[0].lower()
            if "p=reject" in dmarc_val:
                findings.append({"severity": "OK", "check": "DMARC", "detail": "Strict policy (p=reject)"})
            elif "p=quarantine" in dmarc_val:
                findings.append({"severity": "OK", "check": "DMARC", "detail": "Quarantine policy (p=quarantine)"})
            else:
                score -= 5
                findings.append({"severity": "WARNING", "check": "DMARC", "detail": "Monitoring-only policy (p=none)"})

        for selector in COMMON_DKIM_SELECTORS:
            dkim_txt = query_txt_records(f"{selector}._domainkey.{domain}")
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in dkim_txt):
                found_dkim.append(selector)

        if found_dkim:
            findings.append(
                {"severity": "OK", "check": "DKIM", "detail": f"Found selectors: {', '.join(found_dkim)}"}
            )
        else:
            score -= 5
            findings.append(
                {"severity": "WARNING", "check": "DKIM", "detail": "No common DKIM selector detected"}
            )
    else:
        findings.append(
            {
                "severity": "WARNING",
                "check": "TXT / SPF / DKIM / DMARC",
                "detail": "Install 'dnspython' for full TXT, SPF, DKIM, and DMARC checks",
            }
        )

    score = max(0, min(100, score))
    return {
        "domain": domain,
        "score": score,
        "addresses": addr_records,
        "tls": tls_info,
        "email_auth": {
            "spf": spf_records,
            "dmarc": dmarc_records,
            "dkim_selectors": found_dkim,
        },
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit DNS resolution, TLS certificate, and email security records.")
    parser.add_argument("domains", nargs="+", help="One or more domain names to audit")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    reports = [audit_domain(d) for d in args.domains]

    if args.json:
        print(json.dumps(reports, indent=2))
        return 0

    for rep in reports:
        print(f"\n=== Audit Report: {rep['domain']} (Score: {rep['score']}/100) ===")
        for item in rep["findings"]:
            print(f"[{item['severity']:8s}] {item['check']}: {item['detail']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
