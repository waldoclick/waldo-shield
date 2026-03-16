"""
Module: DNS Security Analysis
Checks DNS records, SPF, DMARC, DKIM hints, DNSSEC and zone transfer vulnerability.
"""

import socket
import dns.resolver
import dns.query
import dns.zone
import dns.exception
from urllib.parse import urlparse


def _query(domain: str, record_type: str):
    try:
        answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
        return [rdata.to_text() for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.DNSException):
        return []


def _check_spf(domain: str) -> dict:
    txt_records = _query(domain, "TXT")
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
    result = {
        "present": bool(spf_records),
        "records": spf_records,
        "issues": [],
    }
    if not spf_records:
        result["issues"].append({
            "severity": "medium",
            "message": "No SPF record found.",
            "recommendation": "Add an SPF TXT record to prevent email spoofing. Example: v=spf1 include:_spf.google.com ~all",
        })
    elif len(spf_records) > 1:
        result["issues"].append({
            "severity": "high",
            "message": "Multiple SPF records found. Only one is allowed.",
            "recommendation": "Merge all SPF records into a single TXT record.",
        })
    else:
        spf = spf_records[0]
        if "+all" in spf:
            result["issues"].append({
                "severity": "critical",
                "message": "SPF record uses '+all' which allows any server to send email on behalf of the domain.",
                "recommendation": "Use '~all' (soft fail) or '-all' (hard fail) instead of '+all'.",
            })
    return result


def _check_dmarc(domain: str) -> dict:
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = _query(dmarc_domain, "TXT")
    dmarc_records = [r for r in txt_records if "v=dmarc1" in r.lower()]
    result = {
        "present": bool(dmarc_records),
        "records": dmarc_records,
        "issues": [],
    }
    if not dmarc_records:
        result["issues"].append({
            "severity": "medium",
            "message": "No DMARC record found.",
            "recommendation": "Add a DMARC TXT record at _dmarc.<domain>. Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
        })
    else:
        dmarc = dmarc_records[0].lower()
        if "p=none" in dmarc:
            result["issues"].append({
                "severity": "medium",
                "message": "DMARC policy is set to 'none' (monitoring only, no enforcement).",
                "recommendation": "Change DMARC policy to 'quarantine' or 'reject' after reviewing reports.",
            })
    return result


def _check_zone_transfer(domain: str, nameservers: list) -> dict:
    result = {
        "vulnerable": False,
        "vulnerable_ns": [],
        "issues": [],
    }
    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns.rstrip("."))
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            if zone:
                result["vulnerable"] = True
                result["vulnerable_ns"].append(ns)
        except Exception:
            pass

    if result["vulnerable"]:
        result["issues"].append({
            "severity": "critical",
            "message": f"DNS zone transfer (AXFR) is allowed on: {', '.join(result['vulnerable_ns'])}",
            "recommendation": "Restrict zone transfers to authorized secondary DNS servers only.",
        })
    return result


def _check_dnssec(domain: str) -> dict:
    result = {
        "enabled": False,
        "issues": [],
    }
    try:
        answers = dns.resolver.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        if answers:
            result["enabled"] = True
    except Exception:
        pass

    if not result["enabled"]:
        result["issues"].append({
            "severity": "low",
            "message": "DNSSEC is not enabled.",
            "recommendation": "Enable DNSSEC to protect against DNS spoofing and cache poisoning attacks.",
        })
    return result


def analyze(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.hostname or url

    # Strip www for apex domain checks
    apex_domain = domain
    if apex_domain.startswith("www."):
        apex_domain = apex_domain[4:]

    result = {
        "module": "dns_analysis",
        "url": url,
        "domain": domain,
        "apex_domain": apex_domain,
        "records": {},
        "spf": {},
        "dmarc": {},
        "dnssec": {},
        "zone_transfer": {},
        "nameservers": [],
        "issues": [],
        "error": None,
    }

    try:
        # A / AAAA records
        result["records"]["A"] = _query(domain, "A")
        result["records"]["AAAA"] = _query(domain, "AAAA")

        if not result["records"]["A"] and not result["records"]["AAAA"]:
            result["issues"].append({
                "severity": "high",
                "message": "No A or AAAA records found for the domain.",
                "recommendation": "Verify DNS configuration.",
            })

        # MX records
        result["records"]["MX"] = _query(apex_domain, "MX")

        # NS records
        ns_records = _query(apex_domain, "NS")
        result["records"]["NS"] = ns_records
        result["nameservers"] = [ns.rstrip(".") for ns in ns_records]

        # TXT records
        result["records"]["TXT"] = _query(apex_domain, "TXT")

        # CAA records (Certificate Authority Authorization)
        caa_records = _query(apex_domain, "CAA")
        result["records"]["CAA"] = caa_records
        if not caa_records:
            result["issues"].append({
                "severity": "low",
                "message": "No CAA records found.",
                "recommendation": "Add CAA records to specify which CAs are authorized to issue certificates for your domain.",
            })

        # SPF
        spf = _check_spf(apex_domain)
        result["spf"] = spf
        result["issues"].extend(spf["issues"])

        # DMARC
        dmarc = _check_dmarc(apex_domain)
        result["dmarc"] = dmarc
        result["issues"].extend(dmarc["issues"])

        # DNSSEC
        dnssec = _check_dnssec(apex_domain)
        result["dnssec"] = dnssec
        result["issues"].extend(dnssec["issues"])

        # Zone transfer
        if result["nameservers"]:
            zt = _check_zone_transfer(apex_domain, result["nameservers"])
            result["zone_transfer"] = zt
            result["issues"].extend(zt["issues"])

    except Exception as e:
        result["error"] = str(e)

    return result
