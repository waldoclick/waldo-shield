"""
Module: SSL/TLS Analysis
Analyzes certificate validity, TLS version, cipher suites and known weaknesses.
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse


WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS_KEYWORDS = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]


def _check_weak_cipher(cipher_name: str) -> bool:
    return any(kw.upper() in cipher_name.upper() for kw in WEAK_CIPHERS_KEYWORDS)


def analyze(url: str) -> dict:
    result = {
        "module": "ssl_tls",
        "url": url,
        "enabled": False,
        "certificate": {},
        "protocol": None,
        "cipher": None,
        "days_until_expiry": None,
        "issues": [],
        "error": None,
    }

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        result["issues"].append({
            "severity": "critical",
            "message": "URL does not use HTTPS. SSL/TLS analysis skipped.",
            "recommendation": "Migrate to HTTPS immediately.",
        })
        result["error"] = "Not an HTTPS URL."
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["enabled"] = True

                # Protocol version
                protocol = ssock.version()
                result["protocol"] = protocol

                if protocol in WEAK_PROTOCOLS:
                    result["issues"].append({
                        "severity": "critical",
                        "message": f"Weak TLS protocol in use: {protocol}",
                        "recommendation": "Disable TLS 1.0 and 1.1. Use TLS 1.2 or TLS 1.3 only.",
                    })

                # Cipher suite
                cipher = ssock.cipher()
                if cipher:
                    cipher_name, tls_version, key_bits = cipher
                    result["cipher"] = {
                        "name": cipher_name,
                        "protocol": tls_version,
                        "bits": key_bits,
                    }
                    if _check_weak_cipher(cipher_name):
                        result["issues"].append({
                            "severity": "high",
                            "message": f"Weak cipher suite in use: {cipher_name}",
                            "recommendation": "Disable weak cipher suites (RC4, DES, 3DES, MD5, NULL, EXPORT).",
                        })
                    if key_bits and key_bits < 128:
                        result["issues"].append({
                            "severity": "high",
                            "message": f"Cipher key length too short: {key_bits} bits",
                            "recommendation": "Use cipher suites with at least 128-bit keys.",
                        })

                # Certificate
                cert = ssock.getpeercert()
                if cert:
                    raw_subject = cert.get("subject", ())
                    raw_issuer = cert.get("issuer", ())
                    subject: dict = {}
                    for rdn in raw_subject:
                        for attr in rdn:
                            if isinstance(attr, (list, tuple)) and len(attr) == 2:
                                subject[str(attr[0])] = str(attr[1])
                    issuer: dict = {}
                    for rdn in raw_issuer:
                        for attr in rdn:
                            if isinstance(attr, (list, tuple)) and len(attr) == 2:
                                issuer[str(attr[0])] = str(attr[1])

                    not_after = cert.get("notAfter")
                    not_before = cert.get("notBefore")
                    san = cert.get("subjectAltName", ())

                    san_list = []
                    for entry in san:
                        if isinstance(entry, (list, tuple)) and len(entry) == 2:
                            san_list.append(str(entry[1]))

                    result["certificate"] = {
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": str(not_before) if not_before else None,
                        "not_after": str(not_after) if not_after else None,
                        "subject_alt_names": san_list,
                        "serial_number": cert.get("serialNumber"),
                        "version": cert.get("version"),
                    }

                    # Expiry check
                    if not_after and isinstance(not_after, str):
                        expiry_date = datetime.datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        now = datetime.datetime.utcnow()
                        days_left = (expiry_date - now).days
                        result["days_until_expiry"] = days_left

                        if days_left < 0:
                            result["issues"].append({
                                "severity": "critical",
                                "message": f"SSL certificate has EXPIRED {abs(days_left)} days ago.",
                                "recommendation": "Renew the SSL certificate immediately.",
                            })
                        elif days_left < 14:
                            result["issues"].append({
                                "severity": "critical",
                                "message": f"SSL certificate expires in {days_left} days.",
                                "recommendation": "Renew the SSL certificate urgently.",
                            })
                        elif days_left < 30:
                            result["issues"].append({
                                "severity": "high",
                                "message": f"SSL certificate expires in {days_left} days.",
                                "recommendation": "Plan certificate renewal soon.",
                            })
                        elif days_left < 90:
                            result["issues"].append({
                                "severity": "medium",
                                "message": f"SSL certificate expires in {days_left} days.",
                                "recommendation": "Schedule certificate renewal.",
                            })

                    # Hostname validation
                    hostname_lower = hostname.lower() if hostname else ""
                    san_names = [n.lower() for n in san_list]
                    matched = any(
                        hostname_lower == name or
                        (name.startswith("*.") and hostname_lower.endswith(name[1:]))
                        for name in san_names
                    )
                    cn = subject.get("commonName", "")
                    if not matched and hostname_lower != cn.lower():
                        result["issues"].append({
                            "severity": "high",
                            "message": f"Certificate hostname mismatch: cert is not valid for '{hostname}'.",
                            "recommendation": "Obtain a certificate valid for this hostname.",
                        })

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {str(e)}"
        result["issues"].append({
            "severity": "critical",
            "message": f"Certificate verification error: {str(e)}",
            "recommendation": "Ensure the certificate is valid, trusted, and not self-signed.",
        })
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {str(e)}"
        result["issues"].append({
            "severity": "critical",
            "message": f"SSL/TLS error: {str(e)}",
            "recommendation": "Review the SSL/TLS configuration of the server.",
        })
    except socket.timeout:
        result["error"] = "Connection timed out."
    except Exception as e:
        result["error"] = str(e)

    return result
