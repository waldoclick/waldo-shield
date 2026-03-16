"""
Module: Port Scanner
Scans common ports and identifies potentially risky open services.
"""

import socket
import concurrent.futures
from urllib.parse import urlparse


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    27017: "MongoDB",
}

RISKY_PORTS = {
    21: "FTP transmits credentials in plaintext. Use SFTP or FTPS instead.",
    23: "Telnet transmits data in plaintext. Use SSH instead.",
    25: "SMTP port open to public. May be used for spam if misconfigured.",
    110: "POP3 may transmit credentials in plaintext. Use POP3S (995) instead.",
    143: "IMAP may transmit credentials in plaintext. Use IMAPS (993) instead.",
    445: "SMB port exposed. High risk for ransomware (EternalBlue/WannaCry). Should not be internet-facing.",
    3306: "MySQL port exposed to internet. Should be restricted to localhost or trusted IPs.",
    3389: "RDP exposed to internet. High risk for brute-force and ransomware attacks.",
    5432: "PostgreSQL port exposed to internet. Should be restricted to localhost or trusted IPs.",
    5900: "VNC exposed. High risk for unauthorized remote access.",
    6379: "Redis exposed without authentication by default. Critical risk.",
    27017: "MongoDB exposed. Many instances have no authentication enabled.",
}


def _check_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def analyze(url: str, timeout: float = 1.5) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or url

    result = {
        "module": "port_scan",
        "url": url,
        "host": hostname,
        "open_ports": [],
        "risky_open_ports": [],
        "issues": [],
        "error": None,
    }

    try:
        ip = socket.gethostbyname(hostname)
        result["resolved_ip"] = ip
    except socket.gaierror as e:
        result["error"] = f"Could not resolve hostname: {e}"
        return result

    def scan_port(port: int):
        if _check_port(ip, port, timeout):
            return port
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port = future.result()
            if port is not None:
                service = COMMON_PORTS.get(port, "Unknown")
                entry = {"port": port, "service": service}
                result["open_ports"].append(entry)

                if port in RISKY_PORTS:
                    risky_entry = {**entry, "risk": RISKY_PORTS[port]}
                    result["risky_open_ports"].append(risky_entry)
                    result["issues"].append({
                        "severity": "high" if port in {23, 445, 3389, 6379} else "medium",
                        "message": f"Risky port {port} ({service}) is open.",
                        "recommendation": RISKY_PORTS[port],
                    })

    # Sort results by port number
    result["open_ports"].sort(key=lambda x: x["port"])
    result["risky_open_ports"].sort(key=lambda x: x["port"])

    return result
