"""Informational risk tagging for observed ReconForge metadata."""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

MEDIUM_PORTS = {
    21: "FTP service exposed",
    22: "SSH service exposed",
    23: "Telnet service exposed",
    3306: "MySQL service exposed",
    3389: "RDP service exposed",
    5432: "PostgreSQL service exposed",
    5900: "VNC service exposed",
    6379: "Redis service exposed",
    9200: "Elasticsearch service exposed",
    27017: "MongoDB service exposed",
}


def _risk_tag(
    tag_id: str,
    severity: str,
    title: str,
    description: str,
    target: str,
    evidence: Optional[str] = None,
) -> dict:
    return {
        "id": tag_id,
        "severity": severity,
        "title": title,
        "description": description,
        "target": target,
        "evidence": evidence,
    }


def _port_number(port: Any) -> Optional[int]:
    if isinstance(port, int):
        return port
    if isinstance(port, dict):
        value = port.get("port") or port.get("number") or port.get("id")
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return None


def _port_service(port: Any) -> Optional[str]:
    if isinstance(port, dict):
        service = port.get("service") or port.get("name")
        return str(service) if service else None
    return None


def _port_banner(port: Any) -> Optional[str]:
    if not isinstance(port, dict):
        return None
    banner = port.get("banner")
    if isinstance(banner, dict):
        banner = banner.get("banner") or banner.get("raw") or banner.get("text")
    return str(banner) if banner else None


def _open_ports_from_result(result_type: str, data: dict) -> List[Any]:
    if result_type == "ports":
        return data.get("open_ports", []) or []

    if result_type == "scan":
        ports = []
        for host in data.get("hosts", []) or []:
            if not isinstance(host, dict):
                continue
            ports.extend(host.get("open_ports") or host.get("ports") or [])
        return ports

    return []


def _classify_open_ports(result_type: str, target: str, data: dict) -> List[dict]:
    tags = []
    seen = set()

    for port in _open_ports_from_result(result_type, data):
        number = _port_number(port)
        if number is None or number in seen:
            continue
        seen.add(number)

        service = _port_service(port)
        evidence = f"{number}/{service}" if service else str(number)

        if number == 23:
            tags.append(
                _risk_tag(
                    "telnet-open",
                    "high",
                    "Telnet service observed",
                    "Telnet is a clear-text administrative protocol. Verify this is expected on authorized systems.",
                    target,
                    evidence,
                )
            )
        elif number in MEDIUM_PORTS:
            tags.append(
                _risk_tag(
                    f"open-port-{number}",
                    "medium",
                    MEDIUM_PORTS[number],
                    "A sensitive or administrative TCP service was observed open.",
                    target,
                    evidence,
                )
            )
        else:
            tags.append(
                _risk_tag(
                    f"open-port-{number}",
                    "low",
                    "Open TCP port observed",
                    "An open TCP port was observed during authorized reconnaissance.",
                    target,
                    evidence,
                )
            )

    return tags


def _classify_banners(result_type: str, target: str, data: dict) -> List[dict]:
    tags = []
    ports = data.get("ports", []) if result_type == "banner" else _open_ports_from_result(result_type, data)

    for port in ports or []:
        banner = _port_banner(port)
        if not banner:
            continue
        number = _port_number(port)
        tags.append(
            _risk_tag(
                "banner-disclosure",
                "low",
                "Service banner observed",
                "A service disclosed banner metadata. Review whether version disclosure is acceptable.",
                target,
                f"{number or '-'}: {banner[:120]}",
            )
        )

    return tags


def _parse_cert_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _classify_http(target: str, data: dict) -> List[dict]:
    tags = []
    headers: Dict[str, Optional[str]] = data.get("security_headers") or {}
    missing = [name for name in SECURITY_HEADERS if not headers.get(name)]

    if missing:
        severity = "medium" if any(
            name in missing for name in ["Strict-Transport-Security", "Content-Security-Policy"]
        ) else "low"
        tags.append(
            _risk_tag(
                "missing-http-security-headers",
                severity,
                "HTTP security headers missing",
                "One or more common defensive HTTP security headers were not observed.",
                target,
                ", ".join(missing),
            )
        )

    if data.get("server_header"):
        tags.append(
            _risk_tag(
                "server-header-disclosure",
                "low",
                "Server header observed",
                "The service disclosed server metadata in the HTTP Server header.",
                target,
                str(data.get("server_header"))[:120],
            )
        )

    cert = data.get("tls_certificate") or {}
    not_after = _parse_cert_time(cert.get("not_after") or cert.get("notAfter"))
    if not_after:
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days
        if days_remaining < 0:
            tags.append(
                _risk_tag(
                    "tls-certificate-expired",
                    "high",
                    "TLS certificate expired",
                    "The observed TLS certificate is past its not_after date.",
                    target,
                    str(cert.get("not_after") or cert.get("notAfter")),
                )
            )
        elif days_remaining <= 30:
            tags.append(
                _risk_tag(
                    "tls-certificate-expiring-soon",
                    "medium",
                    "TLS certificate expiring soon",
                    "The observed TLS certificate expires within 30 days.",
                    target,
                    str(cert.get("not_after") or cert.get("notAfter")),
                )
            )

    return tags


def classify_result(result_type: str, target: str, data: dict) -> List[dict]:
    """Classify observed metadata into low/medium/high informational tags."""
    tags = []
    tags.extend(_classify_open_ports(result_type, target, data))
    tags.extend(_classify_banners(result_type, target, data))

    if result_type == "http":
        tags.extend(_classify_http(target, data))

    return tags
