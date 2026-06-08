"""Safe HTTP and TLS configuration analysis for ReconForge."""

import http.client
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from reconforge.core.logging import get_logger
from reconforge.core.models import HTTPAnalysisResult, TLSCertificateInfo

logger = get_logger(__name__)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


class HTTPAnalyzer:
    """Collect passive HTTP headers, redirects, and TLS certificate metadata."""

    def __init__(self, timeout: float = 2.0, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects

    @staticmethod
    def _format_name(name_parts: object) -> Optional[str]:
        """Format subject/issuer tuples returned by ssl.getpeercert()."""
        if not name_parts:
            return None

        formatted: List[str] = []
        for group in name_parts:
            for key, value in group:
                formatted.append(f"{key}={value}")
        return ", ".join(formatted) if formatted else None

    @staticmethod
    def _extract_sans(cert: Dict[str, object]) -> List[str]:
        sans = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type.lower() == "dns":
                sans.append(str(san_value))
        return sans

    def inspect_tls_certificate(self, host: str, port: int) -> TLSCertificateInfo:
        """Inspect TLS certificate metadata without sending application data."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
        except Exception as e:
            logger.debug(f"TLS certificate inspection failed for {host}:{port}: {e}")
            return TLSCertificateInfo(error=str(e))

        return TLSCertificateInfo(
            subject=self._format_name(cert.get("subject")),
            issuer=self._format_name(cert.get("issuer")),
            not_before=cert.get("notBefore"),
            not_after=cert.get("notAfter"),
            sans=self._extract_sans(cert),
        )

    def _request_once(
        self,
        host: str,
        port: int,
        https: bool,
        path: str,
    ) -> Tuple[int, Dict[str, str], Optional[str]]:
        connection_cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
        kwargs = {"timeout": self.timeout}
        if https:
            kwargs["context"] = ssl._create_unverified_context()

        conn = connection_cls(host, port, **kwargs)
        try:
            conn.request("HEAD", path, headers={"Host": host, "User-Agent": "ReconForge/0.1"})
            response = conn.getresponse()
            headers = {key: value for key, value in response.getheaders()}
            location = headers.get("Location")
            return response.status, headers, location
        finally:
            conn.close()

    def analyze(self, host: str, port: int = 443, https: bool = True) -> HTTPAnalysisResult:
        """Analyze HTTP/TLS configuration with HEAD requests only."""
        requested_https = https
        scheme = "https" if https else "http"
        current_host = host
        current_port = port
        current_path = "/"
        redirects: List[str] = []
        headers: Dict[str, str] = {}
        status_code: Optional[int] = None
        error: Optional[str] = None

        for _ in range(self.max_redirects + 1):
            try:
                status_code, headers, location = self._request_once(
                    current_host,
                    current_port,
                    https,
                    current_path,
                )
            except Exception as e:
                logger.debug(f"HTTP analysis failed for {current_host}:{current_port}: {e}")
                error = str(e)
                break

            if status_code not in {301, 302, 303, 307, 308} or not location:
                break

            redirects.append(location)
            parsed = urlparse(urljoin(f"{scheme}://{current_host}:{current_port}{current_path}", location))
            if parsed.scheme not in {"http", "https"}:
                break

            https = parsed.scheme == "https"
            scheme = parsed.scheme
            current_host = parsed.hostname or current_host
            current_port = parsed.port or (443 if https else 80)
            current_path = parsed.path or "/"
            if parsed.query:
                current_path = f"{current_path}?{parsed.query}"

        security_headers = {name: headers.get(name) for name in SECURITY_HEADERS}
        tls_certificate = self.inspect_tls_certificate(host, port) if requested_https else None

        return HTTPAnalysisResult(
            target=host,
            port=port,
            scheme=scheme,
            status_code=status_code,
            server_header=headers.get("Server"),
            security_headers=security_headers,
            redirects=redirects,
            tls_certificate=tls_certificate,
            error=error,
        )
