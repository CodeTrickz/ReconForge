"""Unit tests for safe HTTP/TLS analysis."""

from reconforge.core.models import TLSCertificateInfo
from reconforge.recon.http_analysis import HTTPAnalyzer


def test_http_analyzer_collects_headers_and_tls(monkeypatch):
    analyzer = HTTPAnalyzer(timeout=1.0)

    def fake_request_once(host, port, https, path):
        assert host == "example.com"
        assert port == 443
        assert https is True
        assert path == "/"
        return 200, {
            "Server": "unit-test",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
        }, None

    monkeypatch.setattr(analyzer, "_request_once", fake_request_once)
    monkeypatch.setattr(
        analyzer,
        "inspect_tls_certificate",
        lambda host, port: TLSCertificateInfo(
            subject="commonName=example.com",
            issuer="commonName=Example CA",
            not_before="Jan 1 00:00:00 2026 GMT",
            not_after="Jan 1 00:00:00 2027 GMT",
            sans=["example.com", "www.example.com"],
        ),
    )

    result = analyzer.analyze("example.com", port=443, https=True)

    assert result.status_code == 200
    assert result.server_header == "unit-test"
    assert result.security_headers["Strict-Transport-Security"] == "max-age=31536000"
    assert result.security_headers["Content-Security-Policy"] is None
    assert result.tls_certificate is not None
    assert result.tls_certificate.sans == ["example.com", "www.example.com"]


def test_http_analyzer_records_redirects(monkeypatch):
    analyzer = HTTPAnalyzer(timeout=1.0)
    calls = []

    def fake_request_once(host, port, https, path):
        calls.append((host, port, https, path))
        if len(calls) == 1:
            return 301, {"Location": "https://example.com/login"}, "https://example.com/login"
        return 200, {"Server": "unit-test"}, None

    monkeypatch.setattr(analyzer, "_request_once", fake_request_once)
    monkeypatch.setattr(analyzer, "inspect_tls_certificate", lambda host, port: None)

    result = analyzer.analyze("example.com", port=80, https=False)

    assert result.status_code == 200
    assert result.redirects == ["https://example.com/login"]
    assert calls[-1] == ("example.com", 443, True, "/login")
