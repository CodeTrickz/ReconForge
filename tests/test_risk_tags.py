"""Tests for informational risk tagging."""

import json
from datetime import datetime, timedelta, timezone

from reconforge.core.models import PortListResult, PortScanResult
from reconforge.core.results_store import append_result, load_results_store
from reconforge.core.risk_tags import classify_result
from reconforge.reporting.html_report import HTMLReporter
from reconforge.reporting.json_report import JSONReporter


def test_classifies_open_ports_by_severity():
    tags = classify_result(
        "ports",
        "127.0.0.1",
        {
            "open_ports": [
                {"port": 80, "service": "http"},
                {"port": 22, "service": "ssh"},
                {"port": 23, "service": "telnet"},
            ]
        },
    )

    severities = {tag["id"]: tag["severity"] for tag in tags}
    assert severities["open-port-80"] == "low"
    assert severities["open-port-22"] == "medium"
    assert severities["telnet-open"] == "high"


def test_classifies_banner_disclosure():
    tags = classify_result(
        "banner",
        "127.0.0.1",
        {"ports": [{"port": 22, "banner": "OpenSSH test banner"}]},
    )

    assert tags[0]["id"] == "banner-disclosure"
    assert tags[0]["severity"] == "low"
    assert "OpenSSH" in tags[0]["evidence"]


def test_classifies_missing_http_headers_and_tls_expiry():
    expired = "Jan 01 00:00:00 2020 GMT"
    tags = classify_result(
        "http",
        "example.com",
        {
            "server_header": "nginx",
            "security_headers": {
                "Strict-Transport-Security": None,
                "Content-Security-Policy": None,
            },
            "tls_certificate": {"not_after": expired},
        },
    )

    tag_ids = {tag["id"]: tag for tag in tags}
    assert tag_ids["missing-http-security-headers"]["severity"] == "medium"
    assert tag_ids["server-header-disclosure"]["severity"] == "low"
    assert tag_ids["tls-certificate-expired"]["severity"] == "high"


def test_classifies_tls_certificate_expiring_soon():
    soon = datetime.now(timezone.utc) + timedelta(days=10)
    tags = classify_result(
        "http",
        "example.com",
        {
            "security_headers": {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            "tls_certificate": {
                "not_after": soon.strftime("%b %d %H:%M:%S %Y GMT")
            },
        },
    )

    assert [tag["id"] for tag in tags] == ["tls-certificate-expiring-soon"]
    assert tags[0]["severity"] == "medium"


def test_append_result_stores_risk_tags_and_summary_counts(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    append_result(
        "ports",
        "127.0.0.1",
        {"open_ports": [{"port": 22, "service": "ssh"}]},
    )
    store = load_results_store()

    assert store["results"][0]["risk_tags"][0]["id"] == "open-port-22"
    assert store["summary"]["total_risk_tags"] == 1
    assert store["summary"]["risk_counts"]["medium"] == 1


def test_explicit_json_report_includes_risk_tags(tmp_path):
    output = tmp_path / "ports.json"
    result = PortListResult(
        target="127.0.0.1",
        open_ports=[PortScanResult(port=22, open=True, service="SSH")],
        scanned_ports=[22],
    )

    JSONReporter.report_ports(result, output)
    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["risk_tags"][0]["id"] == "open-port-22"
    assert data["risk_tags"][0]["severity"] == "medium"


def test_html_report_renders_risk_tags(tmp_path):
    output = tmp_path / "report.html"
    store = {
        "session_id": "risk-test",
        "summary": {
            "total_results": 1,
            "unique_targets": 1,
            "total_risk_tags": 1,
            "risk_counts": {"low": 0, "medium": 1, "high": 0},
        },
        "results": [
            {
                "type": "ports",
                "target": "127.0.0.1",
                "timestamp": "2026-06-10T00:00:00Z",
                "data": {"open_ports": [{"port": 22, "service": "SSH"}]},
                "risk_tags": classify_result(
                    "ports",
                    "127.0.0.1",
                    {"open_ports": [{"port": 22, "service": "SSH"}]},
                ),
            }
        ],
    }

    HTMLReporter.report_results_store(store, output)
    html = output.read_text(encoding="utf-8")

    assert "Risk Tags" in html
    assert "SSH service exposed" in html
    assert "medium" in html
