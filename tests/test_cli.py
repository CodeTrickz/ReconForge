"""CLI tests for ReconForge."""

from typer.testing import CliRunner

from reconforge.core.models import HTTPAnalysisResult, TLSCertificateInfo
from reconforge.cli import app
from reconforge.reporting.html_report import HTMLReporter


runner = CliRunner()


def test_help_renders_without_unicode_error():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "ReconForge" in result.output
    assert "ports" in result.output
    assert "banner" in result.output


def test_ports_rejects_invalid_target():
    result = runner.invoke(app, ["ports", "not a valid target"])
    assert result.exit_code == 1
    assert "Invalid input" in result.output


def test_banner_rejects_invalid_port():
    result = runner.invoke(app, ["banner", "127.0.0.1", "--port", "70000"])
    assert result.exit_code == 1
    assert "Port out of range" in result.output


def test_html_template_is_package_data():
    template = HTMLReporter().env.get_template("report.html.j2")
    assert template.name == "report.html.j2"


def test_http_command_outputs_table_and_json(monkeypatch, tmp_path):
    output_file = tmp_path / "http.json"

    class FakeHTTPAnalyzer:
        def __init__(self, timeout):
            self.timeout = timeout

        def analyze(self, host, port, https):
            assert host == "127.0.0.1"
            assert port == 443
            assert https is True
            return HTTPAnalysisResult(
                target=host,
                port=port,
                scheme="https",
                status_code=200,
                server_header="unit-test",
                security_headers={"Strict-Transport-Security": "max-age=31536000"},
                redirects=[],
                tls_certificate=TLSCertificateInfo(subject="commonName=localhost"),
            )

    monkeypatch.setattr("reconforge.cli.HTTPAnalyzer", FakeHTTPAnalyzer)

    result = runner.invoke(
        app,
        ["http", "127.0.0.1", "--port", "443", "--https", "--json-output", str(output_file)],
    )

    assert result.exit_code == 0
    assert "HTTP/TLS ANALYSIS" in result.output
    assert "Strict-Transport-Security" in result.output
    assert output_file.exists()


def test_http_command_rejects_url_input():
    result = runner.invoke(app, ["http", "https://example.com", "--https"])
    assert result.exit_code == 1
    assert "Host must be a hostname or IPv4 address" in result.output
