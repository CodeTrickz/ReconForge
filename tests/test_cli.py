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
    monkeypatch.chdir(tmp_path)
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


def test_ports_dry_run_skips_network_activity(monkeypatch):
    class BoomScanner:
        def __init__(self, timeout):
            raise AssertionError("scanner should not be created during dry-run")

    monkeypatch.setattr("reconforge.cli.PortScanner", BoomScanner)

    result = runner.invoke(app, ["ports", "127.0.0.1", "--dry-run"])

    assert result.exit_code == 0
    assert "DRY RUN" in result.output
    assert "No network activity was performed." in result.output


def test_scan_rejects_target_outside_scope_file(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("192.168.1.0/24\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", "127.0.0.1", "--dry-run", "--scope-file", str(scope_file)])

    assert result.exit_code == 1
    assert "Target outside authorized scope" in result.output


def test_http_dry_run_respects_scope_file(monkeypatch, tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n", encoding="utf-8")

    class BoomAnalyzer:
        def __init__(self, timeout):
            raise AssertionError("HTTP analyzer should not be created during dry-run")

    monkeypatch.setattr("reconforge.cli.HTTPAnalyzer", BoomAnalyzer)

    result = runner.invoke(
        app,
        ["http", "127.0.0.1", "--https", "--dry-run", "--scope-file", str(scope_file)],
    )

    assert result.exit_code == 0
    assert "HTTP/TLS ANALYSIS DRY RUN" in result.output
    assert "127.0.0.1" in result.output


def test_banner_scope_file_accepts_authorized_host(monkeypatch, tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("127.0.0.1\n", encoding="utf-8")

    class FakeBannerGrabber:
        def __init__(self, timeout):
            self.timeout = timeout

        def grab_banners(self, host, ports, workers):
            raise AssertionError("banner grabber should not run during dry-run")

    monkeypatch.setattr("reconforge.cli.BannerGrabber", FakeBannerGrabber)

    result = runner.invoke(
        app,
        ["banner", "127.0.0.1", "--port", "80", "--dry-run", "--scope-file", str(scope_file)],
    )

    assert result.exit_code == 0
    assert "BANNER GRAB DRY RUN" in result.output
