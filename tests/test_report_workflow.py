"""Tests for cumulative report workflow commands."""

from typer.testing import CliRunner

from reconforge.cli import app
from reconforge.core.paths import RESULTS_JSON
from reconforge.core.results_store import append_result, load_results_store
from reconforge.reporting.html_report import HTMLReporter, normalize_scan_result


runner = CliRunner()


def test_report_without_input_uses_default_results_store(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    append_result("ports", "127.0.0.1", {"target": "127.0.0.1", "open_ports": []})

    result = runner.invoke(app, ["report"])

    assert result.exit_code == 0
    assert "Reading results from: .reconforge\\session\\results.json" in result.output or (
        "Reading results from: .reconforge/session/results.json" in result.output
    )


def test_report_creates_timestamped_html_report(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    append_result("http", "example.com", {"status_code": 200})

    result = runner.invoke(app, ["report"])

    assert result.exit_code == 0
    reports = list((tmp_path / "reports").glob("reconforge_report_*.html"))
    assert len(reports) == 1
    assert "ReconForge Cumulative Report" in reports[0].read_text(encoding="utf-8")


def test_report_clear_clears_results_store_after_success(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    append_result("banner", "127.0.0.1", {"ports": []})

    result = runner.invoke(app, ["report", "--clear"])

    assert result.exit_code == 0
    store = load_results_store()
    assert store["results"] == []


def test_clear_results_command_clears_results_store(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    append_result("ports", "127.0.0.1", {})

    result = runner.invoke(app, ["clear-results", "--yes"])

    assert result.exit_code == 0
    assert load_results_store()["results"] == []


def test_empty_results_store_gives_friendly_report_error(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["report"])

    assert result.exit_code == 1
    assert "No ReconForge results found" in result.output
    assert RESULTS_JSON.exists()


def test_html_report_includes_open_ports_from_scan_results(tmp_path):
    output = tmp_path / "report.html"
    store = {
        "session_id": "test-session",
        "created_at": "2026-06-08T00:00:00Z",
        "updated_at": "2026-06-08T00:00:00Z",
        "results": [
            {
                "type": "scan",
                "timestamp": "2026-06-08T00:00:01Z",
                "target": "127.0.0.1",
                "data": {
                    "hosts": [
                        {
                            "ip_address": "127.0.0.1",
                            "alive": True,
                            "open_ports": [
                                {"port": 22, "service": "ssh"},
                                {"port": 80, "service": "http"},
                            ],
                        }
                    ]
                },
            }
        ],
        "summary": {"total_results": 1, "unique_targets": 1},
    }

    HTMLReporter.report_results_store(store, output)
    html = output.read_text(encoding="utf-8")

    assert "Scan Results" in html
    assert "127.0.0.1" in html
    assert "up" in html
    assert "22/ssh, 80/http" in html


def test_html_report_handles_hosts_with_no_open_ports(tmp_path):
    output = tmp_path / "report.html"
    store = {
        "session_id": "test-session",
        "results": [
            {
                "type": "scan",
                "timestamp": "2026-06-08T00:00:01Z",
                "target": "127.0.0.1",
                "data": {
                    "hosts": [
                        {"ip_address": "127.0.0.1", "alive": True, "open_ports": []}
                    ]
                },
            }
        ],
        "summary": {"total_results": 1, "unique_targets": 1},
    }

    HTMLReporter.report_results_store(store, output)
    html = output.read_text(encoding="utf-8")

    assert "127.0.0.1" in html
    assert "No open ports found" in html


def test_html_report_handles_scan_ports_as_integers(tmp_path):
    output = tmp_path / "report.html"
    store = {
        "session_id": "test-session",
        "results": [
            {
                "type": "scan",
                "timestamp": "2026-06-08T00:00:01Z",
                "target": "127.0.0.1",
                "data": {
                    "hosts": [
                        {"ip_address": "127.0.0.1", "alive": True, "ports": [22, 80, 443]}
                    ]
                },
            }
        ],
        "summary": {"total_results": 1, "unique_targets": 1},
    }

    HTMLReporter.report_results_store(store, output)
    html = output.read_text(encoding="utf-8")

    assert "22, 80, 443" in html


def test_html_report_handles_scan_ports_as_objects_with_service_and_banner(tmp_path):
    output = tmp_path / "report.html"
    store = {
        "session_id": "test-session",
        "results": [
            {
                "type": "scan",
                "timestamp": "2026-06-08T00:00:01Z",
                "target": "127.0.0.1",
                "data": {
                    "hosts": [
                        {
                            "hostname": "localhost",
                            "status": "up",
                            "open_ports": [
                                {
                                    "port": 22,
                                    "service": "ssh",
                                    "banner": "OpenSSH test banner",
                                }
                            ],
                        }
                    ]
                },
            }
        ],
        "summary": {"total_results": 1, "unique_targets": 1},
    }

    HTMLReporter.report_results_store(store, output)
    html = output.read_text(encoding="utf-8")

    assert "localhost" in html
    assert "22/ssh (OpenSSH test banner)" in html


def test_normalize_scan_result_returns_simple_host_port_shape():
    result = {
        "type": "scan",
        "timestamp": "2026-06-08T00:00:01Z",
        "target": "127.0.0.1",
        "data": {
            "hosts": [
                {
                    "ip_address": "127.0.0.1",
                    "alive": True,
                    "open_ports": [
                        {"port": 22, "service": "ssh", "banner": {"banner": "OpenSSH"}},
                        80,
                    ],
                }
            ]
        },
    }

    normalized = normalize_scan_result(result)

    assert normalized == {
        "target": "127.0.0.1",
        "timestamp": "2026-06-08T00:00:01Z",
        "hosts": [
            {
                "host": "127.0.0.1",
                "status": "up",
                "open_ports": [
                    {"port": 22, "service": "ssh", "banner": "OpenSSH"},
                    {"port": 80, "service": None, "banner": None},
                ],
            }
        ],
    }
