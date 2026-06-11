"""Tests for SQLite result storage and snapshot comparison."""

import json

from typer.testing import CliRunner

from reconforge.cli import app
from reconforge.core.sqlite_store import compare_snapshots, import_results_file, init_db


runner = CliRunner()


def _store(results):
    return {
        "session_id": "session-test",
        "created_at": "2026-06-11T00:00:00Z",
        "updated_at": "2026-06-11T00:00:00Z",
        "tool": "ReconForge",
        "version": "0.1.1b3",
        "results": results,
        "summary": {},
    }


def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_init_db_creates_sqlite_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    path = init_db()

    assert path.exists()


def test_import_results_file_returns_snapshot_id(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    results_file = tmp_path / "results.json"
    _write_json(results_file, _store([]))

    snapshot_id = import_results_file(results_file)

    assert snapshot_id == 1


def test_compare_snapshots_detects_port_banner_and_tls_changes(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    baseline_file = tmp_path / "baseline.json"
    current_file = tmp_path / "current.json"

    _write_json(
        baseline_file,
        _store(
            [
                {
                    "type": "ports",
                    "target": "127.0.0.1",
                    "data": {
                        "target": "127.0.0.1",
                        "open_ports": [
                            {"port": 22, "service": "SSH"},
                            {"port": 80, "service": "HTTP"},
                        ],
                    },
                },
                {
                    "type": "banner",
                    "target": "127.0.0.1",
                    "data": {"ports": [{"port": 22, "banner": "OpenSSH 8"}]},
                },
                {
                    "type": "http",
                    "target": "example.com",
                    "data": {
                        "target": "example.com",
                        "port": 443,
                        "tls_certificate": {"not_after": "Jan 01 00:00:00 2027 GMT"},
                    },
                },
            ]
        ),
    )
    _write_json(
        current_file,
        _store(
            [
                {
                    "type": "ports",
                    "target": "127.0.0.1",
                    "data": {
                        "target": "127.0.0.1",
                        "open_ports": [
                            {"port": 22, "service": "SSH"},
                            {"port": 443, "service": "HTTPS"},
                        ],
                    },
                },
                {
                    "type": "banner",
                    "target": "127.0.0.1",
                    "data": {"ports": [{"port": 22, "banner": "OpenSSH 9"}]},
                },
                {
                    "type": "http",
                    "target": "example.com",
                    "data": {
                        "target": "example.com",
                        "port": 443,
                        "tls_certificate": {"not_after": "Jan 01 00:00:00 2028 GMT"},
                    },
                },
            ]
        ),
    )

    baseline_id = import_results_file(baseline_file)
    current_id = import_results_file(current_file)
    diff = compare_snapshots(baseline_id, current_id)

    assert [item["port"] for item in diff["newly_opened_ports"]] == [443]
    assert [item["port"] for item in diff["closed_ports"]] == [80]
    assert diff["changed_banners"][0]["baseline"] == "OpenSSH 8"
    assert diff["changed_banners"][0]["current"] == "OpenSSH 9"
    assert diff["changed_tls_metadata"][0]["baseline"]["not_after"].endswith("2027 GMT")
    assert diff["changed_tls_metadata"][0]["current"]["not_after"].endswith("2028 GMT")


def test_db_cli_init_import_and_compare(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    baseline_file = tmp_path / "baseline.json"
    current_file = tmp_path / "current.json"
    _write_json(
        baseline_file,
        _store([{"type": "ports", "target": "127.0.0.1", "data": {"open_ports": [80]}}]),
    )
    _write_json(
        current_file,
        _store([{"type": "ports", "target": "127.0.0.1", "data": {"open_ports": [80, 443]}}]),
    )

    init_result = runner.invoke(app, ["db", "init"])
    baseline_result = runner.invoke(app, ["db", "import", str(baseline_file)])
    current_result = runner.invoke(app, ["db", "import", str(current_file)])
    compare_result = runner.invoke(app, ["compare", "--baseline", "1", "--current", "2"])

    assert init_result.exit_code == 0
    assert baseline_result.exit_code == 0
    assert "snapshot ID 1" in baseline_result.output
    assert current_result.exit_code == 0
    assert "snapshot ID 2" in current_result.output
    assert compare_result.exit_code == 0
    assert "443" in compare_result.output
