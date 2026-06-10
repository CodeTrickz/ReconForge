"""Tests for the cumulative ReconForge results store."""

from reconforge.core.paths import RESULTS_JSON
from reconforge.core.results_store import (
    append_result,
    build_summary,
    clear_results_store,
    load_results_store,
)


def test_results_store_is_created_automatically(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    store = load_results_store()

    assert RESULTS_JSON.exists()
    assert store["results"] == []
    assert store["session_id"]


def test_append_result_preserves_previous_entries(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    append_result("ports", "127.0.0.1", {"open_ports": []})
    append_result("banner", "127.0.0.1", {"ports": []})
    store = load_results_store()

    assert len(store["results"]) == 2
    assert store["results"][0]["type"] == "ports"
    assert store["results"][1]["type"] == "banner"


def test_multiple_result_types_can_be_stored(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    append_result("scan", "192.168.1.0/24", {"hosts": []})
    append_result("ports", "192.168.1.10", {"open_ports": []})
    append_result("http", "example.com", {"status_code": 200})
    store = load_results_store()

    assert {result["type"] for result in store["results"]} == {"scan", "ports", "http"}


def test_build_summary_counts_result_types(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    append_result("ports", "127.0.0.1", {})
    append_result("ports", "127.0.0.1", {})
    append_result("http", "example.com", {})
    store = load_results_store()
    summary = build_summary(store)

    assert summary["total_results"] == 3
    assert summary["unique_targets"] == 2
    assert summary["result_counts"] == {"http": 1, "ports": 2}


def test_clear_results_store_resets_entries(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    append_result("ports", "127.0.0.1", {})
    clear_results_store()
    store = load_results_store()

    assert store["results"] == []
    assert store["summary"]["total_results"] == 0
