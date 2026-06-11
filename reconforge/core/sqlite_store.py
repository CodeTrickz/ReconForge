"""SQLite storage backend for ReconForge result snapshots."""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from reconforge.core.paths import SQLITE_DB, ensure_runtime_dirs, timestamp_iso
from reconforge.core.results_store import build_summary

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    source_file TEXT,
    imported_at TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT,
    summary_json TEXT NOT NULL,
    data_json TEXT NOT NULL
);
"""


def connect_db(db_path: Path = SQLITE_DB) -> sqlite3.Connection:
    """Open a SQLite connection, creating runtime directories first."""
    ensure_runtime_dirs()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = SQLITE_DB) -> Path:
    """Initialize the ReconForge SQLite database."""
    conn = connect_db(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()
    return db_path


def _load_json_file(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Results JSON must contain an object")
    data.setdefault("results", [])
    data["summary"] = build_summary(data)
    return data


def import_results_file(path: Path, db_path: Path = SQLITE_DB) -> int:
    """Import a cumulative results JSON file as a SQLite snapshot."""
    if not path.exists():
        raise FileNotFoundError(path)

    store = _load_json_file(path)
    init_db(db_path)
    imported_at = timestamp_iso()

    conn = connect_db(db_path)
    try:
        cursor = conn.execute(
            """
            INSERT INTO snapshots (
                session_id, source_file, imported_at, created_at, updated_at,
                summary_json, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                store.get("session_id"),
                str(path),
                imported_at,
                store.get("created_at"),
                store.get("updated_at"),
                json.dumps(store.get("summary", {}), default=str),
                json.dumps(store, default=str),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()


def load_snapshot(snapshot_id: int, db_path: Path = SQLITE_DB) -> dict:
    """Load an imported snapshot by integer ID."""
    init_db(db_path)
    conn = connect_db(db_path)
    try:
        row = conn.execute(
            "SELECT data_json FROM snapshots WHERE id = ?",
            (snapshot_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise ValueError(f"Snapshot ID not found: {snapshot_id}")
    return json.loads(row["data_json"])


def _port_number(port: Any) -> Optional[int]:
    if isinstance(port, int):
        return port
    if isinstance(port, dict):
        try:
            return int(port.get("port") or port.get("number") or port.get("id"))
        except (TypeError, ValueError):
            return None
    return None


def _banner_text(port: Any) -> Optional[str]:
    if not isinstance(port, dict):
        return None
    banner = port.get("banner")
    if isinstance(banner, dict):
        banner = banner.get("banner") or banner.get("raw") or banner.get("text")
    return str(banner) if banner else None


def _iter_scan_host_ports(data: dict) -> Iterable[Tuple[str, Any]]:
    for host in data.get("hosts", []) or []:
        if not isinstance(host, dict):
            continue
        host_name = (
            host.get("ip_address")
            or host.get("ip")
            or host.get("host")
            or host.get("hostname")
            or "-"
        )
        for port in host.get("open_ports") or host.get("ports") or []:
            yield str(host_name), port


def extract_open_ports(store: dict) -> Dict[Tuple[str, str, int], dict]:
    """Extract open port observations keyed by target, host, and port."""
    ports: Dict[Tuple[str, str, int], dict] = {}
    for result in store.get("results", []) or []:
        result_type = result.get("type")
        target = str(result.get("target") or result.get("data", {}).get("target") or "-")
        data = result.get("data", {})

        if result_type == "ports":
            host = str(data.get("target") or target)
            iterable = [(host, port) for port in data.get("open_ports", []) or []]
        elif result_type == "scan":
            iterable = list(_iter_scan_host_ports(data))
        else:
            continue

        for host, port in iterable:
            number = _port_number(port)
            if number is None:
                continue
            service = port.get("service") if isinstance(port, dict) else None
            ports[(target, host, number)] = {
                "target": target,
                "host": host,
                "port": number,
                "service": service,
            }
    return ports


def extract_banners(store: dict) -> Dict[Tuple[str, int], str]:
    """Extract observed banner text keyed by target and port."""
    banners: Dict[Tuple[str, int], str] = {}
    for result in store.get("results", []) or []:
        target = str(result.get("target") or result.get("data", {}).get("target") or "-")
        data = result.get("data", {})

        if result.get("type") == "banner":
            ports = data.get("ports", []) or []
        elif result.get("type") == "scan":
            ports = []
            for _host, port in _iter_scan_host_ports(data):
                ports.append(port)
        else:
            continue

        for port in ports:
            number = _port_number(port)
            banner = _banner_text(port)
            if number is not None and banner:
                banners[(target, number)] = banner
    return banners


def extract_tls_metadata(store: dict) -> Dict[Tuple[str, int], dict]:
    """Extract TLS certificate metadata keyed by target and port."""
    tls: Dict[Tuple[str, int], dict] = {}
    for result in store.get("results", []) or []:
        if result.get("type") != "http":
            continue
        data = result.get("data", {})
        cert = data.get("tls_certificate")
        if not isinstance(cert, dict):
            continue
        target = str(result.get("target") or data.get("target") or "-")
        port = int(data.get("port") or 443)
        tls[(target, port)] = {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "not_before": cert.get("not_before"),
            "not_after": cert.get("not_after"),
            "sans": cert.get("sans") or [],
        }
    return tls


def compare_snapshots(baseline_id: int, current_id: int, db_path: Path = SQLITE_DB) -> dict:
    """Compare two imported snapshots."""
    baseline = load_snapshot(baseline_id, db_path)
    current = load_snapshot(current_id, db_path)

    baseline_ports = extract_open_ports(baseline)
    current_ports = extract_open_ports(current)
    baseline_banners = extract_banners(baseline)
    current_banners = extract_banners(current)
    baseline_tls = extract_tls_metadata(baseline)
    current_tls = extract_tls_metadata(current)

    opened = [
        current_ports[key]
        for key in sorted(current_ports.keys() - baseline_ports.keys())
    ]
    closed = [
        baseline_ports[key]
        for key in sorted(baseline_ports.keys() - current_ports.keys())
    ]
    changed_banners = [
        {
            "target": key[0],
            "port": key[1],
            "baseline": baseline_banners[key],
            "current": current_banners[key],
        }
        for key in sorted(baseline_banners.keys() & current_banners.keys())
        if baseline_banners[key] != current_banners[key]
    ]
    changed_tls = [
        {
            "target": key[0],
            "port": key[1],
            "baseline": baseline_tls[key],
            "current": current_tls[key],
        }
        for key in sorted(baseline_tls.keys() & current_tls.keys())
        if baseline_tls[key] != current_tls[key]
    ]

    return {
        "baseline_id": baseline_id,
        "current_id": current_id,
        "newly_opened_ports": opened,
        "closed_ports": closed,
        "changed_banners": changed_banners,
        "changed_tls_metadata": changed_tls,
    }
