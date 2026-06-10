"""Cumulative ReconForge results store."""

import json
import uuid
from collections import Counter
from pathlib import Path
from typing import Dict, Optional

from reconforge.core.paths import RESULTS_JSON, ensure_runtime_dirs, timestamp_iso, timestamp_slug


def _new_store() -> dict:
    now = timestamp_iso()
    return {
        "session_id": timestamp_slug(),
        "created_at": now,
        "updated_at": now,
        "tool": "ReconForge",
        "version": "0.1.1b1",
        "results": [],
        "summary": {},
    }


def load_results_store() -> dict:
    """Load the cumulative results store, creating it if missing."""
    ensure_runtime_dirs()
    if not RESULTS_JSON.exists():
        store = _new_store()
        save_results_store(store)
        return store

    try:
        with open(RESULTS_JSON, "r", encoding="utf-8") as f:
            store = json.load(f)
    except (json.JSONDecodeError, OSError):
        store = _new_store()

    store.setdefault("session_id", timestamp_slug())
    store.setdefault("created_at", timestamp_iso())
    store.setdefault("tool", "ReconForge")
    store.setdefault("version", "0.1.1b1")
    store.setdefault("results", [])
    store["summary"] = build_summary(store)
    store.setdefault("updated_at", store["created_at"])
    save_results_store(store)
    return store


def save_results_store(store: dict) -> None:
    """Persist the cumulative results store."""
    ensure_runtime_dirs()
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, default=str)


def append_result(
    result_type: str,
    target: str,
    data: dict,
    command: Optional[str] = None,
) -> None:
    """Append a reconnaissance result to the cumulative session store."""
    store = load_results_store()
    store["results"].append(
        {
            "id": str(uuid.uuid4()),
            "type": result_type,
            "timestamp": timestamp_iso(),
            "target": target,
            "command": command,
            "data": data,
        }
    )
    store["updated_at"] = timestamp_iso()
    store["summary"] = build_summary(store)
    save_results_store(store)


def clear_results_store() -> None:
    """Reset the cumulative results store."""
    store = _new_store()
    store["summary"] = build_summary(store)
    save_results_store(store)


def build_summary(store: dict) -> dict:
    """Build summary counts from a cumulative results store."""
    results = store.get("results", [])
    result_counts = Counter(item.get("type", "unknown") for item in results)
    targets = sorted({item.get("target") for item in results if item.get("target")})

    target_counts: Dict[str, int] = Counter(
        item.get("target") for item in results if item.get("target")
    )

    return {
        "total_results": len(results),
        "unique_targets": len(targets),
        "targets": targets,
        "result_counts": dict(sorted(result_counts.items())),
        "targets_summary": [
            {"target": target, "result_count": count}
            for target, count in sorted(target_counts.items())
        ],
    }


def load_results_store_from_path(path: Path) -> dict:
    """Load a results store from a custom path without creating the default store."""
    with open(path, "r", encoding="utf-8") as f:
        store = json.load(f)
    store.setdefault("results", [])
    store["summary"] = build_summary(store)
    return store
