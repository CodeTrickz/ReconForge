"""Runtime paths for ReconForge session data and reports."""

from datetime import datetime, timezone
from pathlib import Path

RUNTIME_DIR = Path(".reconforge")
SESSION_DIR = Path(".reconforge/session")
RESULTS_JSON = Path(".reconforge/session/results.json")
REPORTS_DIR = Path("reports")
SQLITE_DB = Path(".reconforge/reconforge.db")


def ensure_runtime_dirs() -> None:
    """Create runtime directories used by ReconForge."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def timestamp_slug() -> str:
    """Return a filesystem-friendly UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def timestamp_iso() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def timestamped_report_path(format: str) -> Path:
    """Return a timestamped report path for html or json output."""
    normalized = format.lower().lstrip(".")
    if normalized not in {"html", "json"}:
        raise ValueError("Report format must be 'html' or 'json'")
    return REPORTS_DIR / f"reconforge_report_{timestamp_slug()}.{normalized}"
