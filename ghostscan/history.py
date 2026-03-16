"""Scan history: persist and list recent scans."""

import json
from datetime import datetime
from pathlib import Path
from typing import List

from ghostscan.config import RESULTS_DIR

HISTORY_FILE = "scan_history.json"
MAX_ENTRIES = 100


def _history_path() -> Path:
    return RESULTS_DIR / HISTORY_FILE


def record_scan(target: str, scan_type: str) -> None:
    """Append one scan record to history (target, scan_type, timestamp)."""
    path = _history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    except (OSError, json.JSONDecodeError):
        data = []
    if not isinstance(data, list):
        data = []
    data.append({
        "target": target,
        "scan_type": scan_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })
    data = data[-MAX_ENTRIES:]
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def list_recent_scans(limit: int = 20) -> List[dict]:
    """Return recent scan records, newest first. Each dict has target, scan_type, timestamp."""
    path = _history_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    data = [x for x in data if isinstance(x, dict) and "target" in x]
    data.reverse()
    return data[:limit]
