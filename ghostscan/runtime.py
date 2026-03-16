"""Runtime checks: root detection, results directory writability, error handling."""

import os
from pathlib import Path
from typing import Optional, Tuple


def is_running_as_root() -> bool:
    """True if process has effective UID 0 (root). Unix only."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # Windows or other


def results_dir_writable(results_dir: Path) -> Tuple[bool, Optional[str]]:
    """
    Check if results directory is writable. Creates dir if missing (if parent is writable).
    Returns (True, None) if ok, (False, error_message) otherwise.
    """
    path = Path(results_dir)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return False, f"Cannot create results directory: {e}"
    if not path.is_dir():
        return False, "Results path is not a directory."
    try:
        if not os.access(path, os.W_OK):
            return False, (
                "Results directory is not writable. "
                "If you previously ran GhostScan with sudo, try: sudo chown -R $USER results"
            )
    except OSError as e:
        return False, str(e)
    return True, None


def ensure_results_dir_ok(results_dir: Path) -> None:
    """
    Ensure results dir exists and is writable. Raises RuntimeError with helpful message if not.
    If running as root and dir exists with wrong ownership, suggest chown.
    """
    ok, err = results_dir_writable(results_dir)
    if ok:
        return
    msg = err or "Results directory not usable."
    if is_running_as_root() and results_dir.exists():
        msg += " (Running as root; results may be owned by root. Run without sudo for normal use.)"
    raise RuntimeError(msg)
