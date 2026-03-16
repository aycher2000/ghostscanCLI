"""Paths and default configuration.

All paths are relative to current working directory (CWD) and use pathlib
for Linux-safe, SSH-friendly behavior. No GUI assumptions; headless CLI only.
"""

from pathlib import Path

# Default directory for scan results (relative to CWD on Kali/SSH)
RESULTS_DIR = Path("results")
# Directory is created on first use in scanner/reporter, not at import

# Latest result filename (used by "report show latest" and "next latest")
LATEST_JSON = "latest.json"
LATEST_XML = "latest.xml"

# --- Runtime environment (confirmed for remote SSH / headless use) ---
# Kali GNU/Linux Rolling 2026.1, Python 3.13.12, Nmap 7.98
# Executed remotely over SSH from Mac terminal; headless CLI only.
RUNTIME_ENV = {
    "platform": "Kali GNU/Linux Rolling 2026.1",
    "python": "3.13.12",
    "nmap": "7.98",
    "usage": "remote SSH, headless CLI",
}
