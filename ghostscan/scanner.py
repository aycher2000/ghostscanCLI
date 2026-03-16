"""Nmap execution and scan type definitions."""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from ghostscan.config import RESULTS_DIR
from ghostscan.runtime import ensure_results_dir_ok


def _sanitize_filename_part(s: str) -> str:
    """Make a string safe for use in filenames (regex- and filesystem-safe)."""
    if not s:
        return "unknown"
    # Allow only alphanumeric, underscore, hyphen, dot
    safe = re.sub(r"[^\w.\-]", "_", s, flags=re.ASCII)
    # Collapse multiple underscores, strip leading/trailing
    safe = re.sub(r"_+", "_", safe).strip("_.")
    return safe or "unknown"


@dataclass
class ScanDef:
    """Definition of a scan type: name, Nmap args, description, visibility, and metadata."""

    name: str
    args: List[str]
    description: str
    visibility: str
    when_to_use: str = ""
    next_step: str = ""
    requires_root: bool = False  # True = root/sudo recommended or needed for best results
    works_without_root: bool = True  # False = scan may not function without root (e.g. OS fingerprint)


# Scan type definitions for CLI and explain
SCAN_DEFS = {
    "discover": ScanDef(
        name="Host discovery",
        args=["-sn"],
        description="Ping and probe to find live hosts (no port scan). May require sudo depending on environment.",
        visibility="Smaller network footprint; may still be logged on filtered networks.",
        when_to_use="First step on a new network to find live hosts before port scanning.",
        next_step="Run 'ghostscan quick <ip>' on interesting hosts.",
        requires_root=True,  # -sn often needs raw sockets (e.g. wlan0); may work with sudo
        works_without_root=True,
    ),
    "quick": ScanDef(
        name="Quick TCP connect",
        args=["-Pn", "-sT", "-T4", "-F"],
        description="Fast scan of common ports using TCP connect. Designed to work without sudo.",
        visibility="Larger network footprint; full TCP handshakes are more likely to be logged.",
        when_to_use="After discovery (or when you know the host is up). Skips host discovery; no raw sockets.",
        next_step="Run 'ghostscan service <ip>' for version detection on open ports.",
        requires_root=False,
        works_without_root=True,
    ),
    "full": ScanDef(
        name="Full port scan",
        args=["-Pn", "-sT", "-T4", "-p-"],
        description="Scan all 65535 ports (slower). Designed to work without sudo.",
        visibility="Large network footprint; many connections, more likely to be logged and flagged by IDS.",
        when_to_use="When quick scan missed services or you need a complete port list.",
        next_step="Run 'ghostscan service <ip>' or profile scans on discovered ports.",
        requires_root=False,
        works_without_root=True,
    ),
    "service": ScanDef(
        name="Service/version detection",
        args=["-Pn", "-sT", "-sV", "-T4", "--version-intensity", "5"],
        description="Probe open ports to detect service and version. Designed to work without sudo.",
        visibility="Moderate footprint; extra probes are more likely to be logged.",
        when_to_use="After finding open ports to identify what is running.",
        next_step="Use profile scans (web, smb) or 'ghostscan os <ip>' for OS guess.",
        requires_root=False,
        works_without_root=True,
    ),
    "os": ScanDef(
        name="OS fingerprinting",
        args=["-O", "--osscan-guess", "-T4"],
        description="Guess operating system from stack behavior. May require sudo depending on environment.",
        visibility="Larger network footprint; unusual packets are more likely to be logged and flagged.",
        when_to_use="When you need to identify the OS.",
        next_step="Combine with service and profile results for full picture.",
        requires_root=True,
        works_without_root=False,  # -O typically needs raw packets; run with sudo for results
    ),
    # NSE scripts below confirmed available on Kali 2026.1 (http-*, smb-*). -Pn -sT for no-root use.
    "profile:web": ScanDef(
        name="Web enumeration profile",
        args=[
            "-Pn", "-sT",
            "-p", "80,443,8080,8443,8000",
            "-sV",
            "--script", "http-title,http-server-header,http-methods",
            "-T4",
        ],
        description="Target web ports and basic HTTP scripts. Designed to work without sudo.",
        visibility="Moderate footprint; HTTP traffic is normal for web servers but may be logged.",
        when_to_use="When you see open web ports (80, 443, 8080, etc.).",
        next_step="Manual HTTP probing or further NSE scripts as needed.",
        requires_root=False,
        works_without_root=True,
    ),
    "profile:smb": ScanDef(
        name="SMB enumeration profile",
        args=[
            "-Pn", "-sT",
            "-p", "139,445",
            "-sV",
            "--script", "smb-os-discovery,smb2-capabilities,smb-security-mode",  # confirmed on Kali
            "-T4",
        ],
        description="Target SMB ports and safe enumeration scripts. Designed to work without sudo.",
        visibility="Moderate footprint; SMB probes are more likely to be logged.",
        when_to_use="When you see open 139/445 (Windows or Samba).",
        next_step="Further SMB scripts or credential testing if authorized.",
        requires_root=False,
        works_without_root=True,
    ),
    "vuln": ScanDef(
        name="Vulnerability scan",
        args=["-Pn", "-sT", "--script", "vuln", "-T4"],
        description="Run NSE vuln scripts against open ports. Highlights potential vulnerabilities.",
        visibility="Large footprint; aggressive probing, likely to be logged.",
        when_to_use="After identifying services; only on authorized targets.",
        next_step="Review findings and validate manually; consider vendor advisories.",
        requires_root=False,
        works_without_root=True,
    ),
}


def run_nmap(
    target: str,
    extra_args: List[str],
    output_xml: Path,
    output_normal: Optional[Path] = None,
) -> subprocess.CompletedProcess:
    """
    Run Nmap against target, writing XML to output_xml.
    If output_normal is set, also write normal (human) output there.
    """
    cmd = ["nmap", "-oX", str(output_xml), target] + extra_args
    if output_normal is not None:
        cmd = ["nmap", "-oX", str(output_xml), "-oN", str(output_normal), target] + extra_args
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=3600,
    )


def get_scan_def(scan_type: str) -> Optional[ScanDef]:
    """Resolve 'quick', 'profile web', etc. to a ScanDef."""
    key = scan_type.strip().lower().replace(" ", ":")
    if key in SCAN_DEFS:
        return SCAN_DEFS[key]
    if key.startswith("profile:"):
        return SCAN_DEFS.get(key)
    return SCAN_DEFS.get(scan_type.strip().lower())


def run_scan(
    target: str,
    scan_type: str,
    results_dir: Optional[Path] = None,
    base_name: Optional[str] = None,
) -> tuple[Path, Path, subprocess.CompletedProcess]:
    """
    Run a scan by type name. Returns (xml_path, json_path, process).
    Uses results_dir or config.RESULTS_DIR; base_name used for file names.
    """
    results_dir = results_dir or RESULTS_DIR
    results_dir = Path(results_dir)
    ensure_results_dir_ok(results_dir)

    scan_def = get_scan_def(scan_type)
    if not scan_def:
        raise ValueError(f"Unknown scan type: {scan_type}")

    from datetime import datetime
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    scan_slug = _sanitize_filename_part(scan_type.replace(" ", "_").replace(":", "_"))
    safe_target = _sanitize_filename_part(target)
    name = base_name or f"{scan_slug}_{safe_target}_{ts}"

    xml_path = results_dir / f"{name}.xml"
    json_path = results_dir / f"{name}.json"

    proc = run_nmap(target, scan_def.args, xml_path)
    return xml_path, json_path, proc
