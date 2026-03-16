"""Explanations and next-step recommendations."""

from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ghostscan.parser import HostResult, PortInfo, ScanResult, load_result_from_json
from ghostscan.scanner import SCAN_DEFS

console = Console()


def explain_scan(scan_type: str) -> bool:
    """
    Print explanation for a scan type. Returns True if found and printed.
    """
    key = scan_type.strip().lower().replace(" ", ":")
    if key not in SCAN_DEFS:
        return False
    d = SCAN_DEFS[key]
    parts = [f"[bold]{d.name}[/bold]\n\n{d.description}\n\n[dim]Visibility:[/dim] {d.visibility}"]
    if getattr(d, "when_to_use", None):
        parts.append(f"\n[dim]When to use:[/dim] {d.when_to_use}")
    if getattr(d, "next_step", None):
        parts.append(f"\n[dim]Typical next step:[/dim] {d.next_step}")
    # Privilege: warn, never block
    if getattr(d, "requires_root", False):
        if getattr(d, "works_without_root", True):
            parts.append("\n[yellow]May require sudo depending on the environment (e.g. raw sockets on wlan0).[/yellow]")
        else:
            parts.append(
                "\n[yellow]May require sudo depending on the environment; this scan typically needs root to work.[/yellow]"
            )
    else:
        parts.append("\n[dim]Designed to work without sudo (uses -Pn -sT to avoid raw sockets).[/dim]")
    console.print(Panel("\n".join(parts), title="Scan explanation"))
    return True


def recommend_general() -> None:
    """Print general workflow recommendations (ghostscan recommend)."""
    table = Table(title="Suggested workflow", show_header=True, header_style="bold")
    table.add_column("Step", style="cyan")
    table.add_column("Command", style="green")
    table.add_column("When to use", style="white")
    table.add_row("1", "ghostscan discover <range>", "Find live hosts (may require sudo depending on env)")
    table.add_row("2", "ghostscan quick <ip>", "Quick common ports; works without sudo (-Pn -sT)")
    table.add_row("3", "ghostscan service <ip>", "Service/version detection; works without sudo")
    table.add_row("4", "ghostscan os <ip>", "OS fingerprint (may require sudo depending on env)")
    table.add_row("—", "ghostscan profile web <ip>", "Web ports + HTTP scripts; works without sudo")
    table.add_row("—", "ghostscan profile smb <ip>", "SMB ports + scripts; works without sudo")
    table.add_row("—", "ghostscan vuln <ip>", "Vulnerability scan (NSE vuln); authorized targets only")
    table.add_row("", "ghostscan recon <ip>", "Automated chain: quick → service → web if detected")
    table.add_row("", "ghostscan map <cidr>", "Discover hosts, then quick + service; network inventory")
    table.add_row("", "ghostscan next latest", "Get next steps from your last scan")
    console.print(table)


def _open_ports(host: HostResult) -> List[PortInfo]:
    return [p for p in host.ports if p.state and p.state.lower() == "open"]


def _has_port(host: HostResult, port: int) -> bool:
    return any(p.port == port for p in _open_ports(host))


# Well-known ports for smart recommendations
WEB_PORTS = {80, 443, 8080, 8443, 8000}
SMB_PORTS = {139, 445}
SSH_PORT = 22
DB_PORTS = {3306, 5432, 27017, 1433, 1521}  # MySQL, PostgreSQL, MongoDB, MSSQL, Oracle


def _port_set(host: HostResult) -> set:
    return {p.port for p in _open_ports(host)}


def has_web_ports(host: HostResult) -> bool:
    """True if host has common web ports open."""
    return bool(_port_set(host) & WEB_PORTS)


def _next_steps_from_result(result: ScanResult) -> List[str]:
    """Generate contextual next-step recommendations from a ScanResult (per-host)."""
    steps: List[str] = []
    for host in result.hosts:
        addr = host.address or "this host"
        open_ports = _open_ports(host)
        port_set = _port_set(host)
        host_steps: List[str] = []
        if not open_ports:
            host_steps.append(f"Host {addr}: No open ports in this scan. Try 'ghostscan full {addr}' for all ports.")
        else:
            if port_set & WEB_PORTS:
                host_steps.append(f"Host {addr}: Web ports open. Run 'ghostscan profile web {addr}' for HTTP details.")
            if port_set & SMB_PORTS:
                host_steps.append(f"Host {addr}: SMB ports open. Run 'ghostscan profile smb {addr}' for SMB enumeration.")
            if SSH_PORT in port_set:
                host_steps.append(f"Host {addr}: SSH (22) detected. Consider key-based auth or 'ghostscan vuln {addr}' if authorized.")
            if port_set & DB_PORTS:
                host_steps.append(f"Host {addr}: Database port(s) open. Run 'ghostscan service {addr}' for version; test only if authorized.")
            if not host.os_match:
                host_steps.append(f"Host {addr}: OS unknown. Run 'ghostscan os {addr}' (may need sudo) for OS fingerprint.")
            if not host_steps:
                host_steps.append(f"Host {addr}: Run 'ghostscan service {addr}' for service/version detection on open ports.")
        steps.extend(host_steps)
    return steps[:20]  # cap for readability


def _resolve_results_path(results_path: str) -> Path:
    """Resolve 'latest' to results/latest.json, otherwise return Path(results_path)."""
    s = results_path.strip().lower()
    if s == "latest":
        from ghostscan.config import RESULTS_DIR, LATEST_JSON
        return RESULTS_DIR / LATEST_JSON
    return Path(results_path)


def next_steps(results_path: str) -> bool:
    """
    Load result from path (JSON or XML), then print next-step recommendations.
    Use 'latest' for most recent run. Returns True if file was found and parsed.
    """
    path = _resolve_results_path(results_path)
    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        return False
    try:
        if path.suffix.lower() == ".json":
            result = load_result_from_json(path)
        else:
            from ghostscan.parser import parse_nmap_xml
            result = parse_nmap_xml(path)
    except Exception as e:
        console.print(f"[red]Could not load results:[/red] {e}")
        return False
    steps = _next_steps_from_result(result)
    if not steps:
        console.print("[yellow]No specific recommendations. Run 'ghostscan recommend' for general workflow.[/yellow]")
        return True
    console.print(Panel("\n".join(f"• {s}" for s in steps), title="Recommended next steps"))
    return True
