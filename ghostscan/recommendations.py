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
            parts.append("\n[yellow]Recommended with sudo for best results.[/yellow]")
        else:
            parts.append(
                "\n[yellow]Recommended with sudo; this scan may not work or may be limited without root.[/yellow]"
            )
    else:
        parts.append("\n[dim]Runs without root.[/dim]")
    console.print(Panel("\n".join(parts), title="Scan explanation"))
    return True


def recommend_general() -> None:
    """Print general workflow recommendations (ghostscan recommend)."""
    table = Table(title="Suggested workflow", show_header=True, header_style="bold")
    table.add_column("Step", style="cyan")
    table.add_column("Command", style="green")
    table.add_column("When to use", style="white")
    table.add_row("1", "ghostscan discover <range>", "Find live hosts on a network (e.g. 192.168.1.0/24)")
    table.add_row("2", "ghostscan quick <ip>", "Quick check of common ports on a single host")
    table.add_row("3", "ghostscan service <ip>", "Identify services and versions on open ports")
    table.add_row("4", "ghostscan os <ip>", "Guess OS (run with sudo for best results)")
    table.add_row("—", "ghostscan profile web <ip>", "Focus on web ports and HTTP info")
    table.add_row("—", "ghostscan profile smb <ip>", "Focus on SMB and Windows-related info")
    table.add_row("", "ghostscan next latest", "Get next steps from your last scan (or use results/latest.json)")
    console.print(table)


def _open_ports(host: HostResult) -> List[PortInfo]:
    return [p for p in host.ports if p.state and p.state.lower() == "open"]


def _has_port(host: HostResult, port: int) -> bool:
    return any(p.port == port for p in _open_ports(host))


def _next_steps_from_result(result: ScanResult) -> List[str]:
    """Generate contextual next-step recommendations from a ScanResult (per-host)."""
    steps: List[str] = []
    for host in result.hosts:
        addr = host.address or "this host"
        open_ports = _open_ports(host)
        host_steps: List[str] = []
        if not open_ports:
            host_steps.append(f"Host {addr}: No open ports in this scan. Try 'ghostscan full {addr}' for all ports.")
        else:
            port_set = {p.port for p in open_ports}
            if 80 in port_set or 443 in port_set or 8080 in port_set or 8443 in port_set:
                host_steps.append(f"Host {addr}: Web ports open. Run 'ghostscan profile web {addr}' for HTTP details.")
            if 139 in port_set or 445 in port_set:
                host_steps.append(f"Host {addr}: SMB ports open. Run 'ghostscan profile smb {addr}' for SMB enumeration.")
            if not host.os_match:
                host_steps.append(f"Host {addr}: OS unknown. Run 'ghostscan os {addr}' (requires root) for OS fingerprint.")
            if not host_steps:
                host_steps.append(f"Host {addr}: Run 'ghostscan service {addr}' for service/version detection on open ports.")
        steps.extend(host_steps)
    return steps[:15]  # cap for readability


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
