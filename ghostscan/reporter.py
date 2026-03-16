"""Rich terminal output and report export.

Output is tuned for headless CLI (e.g. SSH to Kali); uses standard ANSI
and pathlib for clean, readable output in terminal sessions.
"""

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ghostscan.parser import HostResult, PortInfo, ScanResult

console = Console(force_terminal=True)  # assume terminal (SSH), no GUI


def _service_str(p: PortInfo) -> str:
    parts = [f"{p.port}/{p.protocol}", p.state]
    if p.service:
        parts.append(p.service)
    if p.product or p.version:
        parts.append(f"{p.product or ''} {p.version or ''}".strip())
    if p.extrainfo:
        parts.append(p.extrainfo)
    return " | ".join(parts)


def print_scan_summary(result: ScanResult, title: Optional[str] = None) -> None:
    """Print a Rich summary of a ScanResult."""
    title = title or "Scan results"
    console.print(Panel(f"[bold]{title}[/bold]", style="dim"))

    if not result.hosts:
        console.print("[yellow]No hosts found or no data.[/yellow]")
        return

    for host in result.hosts:
        addr = host.address or "unknown"
        name = f" ({host.hostname})" if host.hostname else ""
        console.print(f"\n[cyan]Host:[/cyan] {addr}{name}")
        if host.state:
            console.print(f"  State: {host.state}")
        if host.mac_address:
            mac_line = f"  MAC: {host.mac_address}"
            if host.mac_vendor:
                mac_line += f" ({host.mac_vendor})"
            console.print(mac_line)
        if host.os_match:
            console.print(f"  OS: {host.os_match}")

        if host.ports:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Port", style="cyan")
            table.add_column("State", style="green")
            table.add_column("Service / Version", style="white")
            for p in sorted(host.ports, key=lambda x: (x.port, x.protocol)):
                svc = f"{p.service or '-'}"
                if p.product or p.version:
                    svc += f" {p.product or ''} {p.version or ''}".strip()
                if p.extrainfo:
                    svc += f" ({p.extrainfo})"
                table.add_row(str(p.port), p.state, svc or "-")
            console.print(table)
        else:
            console.print("  [dim]No port data.[/dim]")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[red]Error:[/red] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[green]{message}[/green]")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[dim]{message}[/dim]")


def export_json(result: ScanResult, json_path: Path, scan_type: str = "") -> None:
    """Write ScanResult to JSON; set scan_type on result if provided."""
    if scan_type:
        result.scan_type = scan_type
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(result.to_json(), encoding="utf-8")
