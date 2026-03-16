"""GhostScan CLI – Typer app and commands."""

import shutil
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from ghostscan import __version__
from ghostscan.config import RUNTIME_ENV, RESULTS_DIR, LATEST_JSON
from ghostscan.history import record_scan, list_recent_scans
from ghostscan.parser import parse_nmap_xml, load_result_from_json
from ghostscan.recommendations import explain_scan, recommend_general, next_steps, has_web_ports, _next_steps_from_result
from ghostscan.reporter import export_json, print_error, print_info, print_scan_summary, print_success
from ghostscan.runtime import is_running_as_root, ensure_results_dir_ok
from ghostscan.scanner import run_scan, get_scan_def
from ghostscan.validation import validate_target, validate_target_list

console = Console(force_terminal=True)

app = typer.Typer(
    name="ghostscan",
    help="Guided Nmap CLI for reconnaissance and inventory. Safe, clear, and beginner-friendly.",
    no_args_is_help=True,
)


def _target_callback(value: str) -> str:
    err = validate_target(value)
    if err:
        raise typer.BadParameter(err)
    return value


def _run_and_report(
    target: str,
    scan_type: str,
    save_as_latest: bool = True,
) -> None:
    """Run scan, parse XML, export JSON, print summary, optionally link as latest."""
    scan_def = get_scan_def(scan_type)
    if not scan_def:
        typer.echo(f"Unknown scan type: {scan_type}", err=True)
        raise typer.Exit(1)
    # Root warning only when not already root
    if getattr(scan_def, "requires_root", False) and not is_running_as_root():
        print_info(
            "[yellow]This scan may require root. If you get permission errors (e.g. opening wlan0), run:[/yellow]"
        )
        print_info(f"[yellow]  sudo ghostscan {scan_type.replace(':', ' ')} {target}[/yellow]")
    try:
        ensure_results_dir_ok(RESULTS_DIR)
    except RuntimeError as e:
        print_error(str(e))
        raise typer.Exit(1)
    print_info(f"Running {scan_def.name} against {target}...")
    try:
        with console.status(f"[dim]Scanning...[/dim]", spinner="dots"):
            xml_path, json_path, proc = run_scan(target, scan_type)
    except FileNotFoundError:
        print_error("Nmap not found. Install Nmap and ensure it is on your PATH.")
        raise typer.Exit(1)
    except subprocess.TimeoutExpired:
        print_error("Scan timed out.")
        raise typer.Exit(1)
    except RuntimeError as e:
        print_error(str(e))
        raise typer.Exit(1)
    if proc.returncode != 0:
        print_error(f"Nmap exited with code {proc.returncode}.")
        stderr = (proc.stderr or "").strip()
        if stderr:
            print_error(stderr)
        if "Permission" in stderr or "raw" in stderr.lower() or "socket" in stderr.lower():
            print_info("[dim]Hint: Try running with sudo if this scan requires raw sockets.[/dim]")
        raise typer.Exit(1)
    try:
        result = parse_nmap_xml(xml_path)
    except ValueError as e:
        print_error(f"Failed to parse Nmap output: {e}")
        raise typer.Exit(1)
    result.target = target
    export_json(result, json_path, scan_type=scan_type)
    if save_as_latest:
        latest = RESULTS_DIR / LATEST_JSON
        shutil.copy(json_path, latest)
        print_info(f"Results saved to {json_path} and {latest}")
    else:
        print_info(f"Results saved to {json_path}")
    record_scan(target, scan_type)
    print_scan_summary(result, title=scan_def.name)
    typer.echo("")
    print_info("Tip: run 'ghostscan next latest' for recommended next steps.")


@app.command()
def discover(
    target: str = typer.Argument(..., callback=_target_callback, help="IP, hostname, or CIDR (e.g. 192.168.1.0/24)"),
) -> None:
    """Find live hosts (no port scan). May require sudo depending on environment."""
    _run_and_report(target, "discover")


@app.command()
def quick(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """Quick scan of common ports (-Pn -sT). Designed to work without sudo."""
    _run_and_report(target, "quick")


@app.command()
def full(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """Scan all 65535 ports (-Pn -sT). Designed to work without sudo."""
    _run_and_report(target, "full")


@app.command()
def service(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """Detect service and version on open ports (-Pn -sT). Designed to work without sudo."""
    _run_and_report(target, "service")


@app.command()
def os(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """Guess operating system. May require sudo depending on environment."""
    _run_and_report(target, "os")


profile_app = typer.Typer(help="Pre-built scan profiles (web, smb); work without sudo.")
app.add_typer(profile_app, name="profile")


@profile_app.command("web")
def profile_web(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """Web ports and HTTP scripts (-Pn -sT). Designed to work without sudo."""
    _run_and_report(target, "profile:web")


@profile_app.command("smb")
def profile_smb(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """SMB ports and enumeration scripts (-Pn -sT). Designed to work without sudo."""
    _run_and_report(target, "profile:smb")


@app.command()
def vuln(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """Vulnerability scan (NSE vuln scripts). Only on authorized targets."""
    _run_and_report(target, "vuln")


@app.command()
def recon(
    target: str = typer.Argument(..., callback=_target_callback, help="Single IP or hostname"),
) -> None:
    """Run recon chain: quick → service → web profile if web ports found."""
    try:
        ensure_results_dir_ok(RESULTS_DIR)
    except RuntimeError as e:
        print_error(str(e))
        raise typer.Exit(1)
    scan_def_quick = get_scan_def("quick")
    scan_def_svc = get_scan_def("service")
    scan_def_web = get_scan_def("profile:web")
    if not all((scan_def_quick, scan_def_svc, scan_def_web)):
        print_error("Missing scan definitions.")
        raise typer.Exit(1)
    result = None
    with console.status("[dim]Quick scan...[/dim]", spinner="dots"):
        xml_path, json_path, proc = run_scan(target, "quick")
    if proc.returncode != 0:
        print_error(f"Quick scan failed (exit {proc.returncode}).")
        if proc.stderr:
            print_error(proc.stderr.strip())
        raise typer.Exit(1)
    result = parse_nmap_xml(xml_path)
    result.target = target
    export_json(result, json_path, scan_type="quick")
    print_success("Quick scan complete")
    with console.status("[dim]Service detection...[/dim]", spinner="dots"):
        xml_path2, json_path2, proc2 = run_scan(target, "service")
    if proc2.returncode != 0:
        print_error(f"Service detection failed (exit {proc2.returncode}).")
        print_scan_summary(result, title="Quick scan results")
        raise typer.Exit(1)
    result = parse_nmap_xml(xml_path2)
    result.target = target
    export_json(result, json_path2, scan_type="service")
    print_success("Service detection complete")
    web_detected = any(has_web_ports(h) for h in result.hosts)
    if web_detected:
        print_info("Web service detected. Running web enumeration profile...")
        with console.status("[dim]Web profile...[/dim]", spinner="dots"):
            xml_path3, json_path3, proc3 = run_scan(target, "profile:web")
        if proc3.returncode == 0:
            result = parse_nmap_xml(xml_path3)
            result.target = target
            export_json(result, json_path3, scan_type="profile:web")
            shutil.copy(json_path3, RESULTS_DIR / LATEST_JSON)
            print_success("Web profile complete")
        else:
            print_error("Web profile failed; service results still saved.")
            shutil.copy(json_path2, RESULTS_DIR / LATEST_JSON)
    else:
        shutil.copy(json_path2, RESULTS_DIR / LATEST_JSON)
    record_scan(target, "recon")
    print_scan_summary(result, title="Recon results")
    steps = _next_steps_from_result(result)
    if steps:
        console.print()
        from rich.panel import Panel
        console.print(Panel("\n".join(f"• {s}" for s in steps[:10]), title="Recommended next steps"))
    print_info("Recon workflow complete.")


@app.command("map")
def map_cmd(
    target: str = typer.Argument(..., callback=_target_callback, help="CIDR range (e.g. 192.168.1.0/24)"),
) -> None:
    """Discover hosts, then quick + service scan; build network inventory."""
    from ghostscan.validation import is_valid_cidr
    if not is_valid_cidr(target):
        print_error("map requires a CIDR range (e.g. 192.168.1.0/24).")
        raise typer.Exit(1)
    try:
        ensure_results_dir_ok(RESULTS_DIR)
    except RuntimeError as e:
        print_error(str(e))
        raise typer.Exit(1)
    print_info("Step 1/3: Host discovery...")
    with console.status("[dim]Discovering hosts...[/dim]", spinner="dots"):
        xml_d, json_d, proc_d = run_scan(target, "discover")
    if proc_d.returncode != 0:
        print_error("Host discovery failed. Try with sudo for raw socket access.")
        if proc_d.stderr:
            print_error(proc_d.stderr.strip())
        raise typer.Exit(1)
    discover_result = parse_nmap_xml(xml_d)
    hosts = [h for h in discover_result.hosts if h.address and h.state and h.state.lower() == "up"]
    if not hosts:
        print_info("No hosts found.")
        raise typer.Exit(0)
    addrs = [h.address for h in hosts]
    target_str = " ".join(addrs)
    err = validate_target_list(target_str)
    if err:
        print_error(err)
        raise typer.Exit(1)
    print_success(f"Discovered {len(addrs)} host(s)")
    print_info("Step 2/3: Quick port scan on discovered hosts...")
    with console.status("[dim]Quick scan...[/dim]", spinner="dots"):
        xml_q, json_q, proc_q = run_scan(target_str, "quick", base_name=f"map_quick_{target.replace('/', '_')}")
    if proc_q.returncode != 0:
        print_error("Quick scan failed.")
        raise typer.Exit(1)
    quick_result = parse_nmap_xml(xml_q)
    print_info("Step 3/3: Service detection...")
    with console.status("[dim]Service detection...[/dim]", spinner="dots"):
        xml_s, json_s, proc_s = run_scan(target_str, "service", base_name=f"map_service_{target.replace('/', '_')}")
    if proc_s.returncode != 0:
        inventory = quick_result
        print_info("Service detection failed; showing quick-scan results.")
    else:
        inventory = parse_nmap_xml(xml_s)
    from rich.table import Table
    # Build table from parsed inventory (one row per host with address)
    rows_hosts = [h for h in inventory.hosts if h.address]
    if not rows_hosts:
        print_error("No hosts in scan output. Check that quick/service XML was parsed (Nmap may use XML namespace).")
        print_scan_summary(inventory, title="Raw parsed result")
    else:
        table = Table(title="Discovered hosts", show_header=True, header_style="bold")
        table.add_column("Address", style="cyan")
        table.add_column("Hostname", style="green")
        table.add_column("Open ports / services", style="white")
        for h in rows_hosts:
            addr = h.address or "?"
            name = h.hostname or ""
            open_ports = [p for p in h.ports if p.state and p.state.lower() == "open"]
            ports_svc = ", ".join(
                f"{p.port}({p.service or '?'})" for p in sorted(open_ports, key=lambda x: x.port)[:15]
            )
            if not ports_svc:
                ports_svc = "(none)"
            table.add_row(addr, name, ports_svc)
        console.print(table)
    export_json(inventory, RESULTS_DIR / "map_latest.json", scan_type="map")
    record_scan(target, "map")
    print_success("Network map complete.")


@app.command()
def explain(
    scan_type: str = typer.Argument(..., help="e.g. quick, full, discover, service, os, profile web, vuln"),
) -> None:
    """Explain what a scan does and how visible it is."""
    if not explain_scan(scan_type):
        print_error(
            f"Unknown scan type: '{scan_type}'. "
            "Use quick, full, discover, service, os, profile web, profile smb, vuln."
        )


@app.command()
def recommend() -> None:
    """Show recommended reconnaissance workflow."""
    recommend_general()


@app.command()
def history(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of recent scans to show"),
) -> None:
    """Show recent scan history (target and scan type)."""
    from rich.table import Table
    entries = list_recent_scans(limit=limit)
    if not entries:
        print_info("No scan history yet. Run a scan to record it.")
        return
    table = Table(title="Recent scans", show_header=True, header_style="bold")
    table.add_column("Target", style="cyan")
    table.add_column("Scan type", style="green")
    table.add_column("Time (UTC)", style="dim")
    for e in entries:
        table.add_row(
            e.get("target", "?"),
            e.get("scan_type", "?"),
            e.get("timestamp", "?")[:19].replace("T", " "),
        )
    console.print(table)


@app.command()
def interactive(
    target: str = typer.Argument(..., callback=_target_callback, help="IP or hostname to recon"),
) -> None:
    """Menu-driven recon: choose quick, service, web, os, or vuln scan."""
    menu = (
        "Select next action:\n"
        "  1) Quick scan\n"
        "  2) Service detection\n"
        "  3) Web enumeration\n"
        "  4) OS fingerprinting\n"
        "  5) Vulnerability scan\n"
        "  q) Quit\n"
    )
    while True:
        try:
            choice = input(menu + "Choice [1-5 or q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Exiting.[/dim]")
            raise typer.Exit(0)
        if choice == "q":
            break
        if choice == "1":
            _run_and_report(target, "quick")
        elif choice == "2":
            _run_and_report(target, "service")
        elif choice == "3":
            _run_and_report(target, "profile:web")
        elif choice == "4":
            _run_and_report(target, "os")
        elif choice == "5":
            _run_and_report(target, "vuln")
        else:
            print_info("Invalid choice. Enter 1-5 or q.")


@app.command("next")
def next_cmd(
    results_file: str = typer.Argument(..., help="Path to results JSON/XML, or 'latest' for most recent"),
) -> None:
    """Recommend next steps based on scan results."""
    next_steps(results_file)


report_app = typer.Typer(help="View or export reports.")
app.add_typer(report_app, name="report")


@report_app.command("show")
def report_show(
    which: str = typer.Argument("latest", help="'latest' or path to a results file"),
) -> None:
    """Show scan summary. Use 'latest' for most recent run."""
    path = Path(which)
    if which.strip().lower() == "latest":
        path = RESULTS_DIR / LATEST_JSON
    if not path.exists():
        print_error(f"Results file not found: {path}")
        raise typer.Exit(1)
    try:
        if path.suffix.lower() == ".json":
            result = load_result_from_json(path)
        else:
            result = parse_nmap_xml(path)
    except Exception as e:
        print_error(f"Could not load results: {e}")
        raise typer.Exit(1)
    print_scan_summary(result, title="Report")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"ghostscan {__version__}")
        typer.echo(f"  runtime: {RUNTIME_ENV['platform']} | Python {RUNTIME_ENV['python']} | Nmap {RUNTIME_ENV['nmap']} | {RUNTIME_ENV['usage']}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(None, "--version", "-v", callback=_version_callback, is_eager=True),
) -> None:
    """GhostScan – guided Nmap reconnaissance. Use only on authorized networks."""
    pass


