"""GhostScan CLI – Typer app and commands."""

import subprocess
from pathlib import Path
from typing import Optional

import typer

from ghostscan import __version__
from ghostscan.config import RUNTIME_ENV
from ghostscan.config import RESULTS_DIR, LATEST_JSON
from ghostscan.parser import parse_nmap_xml, load_result_from_json
from ghostscan.recommendations import explain_scan, recommend_general, next_steps
from ghostscan.reporter import export_json, print_error, print_info, print_scan_summary, print_success
from ghostscan.scanner import run_scan, get_scan_def, SCAN_DEFS
from ghostscan.validation import validate_target

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
    if getattr(scan_def, "requires_root", False):
        print_info(
            "[yellow]Note: This scan may require sudo depending on the environment. "
            "If you get permission errors (e.g. opening wlan0), try running with sudo.[/yellow]"
        )
    print_info(f"Running {scan_def.name} against {target}...")
    try:
        xml_path, json_path, proc = run_scan(target, scan_type)
    except FileNotFoundError:
        print_error("Nmap not found. Install Nmap and ensure it is on your PATH.")
        raise typer.Exit(1)
    except subprocess.TimeoutExpired:
        print_error("Scan timed out.")
        raise typer.Exit(1)
    if proc.returncode != 0:
        print_error(f"Nmap exited with code {proc.returncode}.")
        if proc.stderr:
            print_error(proc.stderr.strip())
        raise typer.Exit(1)
    result = parse_nmap_xml(xml_path)
    result.target = target  # ensure saved JSON has the target we scanned
    export_json(result, json_path, scan_type=scan_type)
    if save_as_latest:
        latest = RESULTS_DIR / LATEST_JSON
        # Write path or copy content so "report show latest" and "next latest" work
        import shutil
        shutil.copy(json_path, latest)
        print_info(f"Results saved to {json_path} and {latest}")
    else:
        print_info(f"Results saved to {json_path}")
    print_scan_summary(result, title=scan_def.name)
    typer.echo("")
    print_info("Tip: run 'ghostscan next results/latest.json' for recommended next steps.")


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
def explain(
    scan_type: str = typer.Argument(..., help="e.g. quick, full, discover, profile web, profile smb"),
) -> None:
    """Explain what a scan does and how visible it is."""
    if not explain_scan(scan_type):
        print_error(f"Unknown scan type: '{scan_type}'. Use quick, full, discover, service, os, profile web, profile smb.")


@app.command()
def recommend() -> None:
    """Show recommended reconnaissance workflow."""
    recommend_general()


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


