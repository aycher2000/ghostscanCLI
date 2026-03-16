# GhostScan

A guided command-line reconnaissance and inventory tool that wraps Nmap in a clean, beginner-friendly workflow. Built for use with Kali Linux over SSH; headless CLI only.

**Use only on networks you are authorized to scan.**

---

## Features

- **Host discovery** – Find live hosts on a network (no port scan)
- **Port scanning** – Quick, full, and service-oriented scans
- **Service/version detection** – Identify running services and versions
- **OS fingerprinting** – Guess remote OS (run with `sudo` for best results)
- **Profiles** – Pre-built scans for web and SMB using confirmed NSE scripts
- **Explanations** – Understand what each scan does, visibility, and when to use it
- **Recommendations** – Per-host next-step suggestions from scan results
- **Report export** – JSON and Rich terminal summaries

---

## Runtime

- **Platform:** Kali GNU/Linux Rolling 2026.1  
- **Python:** 3.13+  
- **Nmap:** 7.98  
- **Usage:** Remote SSH from a Mac (or other) terminal; headless CLI only  

Paths are relative to the current working directory and Linux-safe.

---

## Requirements

- Python 3.11+
- Nmap installed and on `PATH` (e.g. default on Kali)

---

## Install

```bash
pip install -r requirements.txt
pip install -e .
```

Check version and runtime:

```bash
ghostscan --version
```

---

## Usage

### Scan commands

| Command | Description |
|--------|-------------|
| `ghostscan discover <target>` | Host discovery (e.g. `192.168.1.0/24`) |
| `ghostscan quick <target>` | Quick scan of common ports |
| `ghostscan full <target>` | All 65535 ports |
| `ghostscan service <target>` | Service/version detection |
| `ghostscan os <target>` | OS fingerprinting (sudo recommended) |
| `ghostscan profile web <target>` | Web ports + http-title, http-server-header, http-methods |
| `ghostscan profile smb <target>` | SMB ports + smb-os-discovery, smb2-capabilities, smb-security-mode |

### Help and workflow

| Command | Description |
|--------|-------------|
| `ghostscan explain <scan>` | Explain a scan (e.g. `quick`, `profile web`) and visibility |
| `ghostscan recommend` | Suggested reconnaissance workflow |
| `ghostscan next latest` | Next steps from your last scan (or use `results/latest.json`) |
| `ghostscan report show latest` | Show summary of latest results |

### Examples

```bash
ghostscan discover 192.168.1.0/24
ghostscan quick 192.168.1.10
ghostscan service 192.168.1.10
ghostscan profile web 192.168.1.10
ghostscan profile smb 192.168.1.50
ghostscan explain quick
ghostscan recommend
ghostscan next latest
ghostscan report show latest
```

Target can be a single IP, hostname, or CIDR range where appropriate.

---

## Privileges

Most scans run without root. For **OS fingerprinting** (`ghostscan os`), root/sudo is recommended for best results; the tool warns but does not require it. Run with `sudo ghostscan os <target>` if you get permission errors.

---

## Project layout

```
ghostscan/
  cli.py           # Typer CLI and commands
  scanner.py      # Nmap execution and scan definitions
  parser.py       # XML/JSON parsing
  reporter.py     # Rich output and export
  recommendations.py  # Explain and next-step logic
  validation.py   # Target validation
  config.py       # Paths and runtime metadata
results/          # Scan output (created on first run)
```

---

## License

MIT (see [LICENSE](LICENSE)). Use responsibly and only on authorized networks.
