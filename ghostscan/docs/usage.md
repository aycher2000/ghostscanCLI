# GhostScan Usage Guide

GhostScan is a guided command-line reconnaissance tool that wraps Nmap in a structured workflow.

It simplifies network scanning by automating common reconnaissance steps and suggesting logical next actions.

GhostScan is designed to run cleanly from a headless terminal (for example over SSH on Kali Linux).

---

# Installation

Clone the repository:

```bash
git clone https://github.com/<your-repo>/ghostscanCLI.git
cd ghostscanCLI
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the CLI:

```bash
pip install -e .
```

Test installation:

```bash
ghostscan --help
```

You should see the available commands.

---

# Basic Recon Workflow

Typical reconnaissance workflow:

```
quick → service → profile → next
```

Example:

```bash
ghostscan quick <target>
ghostscan service <target>
ghostscan profile web <target>
ghostscan next results/latest.json
```

GhostScan will guide the user toward deeper scans based on discovered services.

---

# Commands

## Quick Scan

Runs a fast scan of common ports using TCP connect scanning.

```bash
ghostscan quick <target>
```

Example:

```bash
ghostscan quick scanme.nmap.org
```

Output includes:

- open ports
- detected services
- saved JSON results
- recommended next steps

Example output:

```
Host: 45.33.32.156 (scanme.nmap.org)

Port  State  Service
22    open   ssh
80    open   http
```

---

## Service Detection

Identifies versions of detected services.

```bash
ghostscan service <target>
```

Example:

```bash
ghostscan service scanme.nmap.org
```

Example output:

```
Port  State  Service / Version
22    open   ssh OpenSSH 6.6
80    open   http Apache httpd 2.4
```

---

## Web Enumeration Profile

Runs web-focused scripts to gather information about web services.

```bash
ghostscan profile web <target>
```

Example:

```bash
ghostscan profile web scanme.nmap.org
```

This profile may gather:

- HTTP title
- server headers
- HTTP methods
- technology hints

---

## Next Step Recommendation

GhostScan can analyze scan results and suggest logical next steps.

```bash
ghostscan next results/latest.json
```

Example output:

```
Recommended next steps

Web ports detected.

Run:
ghostscan profile web <target>

For OS fingerprinting:
ghostscan os <target> (requires root)
```

---

## OS Detection

Attempts to detect the operating system of the target.

This scan often requires root privileges.

```bash
sudo ghostscan os <target>
```

Example:

```bash
sudo ghostscan os scanme.nmap.org
```

---

## Host Discovery

Find live hosts on a network.

```bash
ghostscan discover <target>
```

Example:

```bash
ghostscan discover 192.168.1.0/24
```

This identifies which hosts are online before deeper scanning.

---

# Output Files

GhostScan saves results to the `results/` directory.

Example files:

```
results/quick_scanme_2026.json
results/service_scanme_2026.json
results/profile_web_scanme_2026.json
```

A special file is also maintained:

```
results/latest.json
```

This always contains the most recent scan results.

---

# Typical Usage Example

Example recon session:

```bash
ghostscan quick scanme.nmap.org
ghostscan service scanme.nmap.org
ghostscan profile web scanme.nmap.org
ghostscan next results/latest.json
```

This produces a progressive reconnaissance workflow.

---

# Tips

Start with **quick scans** and escalate only when needed.

Typical recon escalation:

```
quick
service
profile web
os detection
vulnerability scans
```

GhostScan helps automate this logic.

---

# Safety

Only run GhostScan against networks and systems you are authorized to scan.

Unauthorized scanning may violate laws or network policies.