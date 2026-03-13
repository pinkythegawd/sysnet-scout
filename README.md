# SysNet Scout

Cross-platform System Information and Network Scanner Utility.

Made by GitHub user **pinkythegawd (MikePinku)**.

## Features

- Works on Windows, Linux, and Android (Termux)
- Local system information report
- Host discovery on a CIDR network using ping sweep
- TCP port scanner with configurable ranges and concurrency
- Top-port quick presets for fast scans
- Scan profile presets (`quick`, `web`, `full`)
- Live progress bars for host and port scans
- DNS and reverse-DNS resolver command
- Compare mode for baseline vs current scans
- Optional service fingerprinting (basic banner grabbing)
- Informational vulnerability hardening hints
- Built-in risk scoring (`low`, `medium`, `high`) with reasons
- Dedicated risk summary command for saved reports
- Interactive `start` command with guided menu
- One-command `demo` mode that generates showcase reports and dashboard
- Optional colorful terminal output and output export to file
- JSON, TXT, and HTML report export support
- No third-party runtime dependency required

## Requirements

- Python 3.8+

## Quick Start

### Windows one-click install (for beginners)

1. Open the project folder.
2. Double-click `install.bat`.
3. Wait for `[SUCCESS] SysNet Scout is ready.`
4. Then run commands using `scout.cmd`.

Example:

```bat
scout.cmd info --json
```

Running `scout.cmd` with no arguments opens a quick command menu.

### Linux and Termux one-click install

1. Open terminal in the project folder.
2. Make scripts executable.
3. Run install.sh once.
4. Use scout.sh for daily commands.

```bash
chmod +x install.sh scout.sh
./install.sh
./scout.sh info --json
```

Running `./scout.sh` with no arguments opens a quick command menu.

### Termux quick helper (recommended on Android)

Use the dedicated helper script to install Termux packages, request storage permission, and run the installer:

```bash
chmod +x termux-setup.sh install.sh scout.sh
./termux-setup.sh
./scout.sh info --json
```

### Run directly from source

```bash
python -m sysnet_scout info --json
```

If your package is in `src/`, use:

```bash
PYTHONPATH=src python -m sysnet_scout info --json
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH="src"; python -m sysnet_scout info --json
```

### Install as a command

```bash
pip install .
sysnet-scout info
```

### Windows easiest way (PowerShell and cmd)

Use the included launcher from the project root:

```powershell
.\scout.cmd info --json
.\scout.cmd scan-hosts --cidr 192.168.1.0/24 --json
.\scout.cmd scan-ports --host 192.168.1.1 --top 20
```

In cmd.exe:

```bat
scout.cmd info --json
scout.cmd resolve --target github.com --json
```

## Usage

### 1) System information

```bash
sysnet-scout info
sysnet-scout info --json
```

### 2) Scan live hosts in subnet

```bash
sysnet-scout scan-hosts --cidr 192.168.1.0/24
sysnet-scout scan-hosts --cidr 192.168.1.0/24 --timeout 1200 --workers 128 --json
```

### 3) Scan open TCP ports

```bash
sysnet-scout scan-ports --host 192.168.1.10 --ports 22,80,443
sysnet-scout scan-ports --host 192.168.1.10 --ports 1-1024 --timeout 0.3 --workers 300 --json
sysnet-scout scan-ports --host 192.168.1.10 --top 20
sysnet-scout scan-ports --host 192.168.1.10 --profile web
sysnet-scout scan-ports --host 192.168.1.10 --profile full
sysnet-scout scan-ports --host 192.168.1.10 --profile web --fingerprint --hints
```

### 4) Resolve domain/IP info

```bash
sysnet-scout resolve --target example.com --json
sysnet-scout resolve --target 8.8.8.8
```

### 5) Export output to file

```bash
sysnet-scout info --export reports/system_info.json
sysnet-scout scan-hosts --cidr 192.168.1.0/24 --export reports/hosts.txt
sysnet-scout scan-ports --host 192.168.1.10 --top 100 --export reports/ports.json
sysnet-scout scan-ports --host 192.168.1.10 --profile web --export reports/web_scan.html
```

- `--export` is an alias of `--save`.
- If export path ends with `.json`, JSON mode is enabled automatically.
- If export path ends with `.txt`, text mode is used (unless you explicitly pass `--json`).
- If export path ends with `.html`, a styled HTML report is generated.

### 6) Compare two scans (diff mode)

```bash
sysnet-scout compare --baseline reports/hosts_day1.json --current reports/hosts_day2.json --json
sysnet-scout compare --baseline reports/ports_old.json --current reports/ports_new.json --export reports/diff.html
```

### 7) Progress bar controls

- Progress bars are enabled automatically in interactive terminals for `scan-hosts` and `scan-ports`.
- Disable progress bars with `--no-progress`.

### 8) Fingerprint and hardening hints

- Add `--fingerprint` on `scan-ports` to attempt lightweight banner detection for open ports.
- Fingerprinting includes protocol-aware probes for common services:
	- HTTP/HTTPS-like ports: status line, server header, and HTML title when available
	- SSH: protocol banner
	- SMTP: greeting/EHLO response
	- Redis: basic `PING` response
- Add `--hints` on `scan-ports` to show informational hardening tips for common exposed services.
- These hints are guidance, not vulnerability proof.
- Port scans now include a risk object in output with score, level, and reasons.

Example:

```bash
sysnet-scout scan-ports --host 192.168.1.10 --profile web --fingerprint --hints --export reports/web_intel.html
```

### 9) Risk summary from saved report

```bash
sysnet-scout risk --report reports/ports.json --json
sysnet-scout risk --report reports/ports.json --export reports/risk_card.html
```

### 10) Risk trend across multiple reports

```bash
sysnet-scout risk-trend --reports reports/ports_day1.json reports/ports_day2.json reports/ports_day3.json --json
sysnet-scout risk-trend --reports reports/ports_day1.json reports/ports_day2.json --export reports/risk_trend.html
```

- Trend analysis auto-sorts reports by `timestamp` when available.
- Files without timestamps are kept in their input order.

### 11) Disable colors for plain terminal output

```bash
sysnet-scout --no-color info
```

### 12) Interactive Start Menu

```bash
sysnet-scout start
sysnet-scout start --choice info --json
```

- `start` opens a guided menu for quick usage.
- Use `--choice` for non-interactive automation.

### 13) Demo Mode (one command showcase)

```bash
sysnet-scout demo
sysnet-scout demo --json
```

- Demo mode runs safe local scans and generates sample artifacts in `reports/`.
- Includes JSON outputs plus `reports/demo_dashboard.html`.

## Termux Notes

- Install Python in Termux: `pkg install python`
- Some networks or Android restrictions may limit ICMP ping responses.
- If ping is blocked, port scanning still works normally.
- The `termux-setup.sh` script can automate package checks (`curl`, `wget`) and storage setup.

## VS Code Debug

- Launch profiles are included in `.vscode/launch.json`.
- Use Run and Debug and select one of:
	- `SysNet Scout: info`
	- `SysNet Scout: scan-hosts`
	- `SysNet Scout: scan-ports`

## Run Tests

This project uses Python's built-in `unittest` framework.

On Linux/Termux:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH="src"; python -m unittest discover -s tests -v
```

## Continuous Integration

- GitHub Actions workflow is defined in `.github/workflows/ci.yml`.
- Test matrix runs on Linux and Windows with Python 3.10, 3.11, and 3.12.
- The pipeline installs the package and runs:

```bash
python -m unittest discover -s tests -v
```

## Publishing Releases

- Release workflow is defined in `.github/workflows/release.yml`.
- It builds sdist and wheel, then publishes to PyPI when a GitHub Release is published.
- It uses PyPI Trusted Publishing via GitHub OIDC (no API token needed in workflow).

PyPI setup (one-time):

1. Create project `sysnet-scout` on PyPI (or claim the name if available).
2. In PyPI project settings, add a Trusted Publisher with:
	- Owner: your GitHub account or org
	- Repository: `CSINS by pinkythegawd`
	- Workflow name: `Release`
	- Environment: `pypi`
3. In GitHub repo settings, ensure Actions are enabled.
4. Create a GitHub Release to trigger publish.

## Disclaimer

Use only on systems and networks you own or are authorized to test.

## Troubleshooting (Windows)

- Problem: PowerShell says script execution is disabled for `scout.ps1`.
Fix: Use `scout.cmd` instead, or run PowerShell with execution policy bypass for that session.
- Problem: `'uv' is not recognized`.
Fix: Install uv with `powershell -ExecutionPolicy Bypass -c "irm https://astral.sh/uv/install.ps1 | iex"`.
- Problem: command not found for `sysnet_scout`.
Fix: Run from project root and use `scout.cmd ...` or `uv run --python 3.12 -m sysnet_scout ...`.
