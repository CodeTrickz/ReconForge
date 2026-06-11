# ReconForge Quick Start Guide

## Installation

### 1. Prerequisites
- Python 3.9 or later
- pip package manager
- Git (optional, for cloning)

### 2. Clone or Download
```bash
cd ReconForge
```

### 3. Install in Development Mode

Install ReconForge with all dependencies:
```bash
pip install -e .
```

To also install development dependencies (testing, linting):
```bash
pip install -e ".[dev]"
```

### 4. Verify Installation

Check that the CLI is available:
```bash
reconforge --help
```

You should see the help menu with available commands.

## Basic Usage Examples

ReconForge keeps a cumulative results store at `.reconforge/session/results.json`. You can run several authorized reconnaissance commands and then generate one combined report:

```bash
reconforge scan 192.168.1.0/24
reconforge ports 192.168.1.10
reconforge banner 192.168.1.10 --port 22
reconforge http example.com --port 443 --https
reconforge results
reconforge report
```

Reports are written to `reports/reconforge_report_<YYYYMMDD_HHMMSS>.html` or `.json`. Use `reconforge report --clear` after a successful report, or `reconforge clear-results`, when you want to reset the session.

Reports include informational low/medium/high risk tags for observed metadata such as open ports, banners, TLS certificate expiry, and missing HTTP security headers. These are defensive review hints only and do not involve exploit logic.

CLI note: `scan`, `ports`, `banner`, and `http` now support `--dry-run` and `--scope-file`. Console output also uses richer progress and summary tables.
Migration note: command names stay the same. A fresh `pip install -e .` now installs `rich` as part of the normal runtime dependencies.

### Example 1: Scan Your Local Network (192.168.1.0/24)

```bash
# Basic scan with host discovery
reconforge scan 192.168.1.0/24

# Scan with specific ports
reconforge scan 192.168.1.0/24 --ports 22,80,443

# Save an explicit JSON copy if needed
reconforge scan 192.168.1.0/24 --json-output results.json

# Successful commands are also appended automatically to:
# .reconforge/session/results.json
```

### Example 2: Scan Specific Host for Common Ports

```bash
# Scan default common ports
reconforge ports 192.168.1.100

# Scan custom port list
reconforge ports 192.168.1.100 --ports 22,80,443,3306,5432

# Scan port range
reconforge ports 192.168.1.100 --ports 1-1024

# Save to JSON
reconforge ports 192.168.1.100 --json-output ports.json
```

Port scans use async TCP connect checks with bounded concurrency; `--workers` controls the maximum number of concurrent connection attempts.

### Authorized Scope Files and Dry Runs

```bash
# Validate a target against an authorized scope file without touching the network
reconforge scan 192.168.1.0/24 --scope-file authorized.txt --dry-run

# Scope files can contain IPv4 hosts, CIDRs, or resolvable hostnames
reconforge http internal.example.com --https --scope-file authorized.txt --dry-run
```

Each scope file should contain one authorized host, CIDR, or hostname per line. Targets outside that scope are refused before any network activity starts.

### Example 3: Grab Service Banners

```bash
# Grab banner from SSH service
reconforge banner 192.168.1.100 --port 22

# Grab from multiple ports
reconforge banner 192.168.1.100 --port 22 --port 80 --port 443

# Save to JSON
reconforge banner 192.168.1.100 --port 22 --port 80 --json-output banners.json
```

### Example 4: Analyze HTTP/TLS Configuration

```bash
# Check authorized HTTP/TLS metadata with HEAD requests only
reconforge http example.com --port 443 --https

# Save an explicit JSON copy if needed
reconforge http example.com --port 443 --https --json-output http_tls.json
```

### Example 5: Review Stored Results and Generate Reports

```bash
# Show the current cumulative session summary
reconforge results

# Generate a timestamped HTML report under reports/
reconforge report

# Generate timestamped JSON under reports/
reconforge report --format json

# Generate a report and clear .reconforge/session/results.json after success
reconforge report --clear

# Clear manually
reconforge clear-results
reconforge clear-results --yes
```

### Example 6: Import and Compare Stored Results

```bash
# Initialize the SQLite snapshot database
reconforge db init

# Import cumulative JSON files as snapshots
reconforge db import .reconforge/session/results.json
reconforge db import previous_results.json

# Compare imported snapshot IDs
reconforge compare --baseline 1 --current 2
```

The compare command reports newly opened ports, closed ports, changed banners, and changed TLS certificate metadata. It does not scan targets; it only compares imported results.

Notes:
- Existing scan, port, banner, HTTP, JSON report, and HTML report commands keep their current behavior.
- SQLite snapshots are stored in `.reconforge/reconforge.db`.
- Existing cumulative results JSON files do not need migration; import them with `reconforge db import` when you want to compare snapshots.

## Advanced Examples

### Detailed Network Scan with Custom Settings

```bash
# Scan with custom timeout and worker threads
reconforge scan 192.168.1.0/24 \
  --timeout 5 \
  --workers 20 \
  --ports 22,80,443,3306,5432,8080
reconforge report
```

### Skip Host Discovery (scan only specified targets)

```bash
# If you already know which hosts are alive, skip ping sweep
reconforge scan 192.168.1.1 \
  --skip-discovery \
  --json-output direct_scan.json
```

### Test on Localhost

```bash
# Safe test: scan your own machine
reconforge scan 127.0.0.1

# Or with specific ports
reconforge scan 127.0.0.1 --ports 22,80,443
```

## Configuration

### Environment Variables

```bash
# Set log level to DEBUG for verbose output
export RECONFORGE_LOG_LEVEL=DEBUG
reconforge scan 192.168.1.0/24

# Set custom log directory
export RECONFORGE_LOG_DIR=/tmp/reconforge_logs
reconforge scan 192.168.1.0/24
```

## Running Tests

If you installed with dev dependencies:

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=reconforge

# Run specific test file
pytest tests/test_targets.py

# Run specific test
pytest tests/test_targets.py::TestTargetParser::test_parse_single_ipv4
```

## Troubleshooting

### Command Not Found
If `reconforge` command is not found after installation:
```bash
# Try with python module
python -m reconforge.cli --help

# Or reinstall
pip install -e .
```

### Permission Denied (on Linux/macOS)
For ping sweep functionality, you may need elevated privileges:
```bash
# Run with sudo if needed
sudo reconforge scan 192.168.1.0/24
```

### Timeout Errors
Increase timeout if you're on a slow network:
```bash
reconforge scan 192.168.1.0/24 --timeout 5
```

### Connection Refused
Not all ports will be open. This is normal behavior. Increase workers for faster scanning:
```bash
reconforge scan 192.168.1.0/24 --workers 20
```

For port scanning, `--workers` changes concurrency only. ReconForge still uses normal TCP connect checks and does not use raw packets, stealth scans, evasion, or exploit payloads.

## Output Files

- **Cumulative Store**: `.reconforge/session/results.json`
- **SQLite Snapshots**: `.reconforge/reconforge.db`
- **Timestamped Reports**: `reports/reconforge_report_<YYYYMMDD_HHMMSS>.html` or `.json`
- **Risk Tags**: Stored per result under `risk_tags`, with summary counts in report JSON
- **Explicit JSON Output**: Optional command-specific files from `--json-output`
- **Explicit HTML Output**: Optional command-specific files from `--html-output`
- **Logs**: Found in `logs/` directory (configurable via environment variable)

## Legal Compliance Checklist

Before running scans:
- ✓ Verify target ownership or written authorization
- ✓ Inform system/network administrators
- ✓ Review local laws regarding network scanning
- ✓ Test on your own lab network first
- ✓ Review ReconForge source code for security assessment

## Next Steps

1. Review the [README.md](README.md) for complete documentation
2. Check [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design decisions
3. Review source code in `reconforge/` for implementation details
4. Run tests to verify your environment
5. Start with localhost scans for practice

---

**Remember**: Always get written authorization before scanning any system or network you don't own.
