# ReconForge

A legal, modular cybersecurity reconnaissance toolkit for authorized pentests, homelabs, CTFs, and internal security audits.

## Legal Use

**CRITICAL: Use ReconForge ONLY on systems and networks for which you have explicit written authorization.**

ReconForge is designed for authorized security testing and reconnaissance purposes only. Unauthorized access to computer networks is **illegal** in virtually all jurisdictions. The authors and contributors are **not responsible** for any misuse or damage caused by this tool.

**Legal Requirements Before Use:**
1. ✅ Obtain **written authorization** from the system/network owner
2. ✅ Verify you own the systems being tested
3. ✅ Review **local laws and regulations** regarding network scanning
4. ✅ Inform system administrators of testing activities
5. ✅ Use only in authorized environments (own lab, authorized pentest, CTF, etc.)

### What ReconForge Is & Isn't

**Authorized Use Cases:**
- ✅ Authorized penetration testing with explicit written permission
- ✅ Internal security audits within your organization
- ✅ Personal homelabs and lab networks
- ✅ Capture The Flag (CTF) competitions
- ✅ Educational testing in controlled environments
- ✅ Responsible vulnerability research

**NOT Permitted:**
- ❌ Unauthorized network scanning
- ❌ Scanning networks without permission
- ❌ Probing third-party systems without authorization
- ❌ Illegal data gathering or privacy violations
- ❌ Testing competitor networks
- ❌ Any illegal activity

---

## Features

ReconForge v0.1 focuses on **safe, legal reconnaissance and reporting**:

### Reconnaissance Capabilities
- **Host Discovery**: Platform-aware ping sweep for active host detection
- **Port Scanning**: Async TCP connect scanning with bounded concurrency (no raw packets, no stealth)
- **Banner Grabbing**: Safe service identification through banner analysis
- **HTTP/TLS Analysis**: Passive status, redirect, security header, and certificate checks
- **Risk Tagging**: Informational low/medium/high tags for observed metadata
- **Target Parsing**: Support for IPv4 addresses, CIDR ranges, and hostnames
- **Report Generation**: JSON export and beautiful HTML reports

### Why This Approach?
- **No Exploitation**: Zero exploit code
- **No Bruteforce**: Single TCP connect attempt per port
- **No Stealth**: Visible connections for audit trails
- **No Evasion**: Direct connections without IDS/IPS bypass
- **No Credentials**: No credential harvesting
- **No Persistence**: No system modification

---

## Quickstart

### Installation

```bash
# Clone or download the repository
cd ReconForge

# Install with dependencies
pip install -e .

# Verify installation
reconforge --help
```

### Basic Commands

```bash
# Discover live hosts on a network
reconforge scan 192.168.1.0/24

# Scan specific ports on a target
reconforge ports 192.168.1.100 --ports 22,80,443

# Grab service banners
reconforge banner 192.168.1.100 --port 22

# Check authorized HTTP/TLS configuration
reconforge http example.com --port 443 --https

# View cumulative results and generate a timestamped report
reconforge results
reconforge report
```

ReconForge automatically appends successful reconnaissance results to `.reconforge/session/results.json`. Running `reconforge report` without arguments generates a cumulative report in `reports/reconforge_report_<YYYYMMDD_HHMMSS>.html`.

Reports include informational risk tags derived only from observed metadata such as open ports, banners, TLS certificate dates, and missing HTTP security headers. These tags are defensive review hints, not exploit checks.

Migration note: no CLI commands or flags changed. JSON and HTML reports now include additional risk tag fields and sections.

---

## Commands

### `reconforge scan <TARGET>`

Perform full reconnaissance on a target network or host.

**Options:**
- `--timeout SECONDS` - Connection timeout (default: 2.0)
- `--workers N` - Number of parallel workers (default: 5)
- `--ports LIST` - Specific ports to scan (default: common 15 ports)
- `--skip-discovery` - Skip ping sweep, scan only specified targets
- `--json-output FILE` - Save results as JSON
- `--html-output FILE` - Generate HTML report

**Examples:**
```bash
# Scan network with defaults
reconforge scan 192.168.1.0/24

# Scan with custom ports and reporting
reconforge scan 192.168.1.0/24 \
  --ports 22,80,443,3306 \
  --json-output results.json \
  --html-output report.html

# Scan with longer timeout for slow networks
reconforge scan 192.168.1.0/24 --timeout 5

# Skip discovery, scan directly
reconforge scan 192.168.1.1 --skip-discovery
```

### `reconforge ports <HOST>`

Scan for open ports on a specific target.

The public CLI is unchanged. Internally, port scans use `asyncio` with bounded concurrency; `--workers` controls the maximum number of concurrent TCP connect attempts.

**Options:**
- `--ports LIST` - Ports to scan (e.g., 22,80,443 or 1-1024)
- `--timeout SECONDS` - Connection timeout (default: 2.0)
- `--workers N` - Maximum concurrent TCP connect attempts (default: 5)
- `--json-output FILE` - Save results to JSON

**Examples:**
```bash
# Scan default common ports
reconforge ports 192.168.1.100

# Scan specific ports
reconforge ports 192.168.1.100 --ports 22,80,443,8080

# Scan port range
reconforge ports 192.168.1.100 --ports 1-1024 --workers 20

# Save to JSON
reconforge ports 192.168.1.100 --json-output ports.json
```

### `reconforge banner <HOST>`

Grab service banners for version/service identification.

**Options:**
- `--port N` - Port to grab banner from (repeatable)
- `--timeout SECONDS` - Connection timeout (default: 2.0)
- `--workers N` - Parallel workers (default: 5)
- `--json-output FILE` - Save results to JSON

**Examples:**
```bash
# Grab banner from SSH service
reconforge banner 192.168.1.100 --port 22

# Grab from multiple ports
reconforge banner 192.168.1.100 --port 22 --port 80 --port 443

# Save results
reconforge banner 192.168.1.100 --port 22 --port 80 --json-output banners.json
```

### `reconforge http <HOST>`

Analyze HTTP response metadata and TLS certificate details for an authorized host.

This command performs normal HTTP `HEAD` requests only. It checks status code, redirects, selected security headers, the `Server` header, and TLS certificate metadata when `--https` is used. It does not fuzz, brute force, exploit, evade, harvest credentials, or modify the target.

**Options:**
- `--port N` - HTTP/TLS port to analyze (default: 443)
- `--https` - Use HTTPS and inspect TLS certificate metadata
- `--timeout SECONDS` - Connection timeout (default: 2.0)
- `--json-output FILE` - Save results to JSON

**Examples:**
```bash
# Analyze HTTPS headers and TLS certificate metadata
reconforge http example.com --port 443 --https

# Analyze a local HTTP service
reconforge http 127.0.0.1 --port 80

# Save HTTP/TLS analysis to JSON
reconforge http example.com --port 443 --https --json-output http_tls.json
```

### `reconforge results`

Show a short summary of the current cumulative results store.

**Examples:**
```bash
reconforge results
```

### `reconforge report`

Generate a cumulative report from `.reconforge/session/results.json`.

**Options:**
- `--input FILE` - Use a custom cumulative results JSON file
- `--format FORMAT` - Output format: `html` or `json` (default: html)
- `--output FILE` - Output file path (default: timestamped file under `reports/`)
- `--clear` - Clear `.reconforge/session/results.json` after successful report generation
- `--summary-only` - Generate only summary data

**Examples:**
```bash
# Generate timestamped HTML from all stored results
reconforge report

# Generate timestamped JSON from all stored results
reconforge report --format json

# Generate a custom report and clear the session after success
reconforge report --output reports/internal_review.html --clear

# Use a custom cumulative results file
reconforge report --input .reconforge/session/results.json --format html
```

### `reconforge clear-results`

Clear the cumulative results store after confirmation.

**Examples:**
```bash
reconforge clear-results
reconforge clear-results --yes
```

### `reconforge db init`

Initialize the SQLite snapshot database at `.reconforge/reconforge.db`.

**Examples:**
```bash
reconforge db init
```

### `reconforge db import <RESULTS-JSON>`

Import a cumulative results JSON file as a SQLite snapshot. The command prints the snapshot ID used by `reconforge compare`.

**Examples:**
```bash
reconforge db import .reconforge/session/results.json
```

### `reconforge compare --baseline ID --current ID`

Compare two imported SQLite snapshots. The comparison reports newly opened ports, closed ports, changed banners, and changed TLS certificate metadata.

**Examples:**
```bash
reconforge compare --baseline 1 --current 2
```

---

## Examples

### Example 1: Quick Network Scan

```bash
# Scan your local network for active hosts and common ports
reconforge scan 192.168.1.0/24 --json-output network_scan.json

# View results
cat network_scan.json
```

### Example 2: Detailed Port Scan

```bash
# Scan a specific host with all common ports and service banners
reconforge ports 192.168.1.100 --ports 1-1024 --workers 20 --json-output port_scan.json
reconforge banner 192.168.1.100 --port 22 --port 80 --port 443
```

### Example 3: Generate Professional Reports

```bash
# Run multiple authorized checks; each result is stored automatically
reconforge scan 192.168.1.0/24
reconforge ports 192.168.1.10
reconforge banner 192.168.1.10 --port 22
reconforge http example.com --port 443 --https

# Review the cumulative session and generate a timestamped report
reconforge results
reconforge report

# Open report in browser (on Windows)
start reports

# On Linux/macOS
open reports
```

### Example 4: Safe Local Testing

```bash
# Test on your own machine (localhost is safe)
reconforge scan 127.0.0.1
reconforge ports 127.0.0.1 --ports 22,80,443
reconforge http 127.0.0.1 --port 80
```

### Example 5: Authorized HTTP/TLS Review

```bash
# Review headers and certificate metadata for an owned or authorized web service
reconforge http internal.example.com --port 443 --https --json-output http_tls.json
```

### Example 6: Lab Network Assessment

```bash
# Complete lab network assessment with all reports
reconforge scan 10.0.0.0/24 \
  --timeout 5 \
  --workers 20 \
  --ports 21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080
reconforge report --clear
```

---

## Default Scanned Ports

When no port list is specified, ReconForge scans these service ports:

```
21   (FTP)
22   (SSH)
23   (Telnet)
25   (SMTP)
53   (DNS)
80   (HTTP)
110  (POP3)
139  (NetBIOS)
143  (IMAP)
443  (HTTPS)
445  (SMB)
3306 (MySQL)
3389 (RDP)
5432 (PostgreSQL)
8080 (HTTP-Alt)
```

---

## Automatic Results Storage

ReconForge keeps a cumulative session file at `.reconforge/session/results.json`. Every successful `scan`, `ports`, `banner`, and `http` command appends a new entry while preserving previous results.

Each stored result may include `risk_tags`, and the top-level summary includes `total_risk_tags` plus `risk_counts` for `low`, `medium`, and `high` informational tags.

Existing session files remain usable. Older entries without `risk_tags` are classified when summaries and reports are generated.

Generated cumulative reports are written to:

```text
reports/reconforge_report_<YYYYMMDD_HHMMSS>.html
reports/reconforge_report_<YYYYMMDD_HHMMSS>.json
```

Useful workflow:

```bash
reconforge scan 192.168.1.0/24
reconforge ports 192.168.1.10
reconforge banner 192.168.1.10 --port 22
reconforge http example.com --port 443 --https
reconforge results
reconforge report
```

Use `reconforge report --clear` to clear the cumulative store after a successful report, or `reconforge clear-results` / `reconforge clear-results --yes` to reset it manually.

Explicit `--json-output` files are still supported for individual commands, but they are optional.

SQLite snapshots are stored in `.reconforge/reconforge.db`. Import one or more cumulative JSON files with `reconforge db import`, then compare snapshot IDs with `reconforge compare --baseline ID --current ID`.

### SQLite Snapshot Notes

- **What changed:** ReconForge can now store cumulative results JSON files as SQLite snapshots and compare two imported snapshots over time.
- **CLI changes:** new `reconforge db init`, `reconforge db import <RESULTS-JSON>`, and `reconforge compare --baseline ID --current ID` commands were added.
- **Output format:** existing scan, port, banner, HTTP, JSON report, and HTML report outputs are unchanged. The new compare output lists newly opened ports, closed ports, changed banners, and changed TLS metadata.
- **Config and storage:** SQLite data is written to `.reconforge/reconforge.db`; no additional configuration is required.
- **Migration:** existing cumulative JSON files remain valid. Import them with `reconforge db import` when you want persistent snapshot IDs for comparison.

---

## Installation

### Prerequisites
- Python 3.9 or later
- pip package manager
- (Optional) Administrative/root access for ICMP ping on some systems

### Setup

```bash
# Navigate to project directory
cd ReconForge

# Install in development mode
pip install -e .

# (Optional) Install with development tools
pip install -e ".[dev]"

# Verify installation
reconforge --help
```

### Troubleshooting Installation

**Command not found:**
```bash
# Try using Python module directly
python -m reconforge.cli --help

# Reinstall
pip install -e .
```

**Permission errors on Linux/macOS:**
```bash
# Ping sweep requires elevated privileges on some systems
sudo reconforge scan 192.168.1.0/24

# Or use skip-discovery to avoid ICMP
reconforge scan 192.168.1.1 --skip-discovery
```

---

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=reconforge

# Run specific test file
pytest tests/test_targets.py

# Run specific test
pytest tests/test_targets.py::TestTargetParser::test_parse_single_ipv4
```

---

## Legal Compliance Checklist

**Before running any scans, verify:**

- [ ] I have **written authorization** from the system/network owner
- [ ] I own the systems or have explicit permission to test them
- [ ] I understand the **local laws** regarding network scanning
- [ ] I have **informed administrators** of testing activities
- [ ] I am testing only on **authorized networks** (own lab, pentest, CTF, etc.)
- [ ] I understand ReconForge contains **no exploitation** features
- [ ] I understand ReconForge is **not for unauthorized scanning**

**Keep records of:**
- Written authorization from system owners
- Testing scope and timeframes
- Findings and reports
- Dates and times of testing activities

---

## Project Structure

```
reconforge/
├── __init__.py                  # Package initialization
├── cli.py                       # Typer CLI interface
├── py.typed                     # Type hints marker (PEP 561)
├── core/
│   ├── __init__.py
│   ├── config.py               # Configuration & defaults
│   ├── logging.py              # Logging setup
│   ├── models.py               # Pydantic data models
│   └── targets.py              # Target parsing & validation
├── recon/
│   ├── __init__.py
│   ├── discovery.py            # Host discovery (ping)
│   ├── ports.py                # Port scanning (TCP)
│   └── banners.py              # Banner grabbing
├── reporting/
│   ├── __init__.py
│   ├── json_report.py          # JSON export
│   ├── html_report.py          # HTML generation
│   └── templates/
│       └── report.html.j2      # HTML template
└── logging/                    # Runtime logs directory

tests/
├── __init__.py
├── test_targets.py
├── test_ports.py
└── test_banners.py

docs/
├── ARCHITECTURE.md             # Design decisions
└── EXAMPLES.md                 # Advanced examples

pyproject.toml                  # Python packaging
README.md                       # This file
QUICKSTART.md                   # Quick reference
LICENSE                        # MIT License
.gitignore                     # Git configuration
```

---

## Configuration

### Environment Variables

```bash
# Set logging verbosity
export RECONFORGE_LOG_LEVEL=DEBUG
reconforge scan 192.168.1.0/24

# Set custom log directory
export RECONFORGE_LOG_DIR=/tmp/logs
reconforge scan 192.168.1.0/24
```

### Configuration Files

Currently ReconForge uses environment variables. Future versions may support configuration files.

---

## Roadmap

ReconForge development stays focused on authorized security testing, defensive reconnaissance, and clear reporting for systems you own or have explicit permission to assess.

### v0.1

- Stable CLI
- Target parsing
- Host discovery
- TCP connect scan
- Banner grabbing
- JSON report
- HTML report

### v0.2

- Async scanner
- Service name detection
- TLS certificate inspection
- HTTP header analyzer

### v0.3

- Plugin architecture
- SQLite result storage
- Compare scans over time

### v0.4

- Authenticated checks voor eigen systemen
- Richer reporting
- Risk tagging

---

## Contributing

Contributions are welcome with these guidelines:

- **Maintain legal compliance** - No exploitation, evasion, or malware code
- **Add tests** - Include unit tests for new features
- **Type hints** - Use full type annotations
- **Documentation** - Update README and docstrings
- **Code style** - Follow PEP 8 / Black formatting

---

## License

MIT License - See [LICENSE](LICENSE) file for details

---

## References & Learning Resources

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Responsible Disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure)
- [Legal Hacking](https://en.wikipedia.org/wiki/Legal_hacking)
- [Penetration Testing Ethics](https://www.ec-council.org/certifications/certified-ethical-hacker/)

---

## Support

For issues, questions, or contributions, please refer to the documentation files:
- [QUICKSTART.md](QUICKSTART.md) - Installation & first-time use
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Design & implementation
- Test files in `tests/` directory for usage examples

---

**Remember: Always get written authorization before testing any system or network you don't own. Use ReconForge responsibly and ethically.**

