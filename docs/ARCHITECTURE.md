# ReconForge Architecture & Design Decisions

## Project Overview

ReconForge is a modular, type-safe Python reconnaissance toolkit designed for authorized security testing. The architecture prioritizes:

- **Legal Compliance**: No exploitation, bruteforce, or evasion features
- **Modularity**: Each reconnaissance function is independent and reusable
- **Type Safety**: Full type hints for IDE support and error prevention
- **Extensibility**: Easy to add new reconnaissance modules
- **Cross-Platform Compatibility**: Works on Windows, Linux, and macOS

## Core Architecture

### 1. Modular Design

```
reconforge/
├── core/              # Core utilities and models
│   ├── config.py      # Configuration management
│   ├── logging.py     # Logging setup
│   ├── models.py      # Pydantic data models (type-safe)
│   └── targets.py     # Target parsing & validation
├── recon/             # Reconnaissance modules
│   ├── discovery.py   # Host discovery (ping sweep)
│   ├── ports.py       # Port scanning (TCP connect)
│   └── banners.py     # Banner grabbing (safe)
├── reporting/         # Report generation
│   ├── json_report.py # JSON export
│   ├── html_report.py # HTML generation
│   └── templates/     # Jinja2 templates
└── cli.py             # CLI application (Typer)
```

### 2. Data Flow Architecture

```
Target String
    ↓
TargetParser (validates and normalizes)
    ↓
List[str] (IP addresses)
    ↓
Reconnaissance Modules:
├─→ HostDiscovery.discover() → DiscoveryResult
├─→ PortScanner.scan() → PortListResult
└─→ BannerGrabber.grab_banners() → BannerGrabResult
    ↓
Pydantic Models (ScanReport)
    ↓
Reporters:
├─→ JSONReporter.report_scan() → JSON file
└─→ HTMLReporter.report_scan() → HTML file
```

## Key Design Decisions

### 1. No Raw Sockets

**Decision**: Use Python's standard `asyncio` TCP connection APIs with TCP connect scans only.

**Rationale**:
- Raw socket scanning requires elevated privileges and specialized knowledge
- Stealth SYN scans are intended for evasion (not in scope)
- TCP connect scanning is straightforward, portable, and legal
- Reduces operating system dependencies

### 2. Pydantic Models for Data Representation

**Decision**: Use Pydantic v2 for all internal data structures.

**Rationale**:
- Type-safe data validation
- Automatic serialization to JSON
- IDE autocomplete and type checking
- Easy schema documentation
- Extensible for future features

### 3. Typer for CLI

**Decision**: Use Typer instead of argparse or Click.

**Rationale**:
- Modern, type-safe CLI framework
- Automatic documentation generation
- Rich formatting and colors
- Based on Click under the hood
- Excellent for Python 3.9+

### 4. Concurrent Execution

**Decision**: Use `concurrent.futures.ThreadPoolExecutor` for parallel operations.

**Rationale**:
- Simple thread pool for I/O-bound operations
- No need for multiprocessing (not CPU-bound)
- Easier to manage resource cleanup
- Better for cross-platform compatibility

### 5. Jinja2 Templates for Reports

**Decision**: Use Jinja2 for HTML report generation.

**Rationale**:
- Standard template engine in Python ecosystem
- Separates presentation from logic
- Easy to customize and extend
- Supports complex layouts and formatting

### 6. Platform-Specific Ping Implementation

**Decision**: Use `subprocess` to call system `ping` command with platform detection.

**Rationale**:
- ICMP access requires raw sockets (privilege escalation)
- System `ping` handles platform differences automatically
- Doesn't require special privileges on most systems
- More reliable than raw ICMP implementation

## Reconnaissance Modules

### HostDiscovery

**Purpose**: Determine which hosts in a network range are alive.

**Implementation**:
- Uses platform-specific ping (Windows: `-n 1 -w timeout`, Linux/macOS: `-c 1 -W timeout`)
- Parallel execution with ThreadPoolExecutor
- Returns DiscoveryResult with alive and dead hosts

**Limitations**:
- Some networks block ICMP (ping sweep will find 0 alive hosts)
- Not a stealth operation - clearly visible in network logs
- Timeout is configurable

### PortScanner

**Purpose**: Identify open ports on target hosts.

**Implementation**:
- TCP connect scanning using `asyncio.open_connection`
- Service identification via known port mappings
- Bounded concurrency with `asyncio.Semaphore`; CLI `--workers` sets the concurrency limit
- No banner grabbing in this module (separate concern)

**Why not SYN scan**:
- Requires raw socket capability (root/administrator)
- Would appear as stealth/evasion feature
- Not authorized for security testing without explicit need

### BannerGrabber

**Purpose**: Identify services and versions via banners.

**Implementation**:
- HTTP ports: Send HEAD request, parse response headers
- Other ports: Connect and read initial response (no data sent)
- Service identification from banner content
- Separate HTTP vs raw banner handling

**Safety Considerations**:
- No sending of exploit payloads
- No bruteforce attempts
- Respects port-specific conventions
- Reads only data the service voluntarily sends

## Data Models

All models inherit from `pydantic.BaseModel` with `ConfigDict(from_attributes=True)`.

### ScanReport (Top-level)
- Contains entire scan results
- Includes configuration, timing, and statistics
- Used for both JSON and HTML output

### HostInfo
- Single host details
- IP, hostname, alive status, open ports

### PortScanResult
- Port-level details
- Port number, open/closed, service name, banner

### BannerInfo
- Service identification data
- HTTP headers, raw banner text, timestamp

## CLI Command Structure

```
reconforge
├── scan <target>          # Full scan with discovery + ports
├── ports <host>           # Port scan only
├── banner <host>          # Banner grab only
├── report <json-file>     # Generate reports
└── version                # Show version
```

Each command supports:
- `--timeout`: Adjust timeout (default: 2.0s)
- `--workers`: Adjust parallelism (default: 5)
- `--json-output`: Save structured results
- `--html-output`: Generate HTML report

## Logging Architecture

- **Level**: Configurable via `RECONFORGE_LOG_LEVEL` environment variable
- **Destinations**: Console (visible) + File (logs/reconforge.log)
- **Format**: Timestamp, logger name, level, message
- **Rotation**: File handler rotates at 10MB with 5 backups

## Type Hints

Full type annotations throughout:
- Function parameters and return types
- Generic types (List, Dict, Optional)
- Model fields with Pydantic
- IDE autocomplete support
- mypy static type checking

## Security Boundaries

### ✅ In Scope
- Host discovery (ping)
- Port scanning (TCP connect)
- Banner grabbing (passive reading + HTTP HEAD)
- Safe reconnaissance
- Authorized testing only

### ❌ Out of Scope
- Exploitation of vulnerabilities
- Bruteforce attacks
- Credential harvesting
- Malware or persistence mechanisms
- Stealth or IDS/IPS evasion
- Scanning without authorization

## Extension Points

### Adding a New Reconnaissance Module

1. Create class in `reconforge/recon/new_module.py`
2. Inherit from appropriate pattern (similar to PortScanner)
3. Return Pydantic model with results
4. Add tests in `tests/test_new_module.py`
5. Export from `reconforge/recon/__init__.py`
6. Integrate in CLI if needed

### Adding a New Report Format

1. Create class in `reconforge/reporting/new_format.py`
2. Implement methods similar to JSONReporter/HTMLReporter
3. Add tests in `tests/test_reporting_new_format.py`
4. Integrate in CLI report command

## Dependencies

### Core
- **typer**: CLI framework with type hints
- **pydantic**: Data validation and serialization
- **jinja2**: HTML template rendering
- **python-dateutil**: Date/time utilities

### Development (Optional)
- **pytest**: Unit testing framework
- **pytest-cov**: Coverage reporting
- **black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Static type checking
- **ruff**: Fast linting (alternative)

## Performance Considerations

### Concurrency Model
- `HostDiscovery`: 1 thread per host (up to `workers` limit)
- `PortScanner`: async TCP connect tasks up to the `workers` concurrency limit
- `BannerGrabber`: 1 thread per port (up to `workers` limit)

### Timeout Tuning
- **Discovery**: 2s default (increase for slow networks)
- **Ports**: 2s default (increase for high latency)
- **Banners**: 2s default (HTTP HEAD might be slower)

### Scaling
- Default workers: 5 (conservative)
- Can increase to 20-50 for large networks
- Port scans avoid per-port thread overhead by using bounded asyncio concurrency

## Legal Compliance

### Built-in Protections
- Disclaimer in README and all reports
- Clear error messages guide proper use
- No stealth or evasion features
- No exploitation capabilities
- No credential harvesting

### Best Practices Enforced
- Explicit target specification (no accidentally scanning wrong network)
- Timeout defaults prevent resource exhaustion
- Clean logging for audit trails
- Structured output for compliance documentation

## Future Enhancements

Possible additions (without compromising scope):

- DNS enumeration (safe, passive)
- WHOIS lookups
- Service version detection (passive)
- SSL/TLS certificate info
- HTTP methods enumeration (OPTIONS)
- Report templates customization
- API mode (FastAPI wrapper)
- Configuration file support
- Target groups/campaigns

---

For implementation details, see the source code docstrings and inline comments.
