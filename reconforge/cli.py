"""Typer CLI application for ReconForge."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from reconforge.core import (
    setup_logging,
    get_logger,
    TargetParser,
    ScanConfig,
    ScanReport,
    HostInfo,
    PortScanResult,
)
from reconforge.core.config import DEFAULT_PORTS, DEFAULT_CONNECT_TIMEOUT, DEFAULT_WORKERS
from reconforge.core.paths import RESULTS_JSON, timestamped_report_path
from reconforge.core.results_store import (
    append_result,
    build_summary,
    clear_results_store,
    load_results_store,
    load_results_store_from_path,
)
from reconforge.core.scope import AuthorizedScope
from reconforge.core.sqlite_store import compare_snapshots, import_results_file, init_db
from reconforge.recon import HostDiscovery, PortScanner, BannerGrabber, HTTPAnalyzer
from reconforge.reporting import JSONReporter, HTMLReporter

# Set up logging
setup_logging()
logger = get_logger(__name__)
console = Console()

# Create Typer app
app = typer.Typer(
    name="reconforge",
    help="ReconForge - Legal Security Reconnaissance Toolkit",
    rich_markup_mode="rich",
)
db_app = typer.Typer(
    name="db",
    help="SQLite storage commands for imported ReconForge result snapshots",
)
app.add_typer(db_app, name="db")


def _validate_timeout(timeout: float) -> None:
    """Validate timeout parameter.
    
    Args:
        timeout: Timeout value in seconds
        
    Raises:
        typer.BadParameter: If timeout is invalid
    """
    if timeout <= 0:
        raise typer.BadParameter("Timeout must be positive (> 0 seconds)")
    if timeout > 300:
        raise typer.BadParameter("Timeout is too large (max 300 seconds)")


def _validate_workers(workers: int) -> None:
    """Validate workers parameter.
    
    Args:
        workers: Number of worker threads
        
    Raises:
        typer.BadParameter: If workers is invalid
    """
    if workers < 1:
        raise typer.BadParameter("Workers must be at least 1")
    if workers > 100:
        raise typer.BadParameter("Workers too large (max 100)")


def _validate_port(port: int) -> None:
    """Validate a TCP port number."""
    if port < 1 or port > 65535:
        raise typer.BadParameter(f"Port out of range: {port}. Use 1-65535.")


def _error(message: str) -> None:
    """Print a consistent validation/runtime error."""
    console.print(f"[bold red][!][/bold red] {message}")


def _success(message: str) -> None:
    """Print a consistent success message."""
    console.print(f"[green][+][/green] {message}")


def _info(message: str) -> None:
    """Print a consistent progress message."""
    console.print(f"[cyan][*][/cyan] {message}")


def _resolve_single_host(host: str) -> str:
    """Validate or resolve a host argument to a single IPv4 address."""
    parser = TargetParser()
    try:
        hosts = parser.parse_target(host)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    if not hosts:
        raise typer.BadParameter(f"Invalid target '{host}'. No host resolved.")
    if len(hosts) != 1:
        raise typer.BadParameter("This command accepts a single host, not a CIDR range.")
    return hosts[0]


def _validate_http_host(host: str) -> str:
    """Validate a host for HTTP analysis while preserving hostnames for SNI."""
    clean_host = host.strip()
    if not clean_host or "/" in clean_host:
        raise typer.BadParameter("Host must be a hostname or IPv4 address, not a URL or CIDR range.")

    parser = TargetParser()
    try:
        targets = parser.parse_target(clean_host)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    if len(targets) != 1:
        raise typer.BadParameter("HTTP analysis accepts a single host, not a CIDR range.")
    return clean_host


def _load_scope(scope_file: Optional[Path]) -> Optional[AuthorizedScope]:
    """Load an optional authorization scope file."""
    if scope_file is None:
        return None
    try:
        return AuthorizedScope.from_file(scope_file)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e


def _assert_in_scope(
    scope: Optional[AuthorizedScope],
    target: str,
    resolved_hosts: List[str],
) -> None:
    """Refuse targets outside the configured authorized scope."""
    if scope is None:
        return
    try:
        scope.assert_targets_allowed(target, resolved_hosts)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e


def _print_dry_run(title: str, rows: List[List[str]]) -> None:
    """Print a dry-run summary without performing network activity."""
    console.print(f"\n[bold]{title} DRY RUN[/bold]")
    _print_table([["Field", "Value"]] + rows)
    console.print("[yellow]No network activity was performed.[/yellow]")


def _print_table(rows: List[List[str]]) -> None:
    """Print a small Rich table."""
    table = Table(show_header=True, header_style="bold cyan")
    for header in rows[0]:
        table.add_column(header)
    for row in rows[1:]:
        table.add_row(*[str(value) for value in row])
    console.print(table)


def print_banner():
    """Print ReconForge banner."""
    banner = """
    +=====================================================================+
    |                    ReconForge v0.1                                  |
    |          Authorized Security Reconnaissance Toolkit                 |
    |                                                                     |
    | WARNING: Use only on authorized systems!                           |
    +=====================================================================+
    """
    console.print(banner)


@db_app.command("init")
def db_init():
    """Initialize the SQLite storage backend."""
    try:
        path = init_db()
        typer.echo(f"[+] SQLite database initialized: {path}")
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("Database initialization failed")
        raise typer.Exit(1)


@db_app.command("import")
def db_import(
    results_file: Path = typer.Argument(..., help="Cumulative ReconForge results JSON file"),
):
    """Import a cumulative results JSON file into SQLite."""
    try:
        snapshot_id = import_results_file(results_file)
        typer.echo(f"[+] Imported {results_file} as snapshot ID {snapshot_id}")
    except FileNotFoundError:
        typer.echo(f"[!] Results file not found: {results_file}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("Database import failed")
        raise typer.Exit(1)


def _print_compare_results(diff: dict) -> None:
    typer.echo("\n" + "=" * 60)
    typer.echo(f"COMPARE SNAPSHOTS {diff['baseline_id']} -> {diff['current_id']}")
    typer.echo("=" * 60)

    opened = diff.get("newly_opened_ports", [])
    closed = diff.get("closed_ports", [])
    banners = diff.get("changed_banners", [])
    tls_changes = diff.get("changed_tls_metadata", [])

    typer.echo("\nNewly opened ports:")
    if opened:
        _print_table(
            [["Target", "Host", "Port", "Service"]]
            + [
                [
                    item.get("target", "-"),
                    item.get("host", "-"),
                    str(item.get("port", "-")),
                    str(item.get("service") or "-"),
                ]
                for item in opened
            ]
        )
    else:
        typer.echo("none")

    typer.echo("\nClosed ports:")
    if closed:
        _print_table(
            [["Closed Target", "Host", "Port", "Service"]]
            + [
                [
                    item.get("target", "-"),
                    item.get("host", "-"),
                    str(item.get("port", "-")),
                    str(item.get("service") or "-"),
                ]
                for item in closed
            ]
        )
    else:
        typer.echo("none")

    typer.echo("\nChanged banners:")
    if banners:
        _print_table(
            [["Banner Target", "Port", "Baseline", "Current"]]
            + [
                [
                    item.get("target", "-"),
                    str(item.get("port", "-")),
                    str(item.get("baseline", "-"))[:80],
                    str(item.get("current", "-"))[:80],
                ]
                for item in banners
            ]
        )
    else:
        typer.echo("none")

    typer.echo("\nChanged TLS metadata:")
    if tls_changes:
        _print_table(
            [["TLS Target", "Port", "Baseline not_after", "Current not_after"]]
            + [
                [
                    item.get("target", "-"),
                    str(item.get("port", "-")),
                    str(item.get("baseline", {}).get("not_after") or "-"),
                    str(item.get("current", {}).get("not_after") or "-"),
                ]
                for item in tls_changes
            ]
        )
    else:
        typer.echo("none")


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Target: IPv4 address, CIDR range (e.g., 192.168.1.0/24), or hostname"
    ),
    timeout: float = typer.Option(
        DEFAULT_CONNECT_TIMEOUT,
        "--timeout",
        help="Connection timeout in seconds"
    ),
    workers: int = typer.Option(
        DEFAULT_WORKERS,
        "--workers",
        help="Number of worker threads"
    ),
    ports: Optional[str] = typer.Option(
        None,
        "--ports",
        help="Ports to scan (e.g., 22,80,443 or 1-1024)"
    ),
    skip_discovery: bool = typer.Option(
        False,
        "--skip-discovery",
        help="Skip host discovery (ping sweep)"
    ),
    json_output: Optional[Path] = typer.Option(
        None,
        "--json-output",
        help="Save results as JSON file"
    ),
    html_output: Optional[Path] = typer.Option(
        None,
        "--html-output",
        help="Generate HTML report"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate inputs and show the planned scan without network activity",
    ),
    scope_file: Optional[Path] = typer.Option(
        None,
        "--scope-file",
        help="File containing authorized IPv4 hosts, CIDRs, or hostnames",
    ),
):
    """Scan a target for live hosts and open ports.
    
    Examples:
        reconforge scan 192.168.1.0/24
        reconforge scan 192.168.1.1 --ports 22,80,443
        reconforge scan example.com --json-output results.json
    """
    print_banner()
    
    try:
        # Validate input parameters
        _validate_timeout(timeout)
        _validate_workers(workers)
        
        # Parse target
        scope = _load_scope(scope_file)

        _info(f"Parsing target: {target}")
        parser = TargetParser()
        try:
            targets = parser.parse_target(target)
        except ValueError as e:
            _error(f"Invalid target: {e}")
            raise typer.Exit(1)
        _assert_in_scope(scope, target, targets)

        _success(f"Found {len(targets)} target(s)")
        
        # Parse ports if specified
        scan_ports = DEFAULT_PORTS
        if ports:
            try:
                scan_ports = parser.parse_ports(ports)
                _success(f"Scanning {len(scan_ports)} specified ports")
            except ValueError as e:
                _error(f"Error parsing ports: {e}")
                raise typer.Exit(1)

        if dry_run:
            _print_dry_run(
                "SCAN",
                [
                    ["Target", target],
                    ["Resolved Targets", str(len(targets))],
                    ["Ports", ", ".join(str(port) for port in scan_ports)],
                    ["Host Discovery", "enabled" if not skip_discovery else "skipped"],
                    ["Workers", str(workers)],
                    ["Timeout", f"{timeout}s"],
                    ["Scope File", str(scope_file) if scope_file else "-"],
                ],
            )
            return
        
        # Host discovery
        scan_start = datetime.now()
        hosts_to_scan = targets
        
        if not skip_discovery:
            _info("Running host discovery (ping sweep)...")
            discovery = HostDiscovery(timeout=timeout)
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                progress.add_task("Discovering live hosts", total=None)
                discovery_result = discovery.discover(targets, workers=workers)
            hosts_to_scan = discovery_result.alive_hosts
            _success(
                f"Discovery complete: {len(hosts_to_scan)} alive, "
                f"{len(discovery_result.dead_hosts)} dead"
            )
        
        # Port scanning
        _info(f"Scanning ports on {len(hosts_to_scan)} host(s)...")
        scanner = PortScanner(timeout=timeout)
        
        # Collect results
        all_hosts = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning hosts", total=len(hosts_to_scan))
            for host in hosts_to_scan:
                progress.update(task, description=f"Scanning {host}")
                result = scanner.scan(host, ports=scan_ports, workers=workers)

                host_info = HostInfo(
                    ip_address=host,
                    alive=True,
                    open_ports=[
                        PortScanResult(
                            port=p.port,
                            open=p.open,
                            service=p.service,
                        )
                        for p in result.open_ports
                        if p.open
                    ]
                )
                all_hosts.append(host_info)
                progress.advance(task)
                if host_info.open_ports:
                    _success(
                        f"{host}: found {len(host_info.open_ports)} open port(s)"
                    )
        
        # Create scan report
        scan_end = datetime.now()
        scan_config = ScanConfig(
            timeout=timeout,
            workers=workers,
            ports=scan_ports,
            ping_enabled=not skip_discovery,
        )
        
        scan_report = ScanReport(
            scan_id=str(uuid.uuid4()),
            target=target,
            targets_scanned=targets,
            start_time=scan_start,
            end_time=scan_end,
            scan_config=scan_config,
            hosts=all_hosts,
            summary={
                "duration_seconds": (scan_end - scan_start).total_seconds(),
                "alive_hosts": len(hosts_to_scan),
                "total_open_ports": sum(len(h.open_ports) for h in all_hosts),
                "hosts_scanned": len(all_hosts),
            }
        )
        
        # Print summary
        console.print("\n[bold]SCAN SUMMARY[/bold]")
        _print_table(
            [
                ["Field", "Value"],
                ["Target", target],
                ["Duration", f"{scan_report.duration:.2f}s"],
                ["Hosts Discovered", str(scan_report.alive_hosts_count)],
                ["Total Open Ports", str(scan_report.total_open_ports)],
            ]
        )
        
        if scan_report.hosts:
            host_rows = [["Host", "Open Ports"]]
            for host in scan_report.hosts:
                ports_str = ", ".join(
                    f"{p.port}/{p.service}" if p.service else str(p.port)
                    for p in host.open_ports
                )
                host_rows.append([host.ip_address, ports_str or "No open ports found"])
            console.print("\n[bold]Host Results[/bold]")
            _print_table(host_rows)

        append_result(
            "scan",
            target,
            scan_report.model_dump(mode="json", exclude_none=True),
            command=f"reconforge scan {target}",
        )
        _success(f"Result appended to {RESULTS_JSON}")
        
        # Save reports
        if json_output:
            JSONReporter.report_scan(scan_report, json_output)
            _success(f"JSON report saved to {json_output}")
        
        if html_output:
            HTMLReporter().report_scan(scan_report, html_output)
            _success(f"HTML report saved to {html_output}")
        
        _success("Scan complete!")
        
    except typer.Exit:
        raise
    except typer.BadParameter as e:
        _error(f"Invalid input: {e}")
        raise typer.Exit(1)
    except Exception as e:
        _error(f"Error: {e}")
        logger.exception("Scan failed")
        raise typer.Exit(1)


@app.command()
def ports(
    host: str = typer.Argument(..., help="Target IP address or hostname"),
    ports_spec: Optional[str] = typer.Option(
        None,
        "--ports",
        help="Ports to scan (e.g., 22,80,443 or 1-1024)"
    ),
    timeout: float = typer.Option(
        DEFAULT_CONNECT_TIMEOUT,
        "--timeout",
        help="Connection timeout in seconds"
    ),
    workers: int = typer.Option(
        DEFAULT_WORKERS,
        "--workers",
        help="Number of worker threads"
    ),
    json_output: Optional[Path] = typer.Option(
        None,
        "--json-output",
        help="Save results as JSON file"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate inputs and show the planned port scan without network activity",
    ),
    scope_file: Optional[Path] = typer.Option(
        None,
        "--scope-file",
        help="File containing authorized IPv4 hosts, CIDRs, or hostnames",
    ),
):
    """Scan ports on a specific host.
    
    Examples:
        reconforge ports 192.168.1.1
        reconforge ports 192.168.1.1 --ports 22,80,443
        reconforge ports example.com --json-output ports.json
    """
    print_banner()
    
    try:
        # Validate input parameters
        _validate_timeout(timeout)
        _validate_workers(workers)
        scope = _load_scope(scope_file)
        
        parser = TargetParser()
        original_host = host
        host = _resolve_single_host(host)
        _assert_in_scope(scope, original_host, [host])
        if host != original_host:
            _success(f"Resolved {original_host} to: {host}")
        
        # Parse ports
        scan_ports = DEFAULT_PORTS
        if ports_spec:
            try:
                scan_ports = parser.parse_ports(ports_spec)
            except ValueError as e:
                _error(f"Error parsing ports: {e}")
                raise typer.Exit(1)

        if dry_run:
            _print_dry_run(
                "PORT SCAN",
                [
                    ["Host", original_host],
                    ["Resolved Host", host],
                    ["Ports", ", ".join(str(port) for port in scan_ports)],
                    ["Workers", str(workers)],
                    ["Timeout", f"{timeout}s"],
                    ["Scope File", str(scope_file) if scope_file else "-"],
                ],
            )
            return
        
        # Scan ports
        _info(f"Scanning {len(scan_ports)} ports on {host}...")
        scanner = PortScanner(timeout=timeout)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("Running TCP connect checks", total=None)
            result = scanner.scan(host, ports=scan_ports, workers=workers)
        
        # Display results
        console.print(f"\n[bold]PORT SCAN RESULTS FOR {host}[/bold]")
        
        if result.open_ports:
            _success(f"Found {len(result.open_ports)} open port(s)")
            rows = [["Port", "Service"]]
            for port in result.open_ports:
                if port.open:
                    rows.append([str(port.port), port.service or "-"])
            _print_table(rows)
        else:
            console.print("[yellow]No open ports found[/yellow]")

        append_result(
            "ports",
            host,
            result.model_dump(mode="json", exclude_none=True),
            command=f"reconforge ports {original_host}",
        )
        _success(f"Result appended to {RESULTS_JSON}")
        
        # Save JSON if requested
        if json_output:
            JSONReporter.report_ports(result, json_output)
            _success(f"Results saved to {json_output}")
        
    except typer.Exit:
        raise
    except typer.BadParameter as e:
        _error(f"Invalid input: {e}")
        raise typer.Exit(1)
    except Exception as e:
        _error(f"Error: {e}")
        logger.exception("Port scan failed")
        raise typer.Exit(1)


@app.command()
def banner(
    host: str = typer.Argument(..., help="Target IP address or hostname"),
    port: List[int] = typer.Option(
        [],
        "--port",
        help="Port number(s) to grab banner from (can be repeated)"
    ),
    timeout: float = typer.Option(
        DEFAULT_CONNECT_TIMEOUT,
        "--timeout",
        help="Connection timeout in seconds"
    ),
    workers: int = typer.Option(
        DEFAULT_WORKERS,
        "--workers",
        help="Number of worker threads"
    ),
    json_output: Optional[Path] = typer.Option(
        None,
        "--json-output",
        help="Save results as JSON file"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate inputs and show the planned banner grab without network activity",
    ),
    scope_file: Optional[Path] = typer.Option(
        None,
        "--scope-file",
        help="File containing authorized IPv4 hosts, CIDRs, or hostnames",
    ),
):
    """Grab service banners for identification.
    
    Examples:
        reconforge banner 192.168.1.1 --port 22
        reconforge banner 192.168.1.1 --port 22 --port 80 --port 443
        reconforge banner example.com --port 22 --json-output banners.json
    """
    print_banner()
    
    try:
        # Validate input parameters
        _validate_timeout(timeout)
        _validate_workers(workers)
        scope = _load_scope(scope_file)
        
        original_host = host
        host = _resolve_single_host(host)
        _assert_in_scope(scope, original_host, [host])
        if host != original_host:
            _success(f"Resolved {original_host} to: {host}")
        
        # Validate ports
        if not port:
            _error("No ports specified. Use --port to specify port(s).")
            raise typer.Exit(1)
        for item in port:
            _validate_port(item)
        port = sorted(set(port))

        if dry_run:
            _print_dry_run(
                "BANNER GRAB",
                [
                    ["Host", original_host],
                    ["Resolved Host", host],
                    ["Ports", ", ".join(str(item) for item in port)],
                    ["Workers", str(workers)],
                    ["Timeout", f"{timeout}s"],
                    ["Scope File", str(scope_file) if scope_file else "-"],
                ],
            )
            return
        
        # Grab banners
        _info(f"Grabbing banners from {len(port)} port(s) on {host}...")
        grabber = BannerGrabber(timeout=timeout)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("Requesting service banners", total=None)
            result = grabber.grab_banners(host, port, workers=workers)
        
        # Display results
        console.print(f"\n[bold]BANNER GRAB RESULTS FOR {host}[/bold]")
        
        if result.ports:
            rows = [["Port", "Service", "Banner", "HTTP Headers"]]
            for banner_info in result.ports:
                headers = "-"
                if banner_info.http_headers:
                    headers = ", ".join(
                        f"{key}: {value}"
                        for key, value in list(banner_info.http_headers.items())[:5]
                    )
                rows.append(
                    [
                        str(banner_info.port),
                        banner_info.service or "-",
                        (banner_info.banner or "-")[:200],
                        headers,
                    ]
                )
            _print_table(rows)
        else:
            console.print("[yellow]No banners grabbed[/yellow]")

        append_result(
            "banner",
            host,
            result.model_dump(mode="json", exclude_none=True),
            command=f"reconforge banner {original_host}",
        )
        _success(f"Result appended to {RESULTS_JSON}")
        
        # Save JSON if requested
        if json_output:
            JSONReporter.report_banners(result, json_output)
            _success(f"Results saved to {json_output}")
        
    except typer.Exit:
        raise
    except typer.BadParameter as e:
        _error(f"Invalid input: {e}")
        raise typer.Exit(1)
    except Exception as e:
        _error(f"Error: {e}")
        logger.exception("Banner grab failed")
        raise typer.Exit(1)


@app.command()
def http(
    host: str = typer.Argument(..., help="Target hostname or IPv4 address"),
    port: int = typer.Option(
        443,
        "--port",
        help="HTTP/TLS port to analyze"
    ),
    https: bool = typer.Option(
        False,
        "--https",
        help="Use HTTPS and inspect the TLS certificate"
    ),
    timeout: float = typer.Option(
        DEFAULT_CONNECT_TIMEOUT,
        "--timeout",
        help="Connection timeout in seconds"
    ),
    json_output: Optional[Path] = typer.Option(
        None,
        "--json-output",
        help="Save results as JSON file"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Validate inputs and show the planned HTTP/TLS analysis without network activity",
    ),
    scope_file: Optional[Path] = typer.Option(
        None,
        "--scope-file",
        help="File containing authorized IPv4 hosts, CIDRs, or hostnames",
    ),
):
    """Analyze HTTP headers and TLS certificate metadata safely.

    This command performs normal HTTP HEAD requests only. It does not fuzz,
    brute force, exploit, evade, or attempt credential access.

    Examples:
        reconforge http example.com --port 443 --https
        reconforge http 127.0.0.1 --port 80
        reconforge http example.com --https --json-output http.json
    """
    print_banner()

    try:
        _validate_timeout(timeout)
        _validate_port(port)
        scope = _load_scope(scope_file)
        host = _validate_http_host(host)
        resolved_hosts = TargetParser().parse_target(host)
        _assert_in_scope(scope, host, resolved_hosts)

        scheme = "https" if https else "http"
        if dry_run:
            _print_dry_run(
                "HTTP/TLS ANALYSIS",
                [
                    ["URL", f"{scheme}://{host}:{port}"],
                    ["Resolved Hosts", ", ".join(resolved_hosts)],
                    ["TLS Inspection", "enabled" if https else "disabled"],
                    ["Timeout", f"{timeout}s"],
                    ["Scope File", str(scope_file) if scope_file else "-"],
                ],
            )
            return

        _info(f"Analyzing {scheme}://{host}:{port} with HTTP HEAD requests...")
        analyzer = HTTPAnalyzer(timeout=timeout)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console,
        ) as progress:
            progress.add_task("Collecting HTTP/TLS metadata", total=None)
            result = analyzer.analyze(host=host, port=port, https=https)

        console.print(f"\n[bold]HTTP/TLS ANALYSIS FOR {host}:{port}[/bold]")

        rows = [
            ["Field", "Value"],
            ["Scheme", result.scheme],
            ["Status Code", str(result.status_code) if result.status_code is not None else "-"],
            ["Server", result.server_header or "-"],
            ["Redirects", " -> ".join(result.redirects) if result.redirects else "-"],
        ]

        for name, value in result.security_headers.items():
            rows.append([name, value or "-"])

        if result.tls_certificate:
            cert = result.tls_certificate
            rows.extend([
                ["TLS Subject", cert.subject or "-"],
                ["TLS Issuer", cert.issuer or "-"],
                ["TLS Not Before", cert.not_before or "-"],
                ["TLS Not After", cert.not_after or "-"],
                ["TLS SANs", ", ".join(cert.sans) if cert.sans else "-"],
            ])
            if cert.error:
                rows.append(["TLS Error", cert.error])

        if result.error:
            rows.append(["HTTP Error", result.error])

        _print_table(rows)

        append_result(
            "http",
            host,
            result.model_dump(mode="json", exclude_none=True),
            command=f"reconforge http {host}",
        )
        _success(f"Result appended to {RESULTS_JSON}")

        if json_output:
            JSONReporter.report_http(result, json_output)
            _success(f"Results saved to {json_output}")

    except typer.Exit:
        raise
    except typer.BadParameter as e:
        _error(f"Invalid input: {e}")
        raise typer.Exit(1)
    except Exception as e:
        _error(f"Error: {e}")
        logger.exception("HTTP analysis failed")
        raise typer.Exit(1)


@app.command()
def report(
    input_file: Optional[Path] = typer.Option(
        None,
        "--input",
        help="Input cumulative results JSON file"
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Output report path"
    ),
    format: str = typer.Option(
        "html",
        "--format",
        help="Output format: html or json"
    ),
    clear: bool = typer.Option(
        False,
        "--clear",
        help="Clear the default results store after successful report generation"
    ),
    summary_only: bool = typer.Option(
        False,
        "--summary-only",
        help="Generate only the summary, without per-result detail sections"
    ),
):
    """Generate a report from the cumulative results store.
    
    Examples:
        reconforge report
        reconforge report --format json
        reconforge report --input .reconforge/session/results.json --clear
    """
    print_banner()
    
    try:
        normalized_format = format.lower()
        if normalized_format not in {"html", "json"}:
            typer.echo(f"[!] Unknown format: {format}. Use 'html' or 'json'.", err=True)
            raise typer.Exit(1)

        source_path = input_file or RESULTS_JSON
        if input_file:
            if not input_file.exists():
                typer.echo(f"[!] Input file not found: {input_file}", err=True)
                raise typer.Exit(1)
            store = load_results_store_from_path(input_file)
        else:
            store = load_results_store()

        if not store.get("results"):
            typer.echo(
                "No ReconForge results found. Run one or more recon commands first, "
                "then run `reconforge report`.",
                err=True,
            )
            raise typer.Exit(1)
        
        if not output_file:
            output_file = timestamped_report_path(normalized_format)
        
        store["summary"] = build_summary(store)
        typer.echo(f"[*] Reading results from: {source_path}")
        typer.echo(f"[*] Generating {normalized_format.upper()} report...")
        
        if normalized_format == "html":
            HTMLReporter.report_results_store(store, output_file, summary_only=summary_only)
        else:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            report_data = {"summary": store["summary"]} if summary_only else store
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)
        
        typer.echo(f"\n[+] Report saved to: {output_file}")

        if clear:
            clear_results_store()
            typer.echo(f"[+] Cleared results store: {RESULTS_JSON}")
        
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("Report generation failed")
        raise typer.Exit(1)


@app.command()
def results():
    """Show a short summary of the cumulative results store."""
    try:
        store = load_results_store()
        summary = store.get("summary", {})
        counts = summary.get("result_counts", {})
        risk_counts = summary.get("risk_counts", {})

        typer.echo("\n" + "=" * 60)
        typer.echo("RECONFORGE RESULTS STORE")
        typer.echo("=" * 60)
        rows = [
            ["Field", "Value"],
            ["Session ID", str(store.get("session_id", "-"))],
            ["Created At", str(store.get("created_at", "-"))],
            ["Updated At", str(store.get("updated_at", "-"))],
            ["Total Results", str(summary.get("total_results", 0))],
            ["Unique Targets", str(summary.get("unique_targets", 0))],
            ["Risk Tags", str(summary.get("total_risk_tags", 0))],
            [
                "Risk Counts",
                ", ".join(
                    f"{key}: {value}"
                    for key, value in sorted(risk_counts.items())
                ) or "-",
            ],
            [
                "Counts By Type",
                ", ".join(f"{key}: {value}" for key, value in sorted(counts.items())) or "-",
            ],
        ]
        _print_table(rows)
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("Results summary failed")
        raise typer.Exit(1)


@app.command("clear-results")
def clear_results(
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Clear without asking for confirmation"
    )
):
    """Clear the cumulative results store."""
    try:
        if not yes and not typer.confirm(f"Clear ReconForge results store at {RESULTS_JSON}?"):
            typer.echo("Aborted.")
            raise typer.Exit(0)

        clear_results_store()
        typer.echo(f"[+] Cleared results store: {RESULTS_JSON}")
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("Clear results failed")
        raise typer.Exit(1)


@app.command()
def compare(
    baseline: int = typer.Option(..., "--baseline", help="Baseline snapshot ID"),
    current: int = typer.Option(..., "--current", help="Current snapshot ID"),
):
    """Compare two imported SQLite snapshots."""
    try:
        diff = compare_snapshots(baseline, current)
        _print_compare_results(diff)
    except ValueError as e:
        typer.echo(f"[!] {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("Snapshot comparison failed")
        raise typer.Exit(1)


@app.command()
def version():
    """Show ReconForge version."""
    typer.echo("ReconForge v0.1.1b4")
    typer.echo("Authorized Security Reconnaissance Toolkit")


@app.callback()
def main(
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging"
    )
):
    """ReconForge - Legal Security Reconnaissance Toolkit
    
    Use this tool ONLY on systems and networks for which you have
    explicit written authorization.
    """
    if verbose:
        setup_logging("DEBUG", console=True)


if __name__ == "__main__":
    app()
