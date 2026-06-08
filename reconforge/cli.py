"""Typer CLI application for ReconForge."""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer

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
from reconforge.recon import HostDiscovery, PortScanner, BannerGrabber, HTTPAnalyzer
from reconforge.reporting import JSONReporter, HTMLReporter

# Set up logging
setup_logging()
logger = get_logger(__name__)

# Create Typer app
app = typer.Typer(
    name="reconforge",
    help="ReconForge - Legal Security Reconnaissance Toolkit",
    rich_markup_mode="rich",
)


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


def _print_table(rows: List[List[str]]) -> None:
    """Print a small ASCII table."""
    widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    typer.echo(separator)
    for index, row in enumerate(rows):
        typer.echo("| " + " | ".join(value.ljust(widths[col]) for col, value in enumerate(row)) + " |")
        if index == 0:
            typer.echo(separator)
    typer.echo(separator)


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
    typer.echo(banner, err=False)


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
        typer.echo(f"[*] Parsing target: {target}")
        parser = TargetParser()
        try:
            targets = parser.parse_target(target)
        except ValueError as e:
            typer.echo(f"[!] Invalid target: {e}", err=True)
            raise typer.Exit(1)
        
        typer.echo(f"[+] Found {len(targets)} target(s)")
        
        # Parse ports if specified
        scan_ports = DEFAULT_PORTS
        if ports:
            try:
                scan_ports = parser.parse_ports(ports)
                typer.echo(f"[+] Scanning {len(scan_ports)} specified ports")
            except ValueError as e:
                typer.echo(f"[!] Error parsing ports: {e}", err=True)
                raise typer.Exit(1)
        
        # Host discovery
        scan_start = datetime.now()
        hosts_to_scan = targets
        
        if not skip_discovery:
            typer.echo("[*] Running host discovery (ping sweep)...")
            discovery = HostDiscovery(timeout=timeout)
            discovery_result = discovery.discover(targets, workers=workers)
            hosts_to_scan = discovery_result.alive_hosts
            typer.echo(
                f"[+] Discovery complete: {len(hosts_to_scan)} alive, "
                f"{len(discovery_result.dead_hosts)} dead"
            )
        
        # Port scanning
        typer.echo(f"[*] Scanning ports on {len(hosts_to_scan)} host(s)...")
        scanner = PortScanner(timeout=timeout)
        
        # Collect results
        all_hosts = []
        for host in hosts_to_scan:
            typer.echo(f"  [*] Scanning {host}...", err=False)
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
            typer.echo(f"    [+] Found {len(host_info.open_ports)} open ports")
        
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
        typer.echo("\n" + "="*60)
        typer.echo("SCAN SUMMARY")
        typer.echo("="*60)
        typer.echo(f"Target: {target}")
        typer.echo(f"Duration: {scan_report.duration:.2f}s")
        typer.echo(f"Hosts discovered: {scan_report.alive_hosts_count}")
        typer.echo(f"Total open ports: {scan_report.total_open_ports}")
        
        if scan_report.hosts:
            typer.echo("\nHosts with open ports:")
            for host in scan_report.hosts:
                if host.open_ports:
                    ports_str = ", ".join([str(p.port) for p in host.open_ports])
                    typer.echo(f"  {host.ip_address}: {ports_str}")
        
        # Save reports
        if json_output:
            JSONReporter.report_scan(scan_report, json_output)
            typer.echo(f"\n[+] JSON report saved to {json_output}")
        
        if html_output:
            HTMLReporter().report_scan(scan_report, html_output)
            typer.echo(f"[+] HTML report saved to {html_output}")
        
        typer.echo("\n[+] Scan complete!")
        
    except typer.Exit:
        raise
    except typer.BadParameter as e:
        typer.echo(f"[!] Invalid input: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
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
        
        parser = TargetParser()
        original_host = host
        host = _resolve_single_host(host)
        if host != original_host:
            typer.echo(f"[+] Resolved {original_host} to: {host}")
        
        # Parse ports
        scan_ports = DEFAULT_PORTS
        if ports_spec:
            try:
                scan_ports = parser.parse_ports(ports_spec)
            except ValueError as e:
                typer.echo(f"[!] Error parsing ports: {e}", err=True)
                raise typer.Exit(1)
        
        # Scan ports
        typer.echo(f"[*] Scanning {len(scan_ports)} ports on {host}...")
        scanner = PortScanner(timeout=timeout)
        result = scanner.scan(host, ports=scan_ports, workers=workers)
        
        # Display results
        typer.echo("\n" + "="*60)
        typer.echo(f"PORT SCAN RESULTS FOR {host}")
        typer.echo("="*60)
        
        if result.open_ports:
            typer.echo(f"\n[+] Found {len(result.open_ports)} open port(s):\n")
            for port in result.open_ports:
                if port.open:
                    service = f" ({port.service})" if port.service else ""
                    typer.echo(f"  {port.port:5d}{service}")
        else:
            typer.echo("\n[-] No open ports found")
        
        # Save JSON if requested
        if json_output:
            JSONReporter.report_ports(result, json_output)
            typer.echo(f"\n[+] Results saved to {json_output}")
        
    except typer.Exit:
        raise
    except typer.BadParameter as e:
        typer.echo(f"[!] Invalid input: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
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
        
        original_host = host
        host = _resolve_single_host(host)
        if host != original_host:
            typer.echo(f"[+] Resolved {original_host} to: {host}")
        
        # Validate ports
        if not port:
            typer.echo("[!] No ports specified. Use --port to specify port(s).", err=True)
            raise typer.Exit(1)
        for item in port:
            _validate_port(item)
        port = sorted(set(port))
        
        # Grab banners
        typer.echo(f"[*] Grabbing banners from {len(port)} port(s) on {host}...")
        grabber = BannerGrabber(timeout=timeout)
        result = grabber.grab_banners(host, port, workers=workers)
        
        # Display results
        typer.echo("\n" + "="*60)
        typer.echo(f"BANNER GRAB RESULTS FOR {host}")
        typer.echo("="*60)
        
        if result.ports:
            for banner_info in result.ports:
                typer.echo(f"\n[*] Port {banner_info.port}:")
                if banner_info.banner:
                    typer.echo(f"  Banner: {banner_info.banner[:200]}")
                if banner_info.http_headers:
                    typer.echo("  HTTP Headers:")
                    for key, value in list(banner_info.http_headers.items())[:5]:
                        typer.echo(f"    {key}: {value}")
        else:
            typer.echo("\n[-] No banners grabbed")
        
        # Save JSON if requested
        if json_output:
            JSONReporter.report_banners(result, json_output)
            typer.echo(f"\n[+] Results saved to {json_output}")
        
    except typer.Exit:
        raise
    except typer.BadParameter as e:
        typer.echo(f"[!] Invalid input: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
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
        host = _validate_http_host(host)

        scheme = "https" if https else "http"
        typer.echo(f"[*] Analyzing {scheme}://{host}:{port} with HTTP HEAD requests...")
        analyzer = HTTPAnalyzer(timeout=timeout)
        result = analyzer.analyze(host=host, port=port, https=https)

        typer.echo("\n" + "=" * 60)
        typer.echo(f"HTTP/TLS ANALYSIS FOR {host}:{port}")
        typer.echo("=" * 60)

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

        if json_output:
            JSONReporter.report_http(result, json_output)
            typer.echo(f"\n[+] Results saved to {json_output}")

    except typer.Exit:
        raise
    except typer.BadParameter as e:
        typer.echo(f"[!] Invalid input: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("HTTP analysis failed")
        raise typer.Exit(1)


@app.command()
def report(
    input_file: Path = typer.Argument(
        ...,
        help="Input JSON report file from previous scan"
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Output file path (defaults to input_file.html or .json)"
    ),
    format: str = typer.Option(
        "html",
        "--format",
        help="Output format: html or json"
    ),
):
    """Generate reports from scan results.
    
    Examples:
        reconforge report scan_results.json --format html --output report.html
        reconforge report scan_results.json --format json
    """
    print_banner()
    
    try:
        if not input_file.exists():
            typer.echo(f"[!] Input file not found: {input_file}", err=True)
            raise typer.Exit(1)
        if format.lower() not in {"html", "json"}:
            typer.echo(f"[!] Unknown format: {format}. Use 'html' or 'json'.", err=True)
            raise typer.Exit(1)
        
        # Determine output file
        if not output_file:
            if format == "html":
                output_file = input_file.with_suffix(".html")
            else:
                output_file = input_file.with_stem(input_file.stem + "_report")
        
        typer.echo(f"[*] Reading report from: {input_file}")
        typer.echo(f"[*] Generating {format.upper()} report...")
        
        # Generate appropriate report
        if format.lower() == "html":
            HTMLReporter.report_from_json(input_file, output_file)
        else:
            # Copy and re-validate JSON
            with open(input_file, "r") as f:
                data = json.load(f)
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
        
        typer.echo(f"\n[+] Report saved to: {output_file}")
        
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"[!] Error: {e}", err=True)
        logger.exception("Report generation failed")
        raise typer.Exit(1)


@app.command()
def version():
    """Show ReconForge version."""
    typer.echo("ReconForge v0.1.0")
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
