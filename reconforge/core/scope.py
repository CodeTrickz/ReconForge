"""Authorized target scope validation."""

import ipaddress
from pathlib import Path
from typing import Iterable, List, Set

from reconforge.core.targets import TargetParser


class AuthorizedScope:
    """Validate resolved targets against an explicit authorization scope."""

    def __init__(self, networks: Iterable[ipaddress.IPv4Network], names: Iterable[str]):
        self.networks = list(networks)
        self.names: Set[str] = {name.lower() for name in names}

    @classmethod
    def from_file(cls, path: Path) -> "AuthorizedScope":
        """Load authorized hosts and CIDRs from a text file."""
        if not path.exists():
            raise ValueError(f"Scope file not found: {path}")
        if not path.is_file():
            raise ValueError(f"Scope path is not a file: {path}")

        parser = TargetParser()
        networks: List[ipaddress.IPv4Network] = []
        names: Set[str] = set()

        for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            entry = raw_line.split("#", 1)[0].strip()
            if not entry:
                continue

            try:
                network = ipaddress.IPv4Network(entry, strict=False)
                networks.append(network)
                continue
            except ValueError:
                pass

            try:
                resolved_hosts = parser.parse_target(entry)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid scope entry on line {line_number}: {entry}. "
                    "Use IPv4 addresses, IPv4 CIDRs, or resolvable hostnames."
                ) from exc

            names.add(entry.lower())
            for host in resolved_hosts:
                networks.append(ipaddress.IPv4Network(f"{host}/32", strict=False))

        if not networks and not names:
            raise ValueError(f"Scope file contains no authorized targets: {path}")

        return cls(networks, names)

    def assert_targets_allowed(self, target: str, resolved_hosts: Iterable[str]) -> None:
        """Raise ValueError if a target or any resolved host falls outside scope."""
        normalized_target = target.strip().lower()
        if normalized_target in self.names:
            return

        outside = []
        for host in resolved_hosts:
            try:
                ip = ipaddress.IPv4Address(host)
            except ValueError as exc:
                raise ValueError(f"Resolved target is not an IPv4 address: {host}") from exc
            if not any(ip in network for network in self.networks):
                outside.append(host)

        if outside:
            shown = ", ".join(outside[:5])
            extra = f" and {len(outside) - 5} more" if len(outside) > 5 else ""
            raise ValueError(f"Target outside authorized scope: {shown}{extra}")
