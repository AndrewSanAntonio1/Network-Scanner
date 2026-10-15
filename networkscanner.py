
#!/usr/bin/env python3
"""
NetworkScanner — authorized lab reconnaissance.

Features:
- Host discovery
- Full TCP port scan (1-65535)
- Service/version detection
- OS fingerprinting
- Optional Nmap vulnerability-category scripts
- XML and normal output reports

No automatic exploitation or lateral movement.
Use only on systems you own or are authorized to assess.
"""

import argparse
import ipaddress
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def validate_target(target):
    """Validate an IP, hostname, or bounded CIDR range."""
    if not target or target.startswith("-"):
        raise ValueError("Invalid target.")

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 1024:
                raise ValueError(
                    "CIDR exceeds 1024 addresses. "
                    "Use a smaller authorized lab range."
                )
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {exc}") from exc
    else:
        try:
            ipaddress.ip_address(target)
        except ValueError:
            # Basic hostname validation.
            if (
                len(target) > 253
                or any(
                    not label
                    or len(label) > 63
                    or label.startswith("-")
                    or label.endswith("-")
                    or not all(
                        c.isalnum() or c == "-"
                        for c in label
                    )
                    for label in target.rstrip(".").split(".")
                )
            ):
                raise ValueError("Invalid IP address or hostname.")


def run_command(command):
    """Run Nmap and return its exit code."""
    print("\n[CMD] " + " ".join(command))
    print("-" * 65)

    try:
        result = subprocess.run(command, check=False)
        return result.returncode
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        return 130
    except OSError as exc:
        print(f"[!] Failed to run Nmap: {exc}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Authorized network reconnaissance using Nmap."
        )
    )

    parser.add_argument(
        "target",
        help="Authorized IP, hostname, or CIDR (up to 1024 addresses)",
    )

    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="Perform host discovery only.",
    )

    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help=(
            "Skip the preliminary discovery phase; useful "
            "for authorized hosts that block discovery probes."
        ),
    )

    parser.add_argument(
        "--ports",
        default="1-65535",
        help="TCP ports/ranges (default: 1-65535).",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=1000,
        help="Nmap host timeout in milliseconds (default: 1000).",
    )

    parser.add_argument(
        "--vuln-check",
        action="store_true",
        help=(
            "Enable Nmap's vuln-category scripts. "
            "Only use with explicit authorization."
        ),
    )

    parser.add_argument(
        "--output",
        default="networkscan",
        help="Output filename prefix (default: networkscan).",
    )

    args = parser.parse_args()

    try:
        validate_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    if not shutil.which("nmap"):
        print("[!] Nmap is not installed.")
        print("    Install it with: sudo apt update && sudo apt install nmap")
        sys.exit(1)

    if not 100 <= args.timeout <= 600000:
        parser.error("--timeout must be between 100 and 600000 ms.")

    if args.output.startswith("-"):
        parser.error("--output must not start with '-'.")
    if not args.output.strip():
        parser.error("--output cannot be empty.")

    # Validate the port expression using Python's ipaddress-independent
    # parser, while allowing Nmap's comma-separated ports and ranges.
    valid_ports = set()
    try:
        for item in args.ports.split(","):
            item = item.strip()
            if not item:
                raise ValueError("Empty port entry.")

            if "-" in item:
                parts = item.split("-")
                if len(parts) != 2:
                    raise ValueError("Invalid port range.")
                start, end = map(int, parts)
                if start > end:
                    raise ValueError("Range start exceeds end.")
                valid_ports.update((start, end))
            else:
                valid_ports.add(int(item))

        if any(p < 1 or p > 65535 for p in valid_ports):
            raise ValueError("Ports must be 1-65535.")

    except ValueError as exc:
        parser.error(f"Invalid --ports: {exc}")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = f"{args.output}_{stamp}"
    xml_file = f"{prefix}.xml"
    normal_file = f"{prefix}.txt"

    print("=" * 65)
    print(" NETWORKSCANNER — AUTHORIZED TESTING ONLY")
    print(f" Target: {args.target}")
    print(f" Started: {datetime.now().astimezone().isoformat()}")
    print(f" Ports: {args.ports}")
    print("=" * 65)

    # Phase 1: host discovery.
    if not args.skip_discovery:
        print("\n[PHASE 1] Host discovery")

        discovery_code = run_command([
            "nmap",
            "-sn",
            "--reason",
            "-oN",
            normal_file,
            args.target,
        ])

        if discovery_code != 0:
            print("[!] Discovery returned a non-zero exit code.")
            print(
                "    If this is an authorized host that blocks "
                "discovery, rerun with --skip-discovery."
            )
            sys.exit(discovery_code)

        if args.discover_only:
            print(f"\n[+] Discovery report: {normal_file}")
            return

    # Phase 2: full TCP ports + service/version + OS fingerprinting.
    print("\n[PHASE 2] TCP ports, services, versions, OS")

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-O",
        "-p",
        args.ports,
        "--reason",
        "--host-timeout",
        f"{args.timeout}ms",
        "-oN",
        normal_file,
        "-oX",
        xml_file,
    ]

    # Optional vulnerability checks. These are detection scripts,
    # not a guarantee that a finding is exploitable.
    if args.vuln_check:
        command.extend(["--script", "vuln"])

    command.append(args.target)

    print(
        "\n[INFO] OS fingerprinting may require root privileges. "
        "Use sudo for your authorized lab if needed."
    )

    scan_code = run_command(command)

    print("\n" + "=" * 65)
    print(" SCAN SUMMARY")
    print("=" * 65)
    print(f" Normal report: {normal_file}")
    print(f" XML report:    {xml_file}")
    print(f" Exit code:     {scan_code}")

    if scan_code == 0:
        print("[+] Nmap finished. Review findings before drawing conclusions.")
    else:
        print("[!] Nmap reported an error or incomplete scan.")

    if args.vuln_check:
        print(
            "[!] Review each reported weakness manually. "
            "Validate software versions, configuration, and applicability."
        )

    print(
        "[i] This tool does not exploit vulnerabilities, "
        "steal credentials, or move laterally."
    )


if __name__ == "__main__":
    main()
