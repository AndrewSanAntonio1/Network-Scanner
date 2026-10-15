
#!/usr/bin/env python3
"""
NetworkScanner — authorized lab reconnaissance.

Features:
- Host discovery
- Full TCP port scan (1-65535)
- Service/version detection
- OS fingerprinting
- Optional Nmap vulnerability-category scripts
- Text, XML, and optional JSON reports

No automatic exploitation or lateral movement.
Use only on systems you own or are authorized to assess.
"""

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree


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


def parse_nmap_xml(xml_file):
    """Convert Nmap XML output into a JSON-serializable scan result."""
    root = ElementTree.parse(xml_file).getroot()
    hosts = []
    script_results = []
    open_tcp_ports = 0

    for host in root.findall("host"):
        addresses = [
            {
                "address": address.get("addr"),
                "type": address.get("addrtype"),
                "vendor": address.get("vendor"),
            }
            for address in host.findall("address")
        ]
        host_address = next(
            (
                address["address"]
                for address in addresses
                if address["type"] in ("ipv4", "ipv6")
            ),
            addresses[0]["address"] if addresses else None,
        )

        ports = []
        for port in host.findall("./ports/port"):
            state_element = port.find("state")
            service_element = port.find("service")
            state = state_element.get("state") if state_element is not None else None
            protocol = port.get("protocol")
            if protocol == "tcp" and state == "open":
                open_tcp_ports += 1

            service = None
            if service_element is not None:
                service = {
                    key: service_element.get(key)
                    for key in ("name", "product", "version", "extrainfo", "tunnel", "method", "conf")
                    if service_element.get(key) is not None
                }
                service["cpe"] = [
                    cpe.text for cpe in service_element.findall("cpe") if cpe.text
                ]

            port_entry = {
                "protocol": protocol,
                "port": int(port.get("portid")),
                "state": state,
                "reason": state_element.get("reason") if state_element is not None else None,
                "service": service,
                "scripts": [],
            }
            for script in port.findall("script"):
                result = {
                    "host": host_address,
                    "port": port_entry["port"],
                    "protocol": protocol,
                    "id": script.get("id"),
                    "output": script.get("output", ""),
                }
                port_entry["scripts"].append(result)
                script_results.append(result)
            ports.append(port_entry)

        host_scripts = []
        for script in host.findall("./hostscript/script"):
            result = {
                "host": host_address,
                "port": None,
                "protocol": None,
                "id": script.get("id"),
                "output": script.get("output", ""),
            }
            host_scripts.append(result)
            script_results.append(result)

        status_element = host.find("status")
        hostnames = [
            {"name": name.get("name"), "type": name.get("type")}
            for name in host.findall("./hostnames/hostname")
        ]
        os_matches = []
        for match in host.findall("./os/osmatch"):
            os_matches.append({
                "name": match.get("name"),
                "accuracy": match.get("accuracy"),
                "classes": [
                    {
                        key: os_class.get(key)
                        for key in ("type", "vendor", "osfamily", "osgen", "accuracy")
                        if os_class.get(key) is not None
                    }
                    for os_class in match.findall("osclass")
                ],
            })

        hosts.append({
            "status": status_element.get("state") if status_element is not None else None,
            "addresses": addresses,
            "hostnames": hostnames,
            "ports": ports,
            "os_matches": os_matches,
            "host_scripts": host_scripts,
        })

    up_hosts = sum(host["status"] == "up" for host in hosts)
    down_hosts = sum(host["status"] == "down" for host in hosts)
    finished = root.find("./runstats/finished")

    return {
        "nmap": {
            "scanner": root.get("scanner"),
            "version": root.get("version"),
            "arguments": root.get("args"),
            "start": root.get("start"),
            "finished": finished.attrib if finished is not None else None,
        },
        "summary": {
            "hosts_up": up_hosts,
            "hosts_down": down_hosts,
            "open_tcp_ports": open_tcp_ports,
            "script_results": len(script_results),
        },
        "hosts": hosts,
        "script_results": script_results,
    }


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
        "--full",
        action="store_true",
        help="Run the full authorized reconnaissance workflow.",
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
        default=None,
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

    parser.add_argument(
        "--json",
        action="store_true",
        help="Save a structured JSON summary alongside the TXT and XML reports.",
    )

    args = parser.parse_args()

    if args.full and args.discover_only:
        parser.error("--full cannot be combined with --discover-only.")
    if args.full and args.skip_discovery:
        parser.error("--full includes host discovery and cannot be combined with --skip-discovery.")
    if args.json and args.discover_only:
        parser.error("--json requires a port scan and cannot be combined with --discover-only.")
    if args.full and args.ports not in (None, "1-65535"):
        parser.error("--full always scans TCP ports 1-65535; remove --ports.")

    ports = args.ports or "1-65535"

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
        for item in ports.split(","):
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

    started_at = datetime.now().astimezone()
    stamp = started_at.strftime("%Y%m%d_%H%M%S")
    prefix = f"{args.output}_{stamp}"
    xml_file = f"{prefix}.xml"
    normal_file = f"{prefix}.txt"
    discovery_file = f"{prefix}_discovery.txt"
    json_file = f"{prefix}.json"

    run_vuln_checks = args.full or args.vuln_check

    print("=" * 65)
    print(" NETWORKSCANNER — AUTHORIZED TESTING ONLY")
    print(f" Target: {args.target}")
    print(f" Started: {started_at.isoformat()}")
    print(f" Ports: {ports}")
    if args.full:
        print(" Mode:   Full authorized reconnaissance")
    print("=" * 65)

    # Phase 1: host discovery.
    if not args.skip_discovery:
        print("\n[PHASE 1/7] Host discovery" if args.full else "\n[PHASE 1] Host discovery")

        discovery_code = run_command([
            "nmap",
            "-sn",
            "--reason",
            "-oN",
            discovery_file,
            args.target,
        ])

        if discovery_code != 0:
            print("[!] Discovery returned a non-zero exit code.")
            if args.full:
                print(
                    "    --full requires successful host discovery. "
                    "Review target reachability and authorization."
                )
            else:
                print(
                    "    If this is an authorized host that blocks "
                    "discovery, rerun with --skip-discovery."
                )
            sys.exit(discovery_code)

        if args.discover_only:
            print(f"\n[+] Discovery report: {discovery_file}")
            return

    # Phase 2: full TCP ports + service/version + OS fingerprinting.
    if args.full:
        print("\n[PHASE 2/7] Full TCP port scan (1-65535)")
        print("[PHASE 3/7] Service detection")
        print("[PHASE 4/7] Version detection")
        print("[PHASE 5/7] Best-effort OS detection")
        print("[PHASE 6/7] Authorized vulnerability checks")
        print("[INFO] Nmap performs these checks in the port-scan command below.")
    else:
        print("\n[PHASE 2] TCP ports, services, versions, OS")

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--version-light",
        "-O",
        "-p",
        ports,
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
    if run_vuln_checks:
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

    if run_vuln_checks:
        print(
            "[!] Review each reported weakness manually. "
            "Validate software versions, configuration, and applicability."
        )

    if args.json:
        try:
            report = parse_nmap_xml(xml_file)
            report.update({
                "target": args.target,
                "mode": "full" if args.full else "custom",
                "ports_scanned": ports,
                "vulnerability_checks_enabled": run_vuln_checks,
                "nmap_exit_code": scan_code,
                "started_at": started_at.isoformat(),
                "reports": {
                    "text": normal_file,
                    "xml": xml_file,
                    "discovery": discovery_file if not args.skip_discovery else None,
                },
            })
            Path(json_file).write_text(
                json.dumps(report, indent=2) + "\n",
                encoding="utf-8",
            )
        except (OSError, ElementTree.ParseError) as exc:
            print(f"[!] Could not create JSON report: {exc}")
            sys.exit(1)
        print(f" JSON report:   {json_file}")
        print(
            "[+] Summary: "
            f"{report['summary']['hosts_up']} host(s) up, "
            f"{report['summary']['open_tcp_ports']} open TCP port(s), "
            f"{report['summary']['script_results']} script result(s)."
        )

    if args.full:
        report_files = [discovery_file, normal_file, xml_file]
        if args.json:
            report_files.append(json_file)
        print(f"[PHASE 7/7] Reports saved: {', '.join(report_files)}")

    print(
        "[i] This tool does not exploit vulnerabilities, "
        "steal credentials, or move laterally."
    )


if __name__ == "__main__":
    main()
