# Network Scanner

A Python command-line wrapper for Nmap that supports **authorized red-team reconnaissance** on systems and labs you are permitted to test. It can discover hosts, scan TCP ports, identify services and versions, perform best-effort OS fingerprinting, and run Nmap's `vuln` category scripts when explicitly requested.

This is not an exploitation framework: it does not attempt to exploit findings, obtain credentials, or perform lateral movement. Its output is technical evidence that must be reviewed and validated.

## Authorization and scope

Use this tool only on systems, subnets, or labs that you own or are explicitly authorized to assess. Before scanning:

1. Confirm the target IP/hostname and the permitted address range.
2. Follow the rules of engagement (RoE), including the testing window, permitted scan types, and incident response contact.
3. Start with a small scope and host discovery. Full-port and vulnerability-script scans can generate additional traffic or affect sensitive services.
4. Store reports securely; they may expose network topology, software versions, and other sensitive details.

Do not decide to attack or move to another host solely because an open port or potential vulnerability was reported.

## Requirements

- Kali Linux (or another system with Python 3 and Nmap)
- Nmap available on `PATH`
- `sudo` for operations that require elevated privileges; OS fingerprinting may require it

### Install on Kali

```bash
sudo apt update
sudo apt install nmap -y
```

Save `networkscanner.py` in your project directory. Check its Python syntax first:

```bash
python3 -m py_compile networkscanner.py
```

No separate Python packages are required; the scanner uses the Python standard library and runs Nmap as a subprocess.

## How it works

For each run, the script validates the target (IP, hostname, or CIDR), port expression, timeout, and output prefix. It accepts CIDR ranges containing up to **1,024 addresses**. It then locates the `nmap` executable and creates timestamped report filenames.

### 1. Host discovery

Unless `--skip-discovery` is used, the script first runs:

```text
nmap -sn --reason -oN <report>.txt <target>
```

`-sn` performs host discovery only; it does not scan ports. `--reason` shows why Nmap considered a host up or down. If this phase fails, the script stops. If `--discover-only` is used without `--skip-discovery`, a successful run ends here.

### 2. TCP port and service scan

If the run is not discovery-only, the script performs an Nmap TCP connect scan (`-sT`) with service/version detection (`-sV --version-light`) and OS fingerprinting (`-O`). By default, it scans TCP ports `1-65535`; use `--ports` to change them. The script also sets the Nmap host timeout and requests scan reasons with `--reason`.

When `--vuln-check` is used, the script adds Nmap's `vuln` script category. These are detection/check scripts, not a complete CVE database and not proof that a finding is exploitable.

### 3. Reports

A full scan creates two reports in the current working directory:

- `<prefix>_<timestamp>.txt` — human-readable normal Nmap output
- `<prefix>_<timestamp>.xml` — XML output for tool-assisted review or parsing

A discovery-only run creates a normal text report only. Use a unique `--output` prefix to organize reports by test or target. Do not commit reports containing sensitive network information.

## Commands

Run these commands from the directory containing `networkscanner.py`. Replace the sample targets with systems or labs covered by your authorization.

### Host discovery only

```bash
python3 networkscanner.py 127.0.0.1 --discover-only
```

### All TCP ports (1–65535), service/version detection, and OS fingerprinting

```bash
sudo python3 networkscanner.py 127.0.0.1
```

### Include Nmap vulnerability-category scripts

```bash
sudo python3 networkscanner.py 127.0.0.1 --vuln-check
```

### Authorized lab subnet

```bash
sudo python3 networkscanner.py 192.168.1.0/24 --vuln-check
```

### Select ports and an output prefix

```bash
python3 networkscanner.py 127.0.0.1 --ports 22,80,443,8000-8100 --output lab-baseline
```

### Skip the separate discovery phase

```bash
sudo python3 networkscanner.py 127.0.0.1 --skip-discovery
```

**Important limitation:** `--skip-discovery` only skips the initial standalone discovery command. The current script does not add Nmap's `-Pn` to the port-scan phase, so Nmap may still use its own host-discovery probes. Therefore, this option does not guarantee that a host blocking discovery probes will be scanned. Do not treat this flag as a firewall bypass.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `target` | None | Required IP address, hostname, or CIDR containing up to 1,024 addresses |
| `--discover-only` | Off | Run only the discovery phase when not combined with `--skip-discovery` |
| `--skip-discovery` | Off | Skip the standalone discovery phase before the port scan |
| `--ports` | `1-65535` | TCP port or comma-separated ports/ranges, e.g. `22,80,443,8000-8100` |
| `--timeout` | `1000` ms | Nmap host timeout; allowed range is `100`–`600000` ms |
| `--vuln-check` | Off | Add Nmap's `vuln` script category |
| `--output` | `networkscan` | Prefix for timestamped report filenames |
| `-h`, `--help` | — | Show the built-in help |

## Red-team review workflow

1. **Plan the test:** Document written authorization, in-scope targets, exclusions, the test window, and the escalation contact.
2. **Discover:** Use `--discover-only` on a small, approved scope. Compare results against the asset inventory, if available.
3. **Enumerate:** Scan only permitted ports and hosts. A full TCP port range can take longer and generate more traffic on larger subnets.
4. **Review the evidence:** Inspect the `.txt` and `.xml` output. Validate service/version and OS guesses; fingerprints may be incorrect or incomplete.
5. **Triage vulnerability findings:** Check applicability, configuration, vendor advisories, and CVE references. Nmap scripts can produce false positives and false negatives.
6. **Report responsibly:** Record the target, time, command/options, findings, confidence, evidence, and remediation suggestions. Share reports only with authorized stakeholders.

## Limitations

- **OS identification:** Fingerprinting is best-effort; the OS may not be identified or may be identified incorrectly. Elevated privileges may be required.
- **Vulnerability coverage:** Nmap scripts are not a complete vulnerability database and do not replace vendor advisories or a dedicated vulnerability management process.
- **Authenticated assessment:** The scanner does not log in to hosts or audit installed packages from inside the host.
- **Exploitation:** Exploitation, credential theft, persistence, and lateral movement are not included.
- **Host discovery:** Hosts that block probes may not be detected. In the current implementation, `--skip-discovery` is not equivalent to Nmap's `-Pn`.
- **TCP only:** The script uses `-sT`; it does not scan UDP ports.

An open port is not automatically a vulnerability, and a script finding is not automatically a confirmed CVE or exploitable condition. Validate findings before assigning a risk rating or making remediation decisions.

## Troubleshooting

- **`Nmap is not installed`** — Install Nmap and ensure it is available on `PATH`.
- **Discovery found no hosts** — Confirm the target is correct, authorized, and reachable. Review Nmap's reason/output; probes may be filtered. Keep the `--skip-discovery` limitation above in mind.
- **OS detection did not work** — Try with `sudo` in an authorized lab; fingerprinting is still best-effort.
- **The scan is slow or incomplete** — Reduce the target range or select only the ports covered by the test. Increase `--timeout` if appropriate for the rules of engagement and environment.
- **Reports are not where expected** — Reports are created in the current working directory, using the output prefix and timestamp.
