# Port Scanner

A Python-based port scanner for authorized security testing. Supports
TCP connect scans, SYN (half-open) scans, and UDP probes with
concurrent scanning and service/banner identification.

## Legal Notice

This tool is for authorized testing only. Only scan systems you own
or have explicit written permission to test. Unauthorized scanning is
illegal in many jurisdictions.

Safe targets for practice:
- 127.0.0.1 (your own machine)
- A VM you control
- scanme.nmap.org (provided by Nmap for practice)

## Features

- TCP connect scan (no privileges needed)
- SYN scan via scapy (stealthier - requires root/admin)
- Best-effort UDP scan
- Concurrent scanning via ThreadPoolExecutor
- Service identification (IANA lookup + banner grabbing)
- JSON export for reporting
- Clean CLI with argparse

## Install

    git clone <your-repo-url>
    cd port-scanner
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt

On Windows (Git Bash):

    python -m venv .venv
    source .venv/Scripts/activate
    python -m pip install -r requirements.txt

## Usage

Basic scan of well-known ports:

    python main.py 127.0.0.1 -p 1-1024

Specific ports with banner grabbing:

    python main.py 127.0.0.1 -p 22,80,443

SYN scan (Linux/macOS with sudo):

    sudo python main.py 127.0.0.1 -p 1-1024 --scan-type syn

Faster scan, no banner grabbing, JSON export:

    python main.py 127.0.0.1 -p 1-65535 --no-banner -o output/results.json

## Defensive Trade-offs

| Scan Type   | Privileges | Noise Level | Notes                                         |
|-------------|------------|-------------|-----------------------------------------------|
| TCP Connect | None       | High        | Full handshake - logged by application        |
| SYN (Half)  | Root       | Low         | No full handshake - logged only by firewalls  |
| UDP         | None       | Variable    | Stateless - results ambiguous                 |

## Roadmap

- OS fingerprinting via TTL / TCP window
- Integration with Nmap's service probes (nmap-service-probes)
- Async implementation using asyncio
- Rich terminal UI

## License

MIT - use responsibly.