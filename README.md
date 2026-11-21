# Port Scanner

A Python port scanner for authorized security testing. It runs TCP
connect scans, SYN (half-open) scans and UDP probes against one host or
a whole network, reports each port as open, closed or filtered, and
identifies the services it finds.

## Legal Notice

This tool is for authorized testing only. Only scan systems you own
or have explicit written permission to test. Unauthorized scanning is
illegal in many jurisdictions.

Safe targets for practice:
- 127.0.0.1 (your own machine)
- A VM you control
- scanme.nmap.org (provided by Nmap for practice)

## Features

- **Three scan types:** TCP connect (no privileges needed), SYN via
  scapy (root/admin), and UDP with real DNS, NTP, SNMP, SSDP and NetBIOS
  requests
- **Port states:** open, closed or filtered, not just open
- **Many targets:** several hosts, CIDR blocks (`192.168.1.0/24`),
  last-octet ranges (`192.168.1.10-20`), or a file of targets
- **IPv4 and IPv6**
- **Host discovery:** dead hosts are skipped when scanning a range
- **Service identification:** IANA port lookup, banners from services
  that speak first (SSH, FTP, SMTP), an HTTP request for web servers,
  and a TLS handshake for encrypted ports
- **Speed and control:** concurrent probes, batched SYN scans, retries
  and a probes-per-second limit
- **Reports:** JSON, CSV or Nmap-style XML

## Install

    git clone https://github.com/AyeshaChughtaiIsMe/PortScanner.git
    cd PortScanner
    python3 -m venv .venv && source .venv/bin/activate
    pip install .

On Windows (Git Bash):

    python -m venv .venv
    source .venv/Scripts/activate
    python -m pip install .

This installs a `portscan` command. TCP connect and UDP scans need
nothing beyond Python 3.10+. For SYN scans, install scapy as well:

    pip install ".[syn]"

SYN scans on Windows also need [Npcap](https://npcap.com/).

You can also run it without installing, from the checkout:

    python main.py 127.0.0.1 -p 1-1024

## Usage

Scan the default ports (1-1024) on one host:

    portscan 127.0.0.1

Specific ports, with banners:

    portscan scanme.nmap.org -p 22,80,443

The 100 most commonly open ports:

    portscan scanme.nmap.org --top-ports 100

Show closed and filtered ports too:

    portscan 127.0.0.1 -p 1-100 --show-all

SYN scan (Linux/macOS with sudo, Windows as administrator):

    sudo portscan 127.0.0.1 -p 1-1024 --scan-type syn

UDP scan of common UDP services:

    portscan 192.168.1.1 -p 53,123,161,1900 --scan-type udp

A whole network, written to CSV:

    portscan 192.168.1.0/24 -p 22,80,443 -o lan.csv

Targets from a file, gently (50 probes per second, one retry):

    portscan -iL targets.txt --top-ports 20 --rate 50 --retries 1

An IPv6 host:

    portscan ::1 -p 1-1024

### Options

| Option | Meaning |
|--------|---------|
| `target ...` | Hostnames, IPs, CIDR blocks or last-octet ranges |
| `-iL FILE` | Read targets from a file, one per line (`#` comments allowed) |
| `-6` | Prefer IPv6 when a hostname has both address types |
| `--skip-discovery` | Scan every target without checking it is up first |
| `-p PORTS` | Ports such as `22,80,443` or `1-1024` (default `1-1024`) |
| `--top-ports N` | The N most commonly open TCP ports (1-100) |
| `-t {tcp,syn,udp}` | Scan type (default `tcp`) |
| `--timeout SECONDS` | Per-port timeout (default 1.0) |
| `--workers N` | Concurrent threads (default 100) |
| `--retries N` | Extra attempts for ports that give no answer (default 0) |
| `--rate N` | Maximum probes per second for tcp/udp (default unlimited) |
| `--no-banner` | Skip service identification (faster) |
| `--show-all` | List closed and filtered ports, not only open ones |
| `-o PATH` | Write a report; format follows `.json`, `.csv` or `.xml` |
| `--format` | Force the report format |
| `--no-progress` | Hide the live progress counter |
| `-v` | Debug logging |

## Understanding the results

| State | Meaning |
|-------|---------|
| `open` | The port answered: something is listening |
| `closed` | The host actively refused: it is up, nothing is listening |
| `filtered` | No answer at all, usually a firewall dropping packets |
| `open\|filtered` | UDP only: silence could mean either |
| `unknown` | The probe itself failed on this machine |

When several targets are given, the scanner first checks which hosts are
up by trying TCP ports 80, 443, 22 and 445; any answer, even a refusal,
counts. A host that silently drops all four looks down. Use
`--skip-discovery` to scan such hosts anyway.

At most 65,536 hosts (a /16) can be scanned in one run.

On Windows, a closed port on your own machine takes about two seconds to
refuse a connection, so with the default one-second timeout it shows as
`filtered`. Use `--timeout 3` to see it as `closed`.

## Report formats

JSON reports hold one entry per host:

    {
      "scan_type": "tcp",
      "started_at": "2026-11-15T21:47:50.242628",
      "finished_at": "2026-11-15T21:47:54.231004",
      "elapsed_seconds": 3.99,
      "hosts": [
        {
          "target": "scanme.nmap.org",
          "ip": "45.33.32.156",
          "state": "up",
          "summary": {"open": 2, "closed": 98},
          "ports": [
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": "ssh", "banner": "SSH-2.0-OpenSSH_6.6.1p1"}
          ]
        }
      ]
    }

`summary` always counts every probed port. `ports` lists the open ones,
or all of them with `--show-all`.

CSV has one row per listed port: `target, ip, port, protocol, state,
service, banner`. XML follows the layout of Nmap's `-oX` output
(`nmaprun/host/ports/port`); it is not a complete implementation of the
Nmap DTD.

## Defensive Trade-offs

| Scan Type   | Privileges | Noise Level | Notes                                         |
|-------------|------------|-------------|-----------------------------------------------|
| TCP Connect | None       | High        | Full handshake - logged by application        |
| SYN (Half)  | Root       | Low         | No full handshake - logged only by firewalls  |
| UDP         | None       | Variable    | Stateless - results ambiguous                 |

## Project layout

    portscanner/
      cli.py         command-line interface
      scanner.py     TCP connect, SYN and UDP scan engine
      banner.py      service identification
      targets.py     target expansion and name resolution
      discovery.py   host discovery
      ports.py       port parsing and the common-port list
      output.py      JSON, CSV and XML report writers
      models.py      result data classes
    tests/           pytest suite
    listener.py      opens a local port to practise against
    main.py          runs the scanner from a checkout

## Development

    pip install -e ".[dev,syn]"
    pytest

The tests only touch 127.0.0.1 and `::1`. SYN scan tests use a stand-in
for scapy, so they need neither scapy nor root. See `TESTING.md` for the
manual testing log.

## Roadmap

- OS fingerprinting via TTL / TCP window
- Integration with Nmap's service probes (nmap-service-probes)
- Async implementation using asyncio
- ICMP echo for host discovery
- TLS certificate details in banners

## License

MIT - use responsibly.
