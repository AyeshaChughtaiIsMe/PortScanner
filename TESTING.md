# Testing Log

Environment: Windows 11, Python 3.10, Git Bash, venv
Date: 2026-11-15

## Contents

- Test 1: Localhost scan
- Test 2: Banner grabbing
- Test 3: Practice host (scanme.nmap.org)
- Test 4: SYN scan
- Test 5: JSON export
- Test 6: Opening port via listener.py and testing it
- Test 7: Known closed port
- Test 8: Service identification accuracy
- Test 9: Invalid hostname handling
- Test 10: Invalid port input validation
- Test 11: Timeout behavior
- Test 12: Empty result formatting
- Test 13: State summary output
- Test 14: Multiple hosts with discovery
- Test 15: Top-ports mode
- Test 16: CSV and XML export
- Automated Unit Tests
- Reproducibility Check

## All commands were run from the project root with the virtual environment active.
## The scanner is invoked as `python -m portscanner` because the code lives in the `portscanner`
## package; `python main.py` still works as a shim from a checkout.

## Test 1: Localhost scan (TCP connect)
Command: python -m portscanner 127.0.0.1 -p 1-100 --no-banner
Result:
    TCP connect scan against 127.0.0.1, 100 port(s)
    100/100 ports probed
    Scan complete in 1.13s — 0 open port(s) found (0 open, 100 filtered)
    No open ports found in the specified range.

## Test 2: Banner grabbing
Command: python -m portscanner 127.0.0.1 -p 22,80,443
Result:
    TCP connect scan against 127.0.0.1, 3 port(s)
    3/3 ports probed
    Scan complete in 1.02s — 0 open port(s) found (0 open, 3 filtered)
    No open ports found in the specified range.

## Test 3: Practice host (scanme.nmap.org)
Command: python -m portscanner scanme.nmap.org -p 1-1000 --workers 200
Result:
    TCP connect scan against scanme.nmap.org (45.33.32.156), 1000 port(s)
    1000/1000 ports probed
    Scan complete in 7.74s — 2 open port(s) found (2 open, 998 filtered)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open           ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80      tcp    open           http           HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu) 

## Test 4: SYN scan
Command: python -m portscanner scanme.nmap.org -p 1-100 --scan-type syn -v 
(Note: This command was run from CMD as administrator, using Npcap because it bypasses Windows' native raw socket restrictions through a driver, allowing Scapy to send custom TCP packets [including SYN packets.])
Result:
    SYN scan against scanme.nmap.org (45.33.32.156), 100 port(s)
    100/100 ports probed
    Scan complete in 4.35s — 2 open port(s) found (2 open, 97 closed, 1 filtered)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open           ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80      tcp    open           http           HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)

## Test 5: JSON export
Command: python -m portscanner scanme.nmap.org -p 1-100 -o output/scan.json
Result:
    TCP connect scan against scanme.nmap.org (45.33.32.156), 100 port(s)
    100/100 ports probed
    Scan complete in 5.06s — 2 open port(s) found (2 open, 98 filtered)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open           ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80      tcp    open           http           

    Use --show-all to list closed and filtered ports.

    Results written to output\scan.json

    scan.json file contents:
    {
        "scan_type": "tcp",
        "started_at": "2026-11-21T23:26:17.473284",
        "finished_at": "2026-11-21T23:26:22.530780",
        "elapsed_seconds": 5.06,
        "hosts": [
            {
            "target": "scanme.nmap.org",
            "ip": "45.33.32.156",
            "state": "up",
            "summary": {
                "filtered": 98,
                "open": 2
            },
            "ports": [
                {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
                },
                {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "banner": ""
                }
            ]
            }
        ]
    }

## Test 6: Opening port via listener.py and testing it
(Opening port)  
Command: python listener.py
Result: 
    Listening on 127.0.0.1:56845
    Press Enter to close...
(Testing port 56845)    
Command: python main.py 127.0.0.1 -p 56845
Result:
    TCP connect scan against 127.0.0.1, 1 port(s)
    1/1 ports probed
    Scan complete in 4.03s — 1 open port(s) found (1 open)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    56845   tcp    open           unknown   
(After closing port 56845)
Command: python main.py 127.0.0.1 -p 56845
Result:
    TCP connect scan against 127.0.0.1, 1 port(s)
    1/1 ports probed
    Scan complete in 1.02s — 0 open port(s) found (0 open, 1 filtered)
    No open ports found in the specified range

## Test 7: Known closed port
Command:  python -m portscanner 127.0.0.1 -p 54321
Result: 
    TCP connect scan against 127.0.0.1, 1 port(s)
    1/1 ports probed
    Scan complete in 1.03s — 0 open port(s) found (0 open, 1 filtered)
    No open ports found in the specified range.

## Test 8: Service identification accuracy
Command: python -m portscanner scanme.nmap.org -p 22,80
Result:
    TCP connect scan against scanme.nmap.org (45.33.32.156), 2 port(s)
    2/2 ports probed
    Scan complete in 2.18s — 2 open port(s) found (2 open)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open           ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80      tcp    open           http           HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)   

## Test 9: Invalid hostname handling
Command: python -m portscanner this-host-does-not-exist.invalid -p 1-100
Result:
    [!] Could not resolve hostname: this-host-does-not-exist.invalid
    [!] No target could be resolved.

## Test 10: Invalid port input validation
Command: python -m portscanner 127.0.0.1 -p 0
Result: 
    [!] Port out of bounds: 0

Command: python -m portscanner 127.0.0.1 -p 70000
Result:
    [!] Port out of bounds: 70000

Command: python -m portscanner 127.0.0.1 -p abc
Result:
    [!] Invalid port: abc

Command: python -m portscanner 127.0.0.1 -p 100-50
Result:
    [!] Port range out of bounds: 100-50

## Test 11: Timeout behavior
Command: python -m portscanner 127.0.0.1 -p 1-10 --timeout 0.3
Result: 
    TCP connect scan against 127.0.0.1, 10 port(s)
    10/10 ports probed
    Scan complete in 0.36s — 0 open port(s) found (0 open, 10 filtered)
    No open ports found in the specified range.

Command: python -m portscanner 127.0.0.1 -p 1-10 --timeout 0.2
Result: 
    TCP connect scan against 127.0.0.1, 10 port(s)
    10/10 ports probed
    Scan complete in 0.22s — 0 open port(s) found (0 open, 10 filtered)
    No open ports found in the specified range.

## Test 12: Empty result formatting
Command: python -m portscanner 127.0.0.1 -p 54321
Result: 
    TCP connect scan against 127.0.0.1, 1 port(s)
    1/1 ports probed
    Scan complete in 1.01s — 0 open port(s) found (0 open, 1 filtered)
    No open ports found in the specified range.

## Test 13: State summary output
Command: python -m portscanner 127.0.0.1 -p 1-20 --show-all
Result:
    TCP connect scan against 127.0.0.1, 20 port(s)
    20/20 ports probed
    Scan complete in 1.04s — 0 open port(s) found (0 open, 20 filtered)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    1       tcp    filtered       unknown        
    2       tcp    filtered       unknown        
    3       tcp    filtered       unknown        
    4       tcp    filtered       unknown        
    5       tcp    filtered       unknown        
    6       tcp    filtered       unknown        
    7       tcp    filtered       echo           
    8       tcp    filtered       unknown        
    9       tcp    filtered       discard        
    10      tcp    filtered       unknown        
    11      tcp    filtered       systat         
    12      tcp    filtered       unknown        
    13      tcp    filtered       daytime        
    14      tcp    filtered       unknown        
    15      tcp    filtered       unknown        
    16      tcp    filtered       unknown        
    17      tcp    filtered       qotd           
    18      tcp    filtered       unknown        
    19      tcp    filtered       chargen        
    20      tcp    filtered       ftp-data      

## Test 14: Multiple hosts with discovery
Command: python -m portscanner 127.0.0.1 scanme.nmap.org -p 22,80
Result:
    Checking which of 2 hosts are up
    2 up. Hosts that drop all traffic look down; use --skip-discovery to scan them anyway.
    127.0.0.1: 0 open, 2 filtered
    scanme.nmap.org (45.33.32.156): 2 open
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open           ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80      tcp    open           http           HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)
    Scan complete in 3.95s — 2 open port(s) found on 2 host(s) (0 down)

## Test 15: Top-ports mode
Command: python -m portscanner scanme.nmap.org --top-ports 100
Result:
    TCP connect scan against scanme.nmap.org (45.33.32.156), 100 port(s)
    100/100 ports probed
    Scan complete in 2.72s — 4 open port(s) found (4 open, 96 filtered)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open           ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80      tcp    open           http           HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)
    2000    tcp    open           unknown        
    5060    tcp    open           unknown        

## Test 16: CSV and XML export
Command: python -m portscanner scanme.nmap.org -p 22,80 -o output/scan.csv
Result:
    TCP connect scan against scanme.nmap.org (45.33.32.156), 2 port(s)
    2/2 ports probed
    Scan complete in 1.93s — 2 open port(s) found (2 open)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open           ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80      tcp    open           http           HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)
    
    Results written to output\scan.csv

    scan.csv contents:
        target,ip,port,protocol,state,service,banner
        scanme.nmap.org,45.33.32.156,22,tcp,open,ssh,SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
        scanme.nmap.org,45.33.32.156,80,tcp,open,http,HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)

Command: python -m portscanner scanme.nmap.org -p 22,80 -o output/scan.xml
Result:
    TCP connect scan against scanme.nmap.org (45.33.32.156), 2 port(s)
    2/2 ports probed
    Scan complete in 2.64s — 1 open port(s) found (1 open, 1 filtered)
    PORT    PROTO  STATE          SERVICE        BANNER
    --------------------------------------------------------------------------------
    80      tcp    open           http           HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)

    Use --show-all to list closed and filtered ports.

    Results written to output\scan.xml

    scan.xml contents:

    <?xml version='1.0' encoding='cp1252'?>
        <nmaprun scanner="portscanner" start="1795297398" startstr="2026-11-21T23:43:18.241205">
        <scaninfo type="tcp" />
        <host>
            <status state="up" />
            <address addr="45.33.32.156" addrtype="ipv4" />
            <hostnames>
            <hostname name="scanme.nmap.org" type="user" />
            </hostnames>
            <ports>
            <port protocol="tcp" portid="80">
                <state state="open" />
                <service name="http" />
                <script id="banner" output="HTTP/1.1 200 OK | Server: Apache/2.4.7 (Ubuntu)" />
            </port>
            </ports>
        </host>
        <runstats>
            <finished timestr="2026-11-21T23:43:20.873210" elapsed="2.64" />
            <hosts up="1" down="0" total="1" />
        </runstats>
    </nmaprun>

## Automated Tests

Tool: pytest
Command: python -m pytest
Result:
    152 passed, 1 skipped in 19.37s

(Note: 1 skipped — requires the openssl CLI, not installed on this Windows machine.)

Coverage highlights:
- CLI argument parsing and validation
- TCP, SYN and UDP scan engines
- Target expansion (CIDR, ranges, files) and resolution
- Output formats (JSON, CSV, XML)
- Regression tests for previously fixed bugs

The suite is run automatically by GitHub Actions on Ubuntu, Windows and macOS against Python 3.10 and 3.13.
