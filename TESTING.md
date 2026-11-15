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
- Automated Unit Tests

## Test 1: Localhost scan
Command: python main.py 127.0.0.1 -p 1-100 --no-banner
Result: 
    Scan complete in 5.05s — 0 open port(s) found
    No open ports found in the specified range.

## Test 2: Banner grabbing
Command: python main.py 127.0.0.1 -p 22,80,443
Result:
    Scan complete in 5.05s — 0 open port(s) found
    No open ports found in the specified range.

## Test 3: Practice host (scanme.nmap.org)
Command: python main.py scanme.nmap.org -p 1-1000 --workers 200
Result:
    Scan complete in 8.40s — 2 open port(s) found

    PORT    PROTO  STATE         SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open          ssh            
    80      tcp    open          http           

## Test 4: SYN scan
Command: python main.py scanme.nmap.org -p 1-100 --scan-type syn -v 
(Note: This command was run from CMD as administrator, using Npcap because it bypasses Windows' native raw socket restrictions through a driver, allowing Scapy to send custom TCP packets [including SYN packets.])
Result:
    Scan complete in 42.61s — 2 open port(s) found

    PORT    PROTO  STATE         SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open          ssh
    80      tcp    open          http

## Test 5: JSON export
Command: python main.py scanme.nmap.org -p 1-100 -o output/scan.json
Result:
    Scan complete in 3.99s — 2 open port(s) found

    PORT    PROTO  STATE         SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open          ssh            
    80      tcp    open          http           

    [+] Results written to output\scan.json

    scan.json file contents:
    {
        "target": "scanme.nmap.org",
        "scan_type": "tcp",
        "started_at": "2026-11-15T21:47:50.242628",
        "elapsed_seconds": 3.99,
        "results": [
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "banner": ""
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

## Test 6: Opening port via listener.py and testing it
(Opening port)  
Command: python listener.py
Result: 
    Listening on 127.0.0.1:55179
    Press Enter to close...
(Testing port 55179)    
Command: python main.py 127.0.0.1 -p 55179
Result:
    Scanning 127.0.0.1 ports 55179-55179 with 100 workers
    Scan complete in 2.03s — 1 open port(s) found

    PORT    PROTO  STATE         SERVICE        BANNER
    --------------------------------------------------------------------------------
    55179   tcp    open          unknown 
(After closing port 55179)
Command: python main.py 127.0.0.1 -p 55179
Result:
    Scan complete in 1.00s — 0 open port(s) found
    No open ports found in the specified range.

## Test 7: Known closed port
Command: python main.py 127.0.0.1 -p 54321
Result: 
    Scan complete in 1.04s — 0 open port(s) found
    No open ports found in the specified range.

## Test 8: Service identification accuracy
Command: python main.py scanme.nmap.org -p 22,80
Result:
    Scan complete in 4.09s — 2 open port(s) found

    PORT    PROTO  STATE         SERVICE        BANNER
    --------------------------------------------------------------------------------
    22      tcp    open          ssh            SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.
    80      tcp    open          http           

## Test 9: Invalid hostname handling
Command: python main.py this-host-does-not-exist.invalid -p 1-100
Result:
    [!] Could not resolve hostname: this-host-does-not-exist.invalid

## Test 10: Invalid port input validation
Command: python main.py 127.0.0.1 -p 0
Result: 
    [!] Port out of bounds: 0

Command: python main.py 127.0.0.1 -p 70000
Result:
    [!] Port out of bounds: 70000

Command: python main.py 127.0.0.1 -p abc
Result:
    [!] Invalid port: abc

Command: python main.py 127.0.0.1 -p 100-50
Result:
    [!] Port range out of bounds: 100-50

## Test 11: Timeout behavior
Command: python main.py 127.0.0.1 -p 1-10 --timeout 0.3
Result:
    Scan complete in 0.31s — 0 open port(s) found
    No open ports found in the specified range.

## Test 12: Empty result formatting
Command: python main.py 127.0.0.1 -p 54321
Result: 
    Scan complete in 1.02s — 0 open port(s) found
    No open ports found in the specified range.

## Automated Unit Tests

Tool: pytest
Command: pytest
Result: 18 passed in 1.17s

Coverage:
- Port scanning logic (open/closed detection, range scanning) - real sockets on localhost
- Service lookup (IANA port - name mapping) - deterministic
- Input validation (valid specs accepted, invalid specs rejected) - deterministic
- Error handling (DNS failure returns False instead of raising) - mocked, no network

The mock-based tests (test_*_mocked) do not send any network traffic.
They patch socket.socket to simulate connect_ex return values, making
them fast, deterministic, and safe to run in CI.

