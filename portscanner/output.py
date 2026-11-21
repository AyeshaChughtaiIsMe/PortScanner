"""
output.py
---------
Writing a scan report to disk as JSON, CSV or Nmap-style XML.

A report is a plain dict:

    {
      "scan_type": "tcp",
      "started_at": "...", "finished_at": "...", "elapsed_seconds": 1.23,
      "hosts": [
        {"target": "example.org", "ip": "93.184.216.34", "state": "up",
         "summary": {"open": 2, "closed": 98},
         "ports": [{"port": 80, "protocol": "tcp", "state": "open",
                    "service": "http", "banner": "..."}]}
      ]
    }
"""

import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

FORMATS = ("json", "csv", "xml")
CSV_COLUMNS = ["target", "ip", "port", "protocol", "state", "service", "banner"]


def format_for(path: str, explicit: str | None = None) -> str:
    """Pick the output format: --format wins, else the file extension."""
    if explicit:
        return explicit
    suffix = Path(path).suffix.lower().lstrip(".")
    return suffix if suffix in FORMATS else "json"


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def write_csv(report: dict, handle) -> None:
    """One row per reported port."""
    writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for host in report["hosts"]:
        for port in host["ports"]:
            writer.writerow({"target": host["target"], "ip": host["ip"],
                             **{k: port[k] for k in CSV_COLUMNS[2:]}})


def to_xml(report: dict) -> str:
    """
    XML laid out like Nmap's -oX output (nmaprun/host/ports/port), so
    tools that read that structure can read this too. It follows the
    layout, not the full Nmap DTD.
    """
    started = datetime.fromisoformat(report["started_at"])
    root = ET.Element("nmaprun", scanner="portscanner",
                      start=str(int(started.timestamp())),
                      startstr=report["started_at"])
    ET.SubElement(root, "scaninfo", type=report["scan_type"])

    for host in report["hosts"]:
        node = ET.SubElement(root, "host")
        ET.SubElement(node, "status", state=host["state"])
        addrtype = "ipv6" if ":" in host["ip"] else "ipv4"
        ET.SubElement(node, "address", addr=host["ip"], addrtype=addrtype)
        if host["target"] != host["ip"]:
            names = ET.SubElement(node, "hostnames")
            ET.SubElement(names, "hostname", name=host["target"], type="user")
        ports = ET.SubElement(node, "ports")
        for port in host["ports"]:
            entry = ET.SubElement(ports, "port", protocol=port["protocol"],
                                  portid=str(port["port"]))
            ET.SubElement(entry, "state", state=port["state"])
            ET.SubElement(entry, "service", name=port["service"])
            if port["banner"]:
                ET.SubElement(entry, "script", id="banner",
                              output=port["banner"])

    stats = ET.SubElement(root, "runstats")
    ET.SubElement(stats, "finished", timestr=report["finished_at"],
                  elapsed=str(report["elapsed_seconds"]))
    up = sum(1 for host in report["hosts"] if host["state"] == "up")
    ET.SubElement(stats, "hosts", up=str(up),
                  down=str(len(report["hosts"]) - up),
                  total=str(len(report["hosts"])))
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def write_report(report: dict, path: str, fmt: str | None = None) -> Path:
    """Write the report in the chosen format; returns the path written."""
    fmt = format_for(path, fmt)
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv":
        with out_path.open("w", newline="", encoding="utf-8") as handle:
            write_csv(report, handle)
    elif fmt == "xml":
        out_path.write_text(to_xml(report), encoding="utf-8")
    else:
        out_path.write_text(to_json(report), encoding="utf-8")
    return out_path
