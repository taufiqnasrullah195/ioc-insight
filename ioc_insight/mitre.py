"""MITRE ATT&CK mapping from analyzer tags/signals. TRD Phase 2 P2.3.

Deterministic tag→technique table; unmapped tags pass through untouched.
The mapping covers the signals our analyzers actually produce — extend
TAG_MAP as new analyzers/tags arrive.
"""
from __future__ import annotations

from .models import AnalyzerResult

# tag substring → (technique id, name)
TAG_MAP: list[tuple[str, str, str]] = [
    ("brute-force", "T1110", "Brute Force"),
    ("ssh", "T1021.004", "Remote Services: SSH"),
    ("ddos", "T1498", "Network Denial of Service"),
    ("port-scan", "T1046", "Network Service Discovery"),
    ("c2", "T1071", "Application Layer Protocol (C2)"),
    ("botnet", "T1584", "Compromise Infrastructure"),
    ("phishing", "T1566", "Phishing"),
    ("malware", "T1204", "User Execution"),
    ("tor-exit", "T1090.003", "Proxy: Multi-hop (Tor)"),
    ("newly-registered", "T1583.001", "Acquire Infrastructure: Domains"),
    ("young-domain", "T1583.001", "Acquire Infrastructure: Domains"),
    ("spam", "T1566", "Phishing"),
    ("scanner", "T1595", "Active Scanning"),
    ("internet-noise", "T1595", "Active Scanning (background)"),
]


def map_techniques(results: list[AnalyzerResult]) -> list[dict]:
    """Return deduped [{id, name, sources}] from all analyzer tags."""
    found: dict[str, dict] = {}
    for r in results:
        if not r.success:
            continue
        for tag in r.tags:
            for needle, tid, name in TAG_MAP:
                if needle in tag.lower():
                    entry = found.setdefault(tid, {"id": tid, "name": name, "sources": set()})
                    entry["sources"].add(r.source)
                    break
    return [
        {"id": e["id"], "name": e["name"], "sources": sorted(e["sources"])}
        for e in sorted(found.values(), key=lambda x: x["id"])
    ]
