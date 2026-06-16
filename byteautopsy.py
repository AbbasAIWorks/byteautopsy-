#!/usr/bin/env python3
"""
ByteAutopsy - Automated PE Static Analysis & SOC Report Generator
====================================================================

A lightweight CLI tool that performs static analysis on Windows PE
files (.exe / .dll) and auto-generates a SOC-ready Markdown/JSON
report, including:

  - File hashes (MD5 / SHA1 / SHA256)
  - PE header & section analysis with entropy-based packing detection
  - Suspicious API imports mapped to MITRE ATT&CK techniques
  - IOC extraction from strings (IPs, domains, URLs, emails,
    registry keys, file paths)
  - A simple, transparent weighted verdict score

Usage:
    python byteautopsy.py sample.exe
    python byteautopsy.py sample.exe --out report.md --json report.json

License: MIT
For educational / authorized analysis use only. Always analyze
unknown binaries inside an isolated VM (e.g. FlareVM / no network).
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone

try:
    import pefile
except ImportError:
    print("[!] Missing dependency 'pefile'. Run: pip install -r requirements.txt")
    sys.exit(1)

# ----------------------------- Config -----------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAPPING_PATH = os.path.join(SCRIPT_DIR, "mitre_mapping.json")

ENTROPY_PACKED_THRESHOLD = 7.2   # section entropy at/above this => likely packed/encrypted
ENTROPY_WARN_THRESHOLD = 6.8     # entropy at/above this => worth a second look
MIN_STRING_LEN = 4

IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|me|tk)\b",
        re.IGNORECASE,
    ),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s\"]+", re.IGNORECASE),
    "filepath": re.compile(r"[A-Za-z]:\\[^\s\"<>:]+"),
}

# ------------------------- Helper functions -------------------------------


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0-8) of a byte sequence."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def file_hashes(path: str) -> dict:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def extract_strings(data: bytes, min_len: int = MIN_STRING_LEN):
    """Pull printable ASCII strings out of raw file bytes."""
    pattern = re.compile(b"[ -~]{%d,}" % min_len)
    return [m.decode("ascii", errors="ignore") for m in pattern.findall(data)]


def extract_iocs(strings_list):
    found = {k: set() for k in IOC_PATTERNS}
    blob = "\n".join(strings_list)
    for key, pattern in IOC_PATTERNS.items():
        for match in pattern.findall(blob):
            found[key].add(match)
    return {k: sorted(v) for k, v in found.items() if v}


def load_mitre_mapping():
    if not os.path.exists(MAPPING_PATH):
        return {}
    with open(MAPPING_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_pe(path: str, mapping: dict):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories()

    info = {
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": datetime.fromtimestamp(
            pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc
        ).isoformat(),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "sections": [],
        "imports": [],
        "flagged_imports": [],
    }

    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        ent = section.get_entropy()
        flags = []
        if ent >= ENTROPY_PACKED_THRESHOLD:
            flags.append("HIGH ENTROPY (possibly packed/encrypted)")
        elif ent >= ENTROPY_WARN_THRESHOLD:
            flags.append("Elevated entropy")

        characteristics = section.Characteristics
        is_writable = bool(characteristics & 0x80000000)
        is_executable = bool(characteristics & 0x20000000)
        if is_writable and is_executable:
            flags.append("WRITABLE + EXECUTABLE (suspicious)")

        info["sections"].append(
            {
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(ent, 2),
                "flags": flags,
            }
        )

    import_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    fname = imp.name.decode(errors="ignore")
                    funcs.append(fname)
                    import_count += 1
                    if fname in mapping:
                        info["flagged_imports"].append(
                            {"api": fname, "dll": dll, **mapping[fname]}
                        )
            info["imports"].append({"dll": dll, "functions": funcs})

    info["import_count"] = import_count
    return info


def compute_verdict(pe_info, ioc_count):
    """Transparent, additive heuristic score. Not a substitute for a human analyst."""
    score = 0
    reasons = []

    if pe_info["flagged_imports"]:
        pts = min(len(pe_info["flagged_imports"]) * 2, 8)
        score += pts
        reasons.append(
            f"{len(pe_info['flagged_imports'])} suspicious API import(s) matched to "
            f"MITRE ATT&CK techniques (+{pts})"
        )

    high_entropy_sections = [s for s in pe_info["sections"] if "HIGH ENTROPY" in " ".join(s["flags"])]
    if high_entropy_sections:
        score += 3
        reasons.append(
            f"{len(high_entropy_sections)} section(s) with high entropy — "
            f"indicates packing/encryption (+3)"
        )

    rwx_sections = [s for s in pe_info["sections"] if "WRITABLE + EXECUTABLE" in " ".join(s["flags"])]
    if rwx_sections:
        score += 2
        reasons.append("Writable + executable section found — common in shellcode loaders (+2)")

    if pe_info["import_count"] < 5:
        score += 2
        reasons.append("Very low import count — may indicate packing or manual API resolution (+2)")

    if ioc_count > 0:
        score += 1
        reasons.append(f"{ioc_count} network/registry/file IOC(s) extracted from strings (+1)")

    if score >= 8:
        verdict = "Likely Malicious"
    elif score >= 4:
        verdict = "Suspicious"
    else:
        verdict = "Likely Benign"

    return verdict, score, reasons


# ------------------------- Report generation -------------------------------


def build_markdown_report(path, hashes, pe_info, iocs, verdict, score, reasons):
    lines = []
    lines.append("# ByteAutopsy Static Analysis Report")
    lines.append("")
    lines.append(f"**File:** `{os.path.basename(path)}`  ")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ")
    lines.append(f"**Verdict:** **{verdict}** (heuristic score: {score})")
    lines.append("")
    lines.append("## Verdict Reasoning")
    for r in reasons or ["No suspicious indicators detected by current heuristics."]:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("## File Hashes")
    for k, v in hashes.items():
        lines.append(f"- **{k.upper()}**: `{v}`")
    lines.append("")
    lines.append("## PE Header")
    lines.append(f"- Machine: `{pe_info['machine']}`")
    lines.append(f"- Compile Timestamp: `{pe_info['timestamp']}`")
    lines.append(f"- Entry Point: `{pe_info['entry_point']}`")
    lines.append(f"- Subsystem: `{pe_info['subsystem']}`")
    lines.append(f"- Total Imports: `{pe_info['import_count']}`")
    lines.append("")
    lines.append("## Sections")
    lines.append("| Name | Virtual Size | Raw Size | Entropy | Flags |")
    lines.append("|------|-------------|----------|---------|-------|")
    for s in pe_info["sections"]:
        flags = ", ".join(s["flags"]) if s["flags"] else "-"
        lines.append(f"| {s['name']} | {s['virtual_size']} | {s['raw_size']} | {s['entropy']} | {flags} |")
    lines.append("")

    if pe_info["flagged_imports"]:
        lines.append("## Suspicious Imports → MITRE ATT&CK Mapping")
        lines.append("| API | DLL | Technique | Name | Tactic |")
        lines.append("|-----|-----|-----------|------|--------|")
        for fi in pe_info["flagged_imports"]:
            lines.append(f"| {fi['api']} | {fi['dll']} | {fi['technique']} | {fi['name']} | {fi['tactic']} |")
        lines.append("")

    if iocs:
        lines.append("## Extracted IOCs")
        for k, vals in iocs.items():
            lines.append(f"### {k.upper()} ({len(vals)})")
            for v in vals[:50]:
                lines.append(f"- `{v}`")
        lines.append("")

    lines.append("---")
    lines.append(
        "*Report auto-generated by ByteAutopsy. For educational and authorized "
        "analysis use only — always validate findings manually before acting on them.*"
    )
    return "\n".join(lines)


# ------------------------------- Main ---------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="ByteAutopsy - Automated PE static analysis & SOC report generator"
    )
    parser.add_argument("file", help="Path to the PE file to analyze (.exe / .dll)")
    parser.add_argument("--out", default=None, help="Output Markdown report path (default: <file>_report.md)")
    parser.add_argument("--json", default=None, help="Also write a JSON report to this path")
    parser.add_argument("--min-string-len", type=int, default=MIN_STRING_LEN)
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    print(f"[*] Analyzing {args.file} ...")
    with open(args.file, "rb") as f:
        data = f.read()

    hashes = file_hashes(args.file)
    mapping = load_mitre_mapping()

    try:
        pe_info = analyze_pe(args.file, mapping)
    except pefile.PEFormatError:
        print("[!] Not a valid PE file. ByteAutopsy currently supports PE (.exe/.dll) files only.")
        sys.exit(1)

    strings_list = extract_strings(data, args.min_string_len)
    iocs = extract_iocs(strings_list)
    ioc_count = sum(len(v) for v in iocs.values())

    verdict, score, reasons = compute_verdict(pe_info, ioc_count)
    report = build_markdown_report(args.file, hashes, pe_info, iocs, verdict, score, reasons)

    out_path = args.out or (os.path.splitext(args.file)[0] + "_report.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"[+] Markdown report written to: {out_path}")

    if args.json:
        json_data = {
            "file": args.file,
            "hashes": hashes,
            "pe_info": pe_info,
            "iocs": iocs,
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
        print(f"[+] JSON report written to: {args.json}")

    print(f"[*] Verdict: {verdict} (score: {score})")


if __name__ == "__main__":
    main()
