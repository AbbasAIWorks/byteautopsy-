# 🩻 ByteAutopsy

**Automated PE static analysis + SOC-ready report generator, in one command.**

ByteAutopsy takes a Windows PE file (`.exe` / `.dll`) and in seconds produces a clean Markdown (and optional JSON) report with:

- 🔑 **File hashes** — MD5 / SHA1 / SHA256
- 🧬 **PE header & section analysis** — entropy-based packing/encryption detection, writable+executable section flags
- 🎯 **MITRE ATT&CK mapping** — suspicious API imports are automatically matched to ATT&CK techniques (no manual lookup)
- 🌐 **IOC extraction** — IPs, domains, URLs, emails, registry keys, and file paths pulled straight from strings
- ⚖️ **Transparent verdict score** — *Likely Benign / Suspicious / Likely Malicious*, with the exact reasoning shown (no black box)

No more manually cross-referencing PEStudio output against the ATT&CK matrix and typing it all into a Word doc — ByteAutopsy does the boring 80% of a static analysis report for you, so you can spend your time on the actual analysis.

```
$ python byteautopsy.py sample.exe

[*] Analyzing sample.exe ...
[+] Markdown report written to: sample_report.md
[+] JSON report written to: sample_report.json
[*] Verdict: Suspicious (score: 6)
```

## Why this exists

Most static analysis tools either (a) only dump raw PE data with no interpretation, or (b) are heavyweight capability-detection frameworks with steep setup costs. ByteAutopsy sits in between: a single dependency-light script that turns raw PE internals into something you can hand straight to a SOC ticket, a CTF writeup, or a malware analysis assignment — with full reasoning shown so you can verify it yourself rather than trusting a black-box verdict.

## Installation

```bash
git clone https://github.com/AbbasAIWorks/byteautopsy-.git
cd byteautopsy
pip install -r requirements.txt
```

Requires Python 3.8+. Only dependency is [`pefile`](https://github.com/erocarrera/pefile).

## Usage

```bash
# Basic — writes sample_report.md next to the input file
python byteautopsy.py sample.exe

# Custom output paths + JSON for tooling/integration
python byteautopsy.py sample.exe --out report.md --json report.json

# Lower the minimum string length picked up during IOC extraction
python byteautopsy.py sample.exe --min-string-len 5
```

> ⚠️ **Safety note:** Only analyze unknown binaries inside an isolated environment (e.g. a FlareVM/REMnux VM with networking disabled). ByteAutopsy performs **static analysis only** — it never executes the target file — but you should still treat any unknown sample as live ammunition.

## Example output

```markdown
## Verdict Reasoning
- 2 suspicious API import(s) matched to MITRE ATT&CK techniques (+4)
- 1 section(s) with high entropy — indicates packing/encryption (+3)

## Suspicious Imports → MITRE ATT&CK Mapping
| API | DLL | Technique | Name | Tactic |
|-----|-----|-----------|------|--------|
| VirtualAllocEx | KERNEL32.dll | T1055 | Process Injection | Defense Evasion, Privilege Escalation |
| IsDebuggerPresent | KERNEL32.dll | T1622 | Debugger Evasion | Defense Evasion |
```

## Extending the ATT&CK mapping

The whole API → ATT&CK lookup table lives in [`mitre_mapping.json`](./mitre_mapping.json) — it's intentionally separated from the code so anyone can extend it without touching Python. To add a new mapping:

```json
"SomeWinAPI": {
  "technique": "T1059",
  "name": "Command and Scripting Interpreter",
  "tactic": "Execution"
}
```

PRs that expand coverage (more APIs, more techniques) are very welcome — this is the part of the project most worth growing.

## Roadmap ideas (open to contributions)

- [ ] ELF/Mach-O support for cross-platform binaries
- [ ] FLOSS-style obfuscated string decoding
- [ ] YARA rule auto-generation from flagged indicators
- [ ] HTML report export with a dark "SOC dashboard" theme
- [ ] Batch mode for scanning a directory of samples

## Disclaimer

This tool is for educational and authorized security research only. The heuristic verdict score is a starting point for analysis, not a definitive classification — always validate findings manually. The author(s) are not responsible for misuse.

## License

MIT — see [LICENSE](./LICENSE).
