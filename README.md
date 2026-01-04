# StaticSentinel
YARA based static malware analysis tool that performs rule matching, entropy analysis, and VirusTotal hash lookups to assess files and avoid false positives

> ⚠️ This is **not an antivirus or sandbox**. It is a **static analysis tool**.

---

## Features

- 🔍 **YARA rule scanning**
  - Automatically uses the official `Yara-Rules/rules` repository
  - Gracefully skips incompatible rules
- 🔐 **SHA-256 hashing**
  - Full-file cryptographic hash calculation
- 📡 **VirusTotal enrichment**
  - Hash-based lookup (no file upload)
- 📊 **Entropy analysis**
  - Detects packed / high-entropy files
- 🧠 **Heuristic scoring**
  - Combines YARA hits, metadata, entropy, and Virustotal signals
- 📁 **File or directory scanning**
- 🧾 **Clear human-readable output**

---

## How It Works (High Level)

1. Downloads YARA rules if missing
2. Compiles all compatible `.yar` files
3. Scans the target file(s) with YARA
4. Calculates SHA-256 and entropy
5. Queries VirusTotal by hash
6. Aggregates results and produces a verdict:
   - `CLEAN`
   - `SUSPICIOUS`
   - `MALICIOUS`

---

## Installation

### Requirements
- Python **3.9+**
- `git`
- A VirusTotal API key

### Install dependencies
```bash
pip install yara-python requests
