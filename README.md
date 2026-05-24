# directoryExplorer

**Web Application Content Discovery Orchestration Tool**

> **WARNING: For authorized penetration testing and security assessments ONLY.**
> Unauthorized scanning may violate computer fraud and abuse laws.
> Always obtain explicit written permission before scanning any system.

---

## Overview

`directoryExplorer` orchestrates industry-standard web content discovery tools — **gobuster** and **dirsearch** — into a single, unified workflow. It normalizes outputs, deduplicates findings, and generates professional reports in HTML, CSV, TXT, and JSON formats.

### Key Features

- **Multi-tool orchestration** — runs all tools sequentially or in parallel
- **Normalized findings** — unified schema with deduplication and confidence scoring
- **Multi-target support** — scan lists of targets from plain text, CSV, or JSON files
- **Professional reports** — sortable/filterable HTML dashboard with charts, CSV, TXT, JSON
- **Safe defaults** — conservative thread limits, request delays, exponential backoff
- **Authentication support** — cookies, Authorization headers, custom headers
- **Resume support** — skip already-completed targets on interrupted scans
- **SQLite backend** — persistent finding storage across sessions
- **Technology fingerprinting** — passive tech stack detection and favicon hashing
- **Built-in wordlist** — 150+ entries covering common paths and sensitive files

---

## Installation

### Kali Linux (Recommended)

```bash
# 1. Clone or download the tool
git clone https://github.com/DigitalOhara/directoryExplorer.git
cd directoryExplorer

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip3 install -r requirements.txt

# 4. Install external tools (Kali already includes most)
sudo apt update
sudo apt install -y gobuster dirsearch

# Verify tools are available
which gobuster dirsearch
```

### Other Linux / macOS

```bash
# gobuster
go install github.com/OJ/gobuster/v3@latest

# dirsearch
pip3 install dirsearch
```

---

## Quick Start

```bash
# Activate virtual environment
source venv/bin/activate

# Single target
python3 directoryExplorer.py -t https://example.com

# Multiple targets from file
python3 directoryExplorer.py -f targets.txt

# With custom wordlist and extensions
python3 directoryExplorer.py -t https://example.com \
    -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
    -e php asp aspx js json

# Authenticated scan
python3 directoryExplorer.py -t https://app.example.com \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -c "session=abc123"

# Through a proxy (Burp Suite)
python3 directoryExplorer.py -t https://example.com \
    --proxy http://127.0.0.1:8080

# Run only a specific tool
python3 directoryExplorer.py -t https://example.com \
    --tool gobuster

# Aggressive scan (more threads, no delay)
python3 directoryExplorer.py -t https://example.com \
    -T 50 -d 0 --recursion-depth 3

# Resume an interrupted multi-target scan
python3 directoryExplorer.py -f targets.txt --resume
```

---

## Command-Line Reference

### Target Specification

| Flag | Description |
|------|-------------|
| `-t, --target URL` | Single target URL |
| `-f, --targets-file FILE` | File containing multiple targets |
| `--target-format FORMAT` | `plain` (default), `csv`, or `json` |

### Scope

| Flag | Description |
|------|-------------|
| `-w, --wordlist FILE` | Custom wordlist (merged with built-in) |
| `-e, --extensions EXT...` | File extensions to probe |

### Authentication

| Flag | Description |
|------|-------------|
| `-H, --header "Name: Value"` | Custom HTTP header (repeatable) |
| `-c, --cookies "key=val"` | Cookie string |
| `-a, --auth "Bearer TOKEN"` | Authorization header value |

### Performance

| Flag | Default | Description |
|------|---------|-------------|
| `-T, --threads N` | 10 | Max threads per tool |
| `-d, --delay SECS` | 1.0 | Delay between requests |
| `--timeout SECS` | 30 | Request timeout |
| `--parallel-targets N` | 2 | Max simultaneous targets |
| `--random-jitter` | off | Add random jitter to timing |

### HTTP Behaviour

| Flag | Description |
|------|-------------|
| `--user-agent STRING` | Custom User-Agent |
| `--random-agent` | Randomize User-Agent |
| `--proxy URL` | HTTP/SOCKS proxy |
| `--follow-redirects` | Follow redirects |
| `--recursion-depth N` | Directory recursion depth |

### Status Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--status-filter CODES...` | 200 301 302 307 308 | Show only these codes |
| `--include-status CODES...` | — | Add codes to filter |
| `--exclude-status CODES...` | — | Remove codes from filter |

### Tools

| Flag | Description |
|------|-------------|
| `--tool TOOL...` | Run only: `gobuster dirsearch` |

### Output

| Flag | Description |
|------|-------------|
| `-o, --output DIR` | Output directory (default: `output/`) |
| `--html-report` | Generate HTML report |
| `--csv-report` | Generate CSV report |
| `--txt-report` | Generate TXT report |
| `--json` | Export JSON findings |
| `--verbose` | Debug logging |
| `--resume` | Skip completed targets |

---

## Target File Formats

### Plain text (`targets.txt`)
```
https://example.com
https://staging.example.com
https://internal.corp:8080
```

### CSV (`targets.csv`)
```csv
name,url
production,https://example.com
staging,https://staging.example.com
api,https://api.example.com
```

### JSON (`targets.json`)
```json
[
  {"name": "prod",    "url": "https://example.com"},
  {"name": "staging", "url": "https://staging.example.com"},
  {"name": "dev",     "url": "https://dev.example.com"}
]
```

---

## Output Structure

```
output/
├── findings.db                    # SQLite database (all findings)
├── summary/
│   ├── master_report.html         # Interactive master dashboard
│   ├── master_report.csv          # All findings (CSV)
│   ├── master_report.txt          # Text summary
│   └── master_report.json         # Full JSON export
├── targets/
│   ├── example.com/
│   │   ├── raw/
│   │   │   ├── gobuster_output.txt
│   │   │   └── dirsearch_output.txt
│   │   ├── parsed/
│   │   │   ├── findings.json
│   │   │   ├── fingerprint.json
│   │   │   └── summary.json
│   │   ├── reports/
│   │   │   ├── report.html
│   │   │   ├── findings.csv
│   │   │   ├── findings.json
│   │   │   └── summary.txt
│   │   └── logs/
│   │       ├── directoryExplorer.log
│   │       └── dirsearch_stderr.txt
│   └── staging.example.com/
│       └── …
└── logs/
    └── directoryExplorer.log
```

---

## Finding Schema

Every normalized finding has the following structure:

```json
{
  "target":        "https://example.com",
  "url":           "https://example.com/admin",
  "status":        200,
  "length":        4096,
  "tool":          "gobuster,dirsearch",
  "response_time": "0.234s",
  "content_type":  "text/html",
  "timestamp":     "2024-01-15T14:22:01+00:00",
  "source_log":    "output/targets/example.com/raw/gobuster_output.txt",
  "confidence":    1.0
}
```

**Confidence scoring:**
- `1.0` — HTTP 200 (confirmed)
- `0.8` — HTTP 3xx redirect
- `+0.2` — bonus for each additional tool confirming the same URL (capped at 1.0)

---

## HTML Report Features

- **Dark-themed dashboard** with status code doughnut chart and tool breakdown bar chart
- **Master dashboard** includes per-target bar chart and target summary table
- **Sortable columns** — click any column header to sort
- **Live search** — filter by URL, tool name, status code, or any text
- **Status code filter** — quick-filter to 200/301/302 etc.
- **Tool filter** — show findings from specific tools only
- **CSV export** — download filtered results as CSV
- **Pagination** — 100 rows per page for large result sets
- **Print-friendly** — works with browser print / Save as PDF

---

## Architecture

```
directoryExplorer/
├── directoryExplorer.py     # CLI entry point
├── config.py                # Central configuration & constants
├── runner.py                # Orchestration engine (single + multi-target)
├── parser.py                # Normalization, deduplication, scoring
├── report.py                # HTML/CSV/TXT/JSON report generation
├── wordlists/
│   ├── __init__.py
│   └── default.py           # Built-in wordlist (150+ paths + sensitive files)
├── tools/
│   ├── __init__.py
│   ├── base.py              # BaseTool abstract class + Finding dataclass
│   ├── gobuster.py
│   └── dirsearch.py
├── utils/
│   ├── __init__.py
│   ├── logging_utils.py     # Rotating file + coloured console logging
│   ├── network.py           # URL validation, multi-target file parsing
│   └── fingerprint.py       # Technology detection, favicon hashing
└── templates/
    └── report_template.html # HTML report template
```

---

## Adding a New Tool

1. Create `tools/mytool.py` subclassing `BaseTool`:
   ```python
   from .base import BaseTool, Finding
   class MyTool(BaseTool):
       name = "mytool"
       def build_command(self): ...
       def parse_output(self, raw, log_path): ...
   ```
2. Register it in `tools/__init__.py`:
   ```python
   from .mytool import MyTool
   TOOL_REGISTRY["mytool"] = MyTool
   ```
3. Add `"mytool"` to `SUPPORTED_TOOLS` in `config.py`.

---

## Safe Usage Guidelines

1. **Always obtain written authorization** before scanning any target.
2. Start with `--delay 2` and `-T 5` to reduce server load.
3. Use `--status-filter 200` first to identify live endpoints before expanding.
4. Use `--proxy http://127.0.0.1:8080` to route through Burp Suite for manual review.
5. Run during agreed maintenance windows when possible.
6. Review `output/logs/directoryExplorer.log` for any errors or anomalies.

---

## License

This tool is provided for **educational and authorized security testing purposes only**.
The author assumes no liability for misuse. By using this tool you agree to use it
only against systems you own or have explicit written permission to test.
