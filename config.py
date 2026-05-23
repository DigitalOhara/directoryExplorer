"""
Central configuration for directoryExplorer.
"""

import os

VERSION = "1.0.0"
TOOL_NAME = "directoryExplorer"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_THREADS = 10
DEFAULT_DELAY = 1.0
DEFAULT_TIMEOUT = 30
DEFAULT_RECURSION_DEPTH = 2
DEFAULT_PARALLEL_TARGETS = 2
DEFAULT_RETRY_COUNT = 3
DEFAULT_RETRY_BACKOFF = 2.0          # exponential base (seconds)
DEFAULT_JITTER_MAX = 0.5             # max random jitter seconds

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/91.0.4472.114 Safari/537.36"
)

DEFAULT_STATUS_CODES = [200, 301, 302, 307, 308]

DEFAULT_EXTENSIONS = [
    "php", "asp", "aspx", "jsp", "js", "json",
    "txt", "bak", "old", "zip", "conf", "xml",
]

# Tools supported
SUPPORTED_TOOLS = ["gobuster", "dirsearch"]

# ── User-Agent pool (--random-agent) ──────────────────────────────────────────
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) "
        "Gecko/20100101 Firefox/121.0"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.2 Mobile/15E148 Safari/604.1"
    ),
]

# ── Ethics banner ─────────────────────────────────────────────────────────────
ETHICS_BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          directoryExplorer v{version} — Web Content Discovery Tool          ║
║                  FOR AUTHORIZED PENETRATION TESTING ONLY                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  WARNING: Use only on systems you own or are explicitly authorized to test. ║
║  Unauthorized scanning may violate computer fraud and abuse laws.           ║
╚══════════════════════════════════════════════════════════════════════════════╝
""".format(version=VERSION)

# ── Output layout ─────────────────────────────────────────────────────────────
OUTPUT_ROOT = "output"
SUMMARY_DIR = "summary"
TARGETS_DIR = "targets"

# Sub-dirs created per target
TARGET_SUBDIRS = ["raw", "parsed", "reports", "logs"]

# ── SQLite backend ─────────────────────────────────────────────────────────────
SQLITE_DB_NAME = "findings.db"

# ── Tool installation recipes ─────────────────────────────────────────────────
# Each entry is a list of shell commands tried in order until one succeeds.
# Commands are run with shell=True; they must be idempotent (safe to re-run).
TOOL_INSTALL_RECIPES = {
    "gobuster": [
        "apt-get install -y gobuster",
        "go install github.com/OJ/gobuster/v3@latest && cp ~/go/bin/gobuster /usr/local/bin/gobuster",
    ],
    "dirsearch": [
        "apt-get install -y dirsearch",
        "pip3 install dirsearch",
        "pip install dirsearch",
    ],
}

# ── Confidence scoring weights ─────────────────────────────────────────────────
CONFIDENCE_WEIGHTS = {
    "status_200": 1.0,
    "status_3xx": 0.8,
    "multi_tool": 0.2,   # bonus per additional confirming tool
}
