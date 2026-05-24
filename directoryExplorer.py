#!/usr/bin/env python3
"""
directoryExplorer — Web Content Discovery Orchestration Tool
For authorized penetration testing and security assessments ONLY.
"""

import argparse
import os
import sys
import textwrap
import time
import warnings
from pathlib import Path
from typing import List, Optional

# Suppress urllib3 TLS warnings — tools use -k / --no-tls-validation for the
# actual scan; the fingerprinting requests are internal and the noise is not
# actionable from the terminal.
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# ── Dependency guard (runs before everything else) ─────────────────────────────
def _check_python_version():
    if sys.version_info < (3, 11):
        print(
            f"[!] Python 3.11+ required. You are running {sys.version}",
            file=sys.stderr,
        )
        sys.exit(1)

_check_python_version()

# ── Ensure project root is on sys.path ────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from config import (
    ETHICS_BANNER, DEFAULT_THREADS, DEFAULT_DELAY, DEFAULT_TIMEOUT,
    DEFAULT_STATUS_CODES, DEFAULT_EXTENSIONS, DEFAULT_USER_AGENT,
    DEFAULT_RECURSION_DEPTH, DEFAULT_PARALLEL_TARGETS, OUTPUT_ROOT,
    SUPPORTED_TOOLS,
)
from utils.logging_utils import setup_logging, get_logger
from utils.network import validate_url, parse_targets_file, Target
from wordlists.default import build_combined_wordlist, WordlistResult
from runner import run_scan
from report import write_target_reports, write_master_reports


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="directoryExplorer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            directoryExplorer — Web content discovery orchestration tool.
            Supports: gobuster, dirsearch.

            ⚠  For authorized penetration testing ONLY.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              Single target:
                python directoryExplorer.py -t https://example.com

              Multiple targets:
                python directoryExplorer.py -f targets.txt

              Custom wordlist + extensions:
                python directoryExplorer.py -t https://example.com \\
                    -w /usr/share/wordlists/dirb/common.txt -e php,asp,js

              Authenticated scan with proxy:
                python directoryExplorer.py -t https://app.example.com \\
                    -H "Authorization: Bearer TOKEN" \\
                    --proxy http://127.0.0.1:8080

              Run only gobuster, HTML + JSON output:
                python directoryExplorer.py -t https://example.com \\
                    --tool gobuster --html-report --json
        """),
    )

    # ── Target specification ───────────────────────────────────────────────────
    tgt = parser.add_argument_group("Target")
    tgt.add_argument("-t", "--target",
        help="Target URL (e.g. https://example.com)")
    tgt.add_argument("-f", "--targets-file", dest="targets_file",
        help="Path to file containing multiple targets")
    tgt.add_argument("--target-format", dest="target_format",
        choices=["plain", "csv", "json"], default="plain",
        help="Format of targets file (default: plain)")

    # ── Wordlist / scope ───────────────────────────────────────────────────────
    scope = parser.add_argument_group("Scope")
    scope.add_argument("-w", "--wordlist",
        help="Custom wordlist path (merged with built-in)")
    scope.add_argument("-e", "--extensions", nargs="+",
        default=DEFAULT_EXTENSIONS,
        help=f"File extensions to probe (default: {' '.join(DEFAULT_EXTENSIONS)})")

    # ── Authentication / headers ───────────────────────────────────────────────
    auth_grp = parser.add_argument_group("Authentication")
    auth_grp.add_argument("-H", "--header", action="append", dest="header",
        metavar="HEADER", help="Custom header (repeatable): 'Name: Value'")
    auth_grp.add_argument("-c", "--cookies",
        help="Cookie string for authenticated scans")
    auth_grp.add_argument("-a", "--auth",
        help="Authorization header value (e.g. 'Bearer TOKEN')")

    # ── Performance ───────────────────────────────────────────────────────────
    perf = parser.add_argument_group("Performance")
    perf.add_argument("-T", "--threads", type=int, default=DEFAULT_THREADS,
        help=f"Max threads per tool (default: {DEFAULT_THREADS})")
    perf.add_argument("-d", "--delay", type=float, default=DEFAULT_DELAY,
        help=f"Delay between requests in seconds (default: {DEFAULT_DELAY})")
    perf.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    perf.add_argument("--parallel-targets", dest="parallel_targets",
        type=int, default=DEFAULT_PARALLEL_TARGETS,
        help=f"Max simultaneous targets (default: {DEFAULT_PARALLEL_TARGETS})")
    perf.add_argument("--random-jitter", dest="random_jitter",
        action="store_true", help="Add random jitter to request timing")

    # ── HTTP behaviour ─────────────────────────────────────────────────────────
    http = parser.add_argument_group("HTTP")
    http.add_argument("--user-agent", dest="user_agent",
        default=DEFAULT_USER_AGENT, help="Custom User-Agent string")
    http.add_argument("--random-agent", dest="random_agent",
        action="store_true", help="Randomize User-Agent per request")
    http.add_argument("--proxy", help="Proxy URL (http://host:port or socks5://...)")
    http.add_argument("--follow-redirects", dest="follow_redirects",
        action="store_true", help="Follow HTTP redirects")
    http.add_argument("--recursion-depth", dest="recursion_depth",
        type=int, default=DEFAULT_RECURSION_DEPTH,
        help=f"Recursion depth for supported tools (default: {DEFAULT_RECURSION_DEPTH})")

    # ── Status filtering ───────────────────────────────────────────────────────
    filt = parser.add_argument_group("Filtering")
    filt.add_argument("--status-filter", dest="status_filter",
        nargs="+", type=int, default=DEFAULT_STATUS_CODES,
        help=f"Show only these status codes (default: {DEFAULT_STATUS_CODES})")
    filt.add_argument("--include-status", dest="include_status",
        nargs="+", type=int, help="Explicitly include additional status codes")
    filt.add_argument("--exclude-status", dest="exclude_status",
        nargs="+", type=int, help="Exclude specific status codes")

    # ── Tool selection ─────────────────────────────────────────────────────────
    tools_grp = parser.add_argument_group("Tools")
    tools_grp.add_argument("--tool", nargs="+",
        choices=SUPPORTED_TOOLS,
        help=f"Run only selected tool(s): {SUPPORTED_TOOLS}")

    # ── Output ────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", default=OUTPUT_ROOT,
        help=f"Output root directory (default: {OUTPUT_ROOT})")
    out.add_argument("--html-report", dest="html_report",
        action="store_true", help="Generate HTML report (default: on)")
    out.add_argument("--csv-report",  dest="csv_report",
        action="store_true", help="Generate CSV report (default: on)")
    out.add_argument("--txt-report",  dest="txt_report",
        action="store_true", help="Generate TXT report (default: on)")
    out.add_argument("--json",
        action="store_true", help="Export JSON findings (default: on)")
    out.add_argument("--no-html",  dest="no_html", action="store_true")
    out.add_argument("--no-csv",   dest="no_csv",  action="store_true")
    out.add_argument("--no-txt",   dest="no_txt",  action="store_true")
    out.add_argument("--no-json",  dest="no_json", action="store_true")

    # ── Misc ──────────────────────────────────────────────────────────────────
    misc = parser.add_argument_group("Misc")
    misc.add_argument("--verbose", "-v", action="store_true",
        help="Enable verbose/debug logging")
    misc.add_argument("--resume", action="store_true",
        help="Skip already-completed targets (resume interrupted scan)")
    misc.add_argument("--version", action="version",
        version=f"directoryExplorer 1.0.0")

    return parser


# ── Status filter resolution ───────────────────────────────────────────────────

def resolve_status_filter(args: argparse.Namespace) -> List[int]:
    codes = set(args.status_filter)
    if args.include_status:
        codes |= set(args.include_status)
    if args.exclude_status:
        codes -= set(args.exclude_status)
    return sorted(codes)


# ── Target collection ──────────────────────────────────────────────────────────

def collect_targets(args: argparse.Namespace, log) -> List[Target]:
    targets: List[Target] = []

    if args.target:
        url = args.target.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        if validate_url(url):
            from utils.network import _name_from_url
            targets.append(Target(name=_name_from_url(url), url=url))
        else:
            log.error("Invalid target URL: %s", args.target)
            sys.exit(1)

    if args.targets_file:
        file_targets = parse_targets_file(args.targets_file, args.target_format)
        if not file_targets:
            log.error("No valid targets found in %s", args.targets_file)
            sys.exit(1)
        targets.extend(file_targets)

    if not targets:
        log.error("No targets specified. Use -t <URL> or -f <file>.")
        sys.exit(1)

    # Deduplicate by URL
    seen = set()
    unique = []
    for t in targets:
        if t.url not in seen:
            seen.add(t.url)
            unique.append(t)

    log.info("Loaded %d unique target(s)", len(unique))
    return unique


# ── Dependency check & auto-install ───────────────────────────────────────────

def _install_tool(tool: str, log) -> bool:
    """
    Try each install recipe for `tool` in order.
    Returns True if the tool is on PATH after installation, False otherwise.
    """
    import shutil
    import subprocess
    from config import TOOL_INSTALL_RECIPES

    recipes = TOOL_INSTALL_RECIPES.get(tool, [])
    if not recipes:
        log.warning("[install] No install recipe known for %s", tool)
        return False

    for cmd in recipes:
        log.info("[install] Trying: %s", cmd)
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
            )
            if result.returncode == 0 and shutil.which(tool):
                log.info("[install] %s installed successfully via: %s", tool, cmd)
                return True
            if result.returncode != 0:
                log.debug(
                    "[install] Command failed (rc=%d): %s\n%s",
                    result.returncode, cmd, result.stderr.strip()
                )
        except subprocess.TimeoutExpired:
            log.warning("[install] Timed out: %s", cmd)
        except Exception as exc:
            log.debug("[install] Error running '%s': %s", cmd, exc)

    log.warning("[install] All recipes failed for %s — it will be skipped", tool)
    return False


def check_dependencies(log) -> None:
    import shutil
    available = []
    missing   = []

    for tool in SUPPORTED_TOOLS:
        if shutil.which(tool):
            available.append(tool)
        else:
            missing.append(tool)

    if missing:
        log.info(
            "Missing tool(s): %s — attempting automatic installation…",
            ", ".join(missing),
        )
        still_missing = []
        for tool in missing:
            if _install_tool(tool, log):
                available.append(tool)
            else:
                still_missing.append(tool)

        if still_missing:
            log.warning(
                "Could not install: %s  "
                "— these will be skipped. Install manually or use --tool.",
                ", ".join(still_missing),
            )

    if available:
        log.info("Available tools: %s", ", ".join(sorted(available)))

    if not available:
        log.error(
            "No supported tools available after install attempts. "
            "Manually install at least one of: %s",
            ", ".join(SUPPORTED_TOOLS),
        )
        sys.exit(1)


# ── Wordlist cleanup ──────────────────────────────────────────────────────────

def _cleanup_wordlist(wl) -> None:
    """Delete only files we created in /tmp; never touch dicc.txt or output-dir files."""
    seen: set = set()
    for path in (wl.clean_path, wl.dirsearch_path):
        if path and path not in seen and path.startswith("/tmp"):
            seen.add(path)
            try:
                os.unlink(path)
            except OSError:
                pass


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Print ethics banner — flush=True forces immediate stdout flush before
    # logging (which goes to stderr) can interleave with it.
    print(ETHICS_BANNER, flush=True)

    # Require at least one target
    if not args.target and not args.targets_file:
        parser.print_help()
        sys.exit(0)

    # Setup logging
    log_dir = os.path.join(args.output, "logs")
    log = setup_logging(log_dir, verbose=args.verbose)

    log.info("directoryExplorer starting…")

    # Resolve status filter
    args.status_filter = resolve_status_filter(args)
    log.info("Status filter: %s", args.status_filter)

    # Collect targets
    targets = collect_targets(args, log)

    # Check tool availability
    check_dependencies(log)

    # Resolve wordlists — dicc.txt for dirsearch, cleaned copy for other tools
    log.info("Resolving wordlist…")
    wl = build_combined_wordlist(
        custom_path=args.wordlist,
        output_dir=args.output,
    )

    start_time = time.monotonic()

    try:
        master = run_scan(targets, args, wl)

        elapsed = time.monotonic() - start_time
        log.info(
            "Scan complete in %.1fs — %d findings across %d target(s)",
            elapsed,
            master.get("total_findings", 0),
            master.get("total_targets", 0),
        )

        _generate_reports(master, args, log)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Partial results may have been saved.")
        sys.exit(130)
    finally:
        # Delete any temp files we created (never touch dicc.txt or output_dir files)
        _cleanup_wordlist(wl)


def _generate_reports(master: dict, args: argparse.Namespace, log) -> None:
    output_root = args.output

    # Per-target reports
    for target_summary in master.get("targets", []):
        tdir = target_summary.get("output_dir", "")
        if tdir:
            try:
                write_target_reports(target_summary, tdir, args)
            except Exception as exc:
                log.error(
                    "Failed to write target report for %s: %s",
                    target_summary.get("target_url"), exc,
                )

    # Master reports
    try:
        write_master_reports(master, output_root, args)
    except Exception as exc:
        log.error("Failed to write master reports: %s", exc)

    # Print summary to console
    print()
    print("=" * 70)
    print(f"  SCAN COMPLETE")
    print("=" * 70)
    print(f"  Targets   : {master.get('total_targets', 0)}")
    print(f"  Completed : {master.get('completed', 0)}")
    print(f"  Failed    : {master.get('failed', 0)}")
    print(f"  Findings  : {master.get('total_findings', 0)}")
    print()
    print(f"  Output    : {output_root}/")
    print(f"  Reports   : {output_root}/summary/master_report.html")
    print("=" * 70)
    print()

    log.info("Reports saved to: %s", output_root)


if __name__ == "__main__":
    main()
