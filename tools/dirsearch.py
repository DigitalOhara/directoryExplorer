"""
dirsearch tool wrapper — uses JSON output mode for reliable parsing.

JSON result structure:
  {"results": [{"url": "...", "status": 200, "content-length": 1234, "redirect": "..."}, ...]}
"""

import json
import os
import re
import shutil
import subprocess
import sys
from typing import List, Optional

from .base import BaseTool, Finding


# Fallback: parse the default coloured text output
# Example: [22:30:01] 200 -    4KB - /admin/
_TEXT_RE = re.compile(
    r"\[\d{2}:\d{2}:\d{2}\]\s+"
    r"(?P<status>\d{3})\s+-\s+"
    r"(?P<size>[\d.]+\s*[BKMG]?B?)\s+-\s+"
    r"(?P<path>/\S*)",
    re.IGNORECASE,
)


def _build_status_arg(status_filter: List[int]) -> str:
    """
    Convert a list of status codes to dirsearch's compact range notation.

    The default filter [200,301,302,307,308] maps to "200,300-399" — a broader
    range that catches all redirects and was found to work well against WAFs.
    Any custom filter is collapsed into the shortest equivalent range string
    (e.g. [200,403,404] → "200,403-404").
    """
    default_codes = {200, 301, 302, 307, 308}
    if set(status_filter) == default_codes:
        return "200,300-399"

    sorted_codes = sorted(set(status_filter))
    if not sorted_codes:
        return "200"

    ranges: List[str] = []
    start = end = sorted_codes[0]
    for code in sorted_codes[1:]:
        if code == end + 1:
            end = code
        else:
            ranges.append(str(start) if start == end else f"{start}-{end}")
            start = end = code
    ranges.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(ranges)


def _parse_size(raw: str) -> int:
    """Convert dirsearch human-readable size (e.g. '4KB', '234B') to bytes."""
    raw = raw.strip().upper().replace(" ", "")
    multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if raw.endswith(suffix):
            try:
                return int(float(raw[: -len(suffix)]) * mult)
            except ValueError:
                return 0
    try:
        return int(raw)
    except ValueError:
        return 0


_DIRSEARCH_SCRIPT_CANDIDATES = [
    "/usr/lib/python3/dist-packages/dirsearch/dirsearch.py",
    "/usr/local/lib/python3/dist-packages/dirsearch/dirsearch.py",
    "/usr/share/dirsearch/dirsearch.py",
    "/opt/dirsearch/dirsearch.py",
]


def _resolve_dirsearch_cmd() -> Optional[List[str]]:
    """
    Find a working command prefix to invoke dirsearch, trying multiple strategies:
    1. Parse the wrapper binary to extract the .py script path, run with sys.executable.
    2. Try known common script paths with sys.executable.
    3. Fall back to the bare 'dirsearch' binary.
    Returns a list like [sys.executable, '/path/to/dirsearch.py'] or ['dirsearch'],
    or None if nothing works.
    """
    from utils.logging_utils import get_logger
    _log = get_logger()

    candidates: List[List[str]] = []

    # Strategy 1 — parse wrapper binary for the embedded .py path
    binary = shutil.which("dirsearch")
    if binary:
        try:
            with open(binary, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(512)
            m = re.search(r'python3?\s+"?(/[^\s"]+dirsearch\.py)"?', content)
            if m and os.path.isfile(m.group(1)):
                candidates.append([sys.executable, m.group(1)])
        except Exception:
            pass

    # Strategy 2 — well-known install paths
    for path in _DIRSEARCH_SCRIPT_CANDIDATES:
        if os.path.isfile(path):
            candidates.append([sys.executable, path])

    # Strategy 3 — bare binary last (system Python may lack pkg_resources)
    if binary:
        candidates.append(["dirsearch"])

    # When the command uses sys.executable + a system script, the virtualenv
    # Python won't see system dist-packages (e.g. pkg_resources). Inject the
    # system dist-packages dir (grandparent of the script) into PYTHONPATH.
    def _build_env(cmd: List[str]) -> dict:
        env = os.environ.copy()
        if len(cmd) == 2 and cmd[0] == sys.executable and cmd[1].endswith(".py"):
            sys_dist = os.path.dirname(os.path.dirname(cmd[1]))
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (sys_dist + ":" + existing) if existing else sys_dist
        return env

    for cmd in candidates:
        try:
            env = _build_env(cmd)
            r = subprocess.run(
                cmd + ["--version"], capture_output=True, text=True,
                timeout=5, env=env,
            )
            if r.returncode == 0:
                _log.debug("[dirsearch] using command: %s", " ".join(cmd))
                return cmd
            _log.debug(
                "[dirsearch] command failed (rc=%d): %s\n  stderr: %s",
                r.returncode, " ".join(cmd), r.stderr.strip()[:200],
            )
        except Exception as exc:
            _log.debug("[dirsearch] command exception: %s — %s", " ".join(cmd), exc)
            continue

    _log.error(
        "[dirsearch] No working invocation found. "
        "Tried: %s. Install setuptools: pip3 install setuptools",
        [" ".join(c) for c in candidates],
    )
    return None


class DirsearchTool(BaseTool):
    name = "dirsearch"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._json_out = os.path.join(
            os.path.dirname(self._raw_log_path), "dirsearch_results.json"
        )
        self._cmd_prefix: Optional[List[str]] = _resolve_dirsearch_cmd()
        # PYTHONPATH needed so virtualenv Python can find system pkg_resources
        self._run_env: Optional[dict] = None
        if self._cmd_prefix and len(self._cmd_prefix) == 2 \
                and self._cmd_prefix[0] == sys.executable \
                and self._cmd_prefix[1].endswith(".py"):
            sys_dist = os.path.dirname(os.path.dirname(self._cmd_prefix[1]))
            env = os.environ.copy()
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (sys_dist + ":" + existing) if existing else sys_dist
            self._run_env = env

    def is_available(self) -> bool:
        return self._cmd_prefix is not None

    def run(self):
        if self._run_env:
            import os as _os
            old = _os.environ.copy()
            _os.environ.update(self._run_env)
            try:
                return super().run()
            finally:
                _os.environ.clear()
                _os.environ.update(old)
        return super().run()

    # Dirsearch-specific rate-limiting defaults that help bypass WAFs/Cloudflare.
    # These cap requests regardless of the global --threads / --delay values.
    _DEFAULT_THREADS  = 5
    _DEFAULT_DELAY    = 0.5
    _MAX_RATE         = 10   # requests per second

    def build_command(self) -> List[str]:
        # Use conservative per-tool defaults; honour whatever the user explicitly
        # lowered further via -T / -d (but never exceed the WAF-safe ceiling).
        threads = min(self.threads, self._DEFAULT_THREADS)
        delay   = max(self.delay,   self._DEFAULT_DELAY)

        cmd = [
            *(self._cmd_prefix or ["dirsearch"]),
            "-u", self.target,
            "-w", self.wordlist,
            "--threads", str(threads),
            "--delay",   str(delay),
            "--max-rate", str(self._MAX_RATE),
            "--timeout", str(self.timeout),
            "--no-color",
            "-o", self._json_out,
            "--format", "json",
        ]

        if self.extensions:
            cmd += ["-e", ",".join(e.lstrip(".") for e in self.extensions)]
            cmd += ["--force-extensions"]

        for key, val in self.headers.items():
            if key.lower() != "user-agent":   # handled separately below
                cmd += ["-H", f"{key}: {val}"]

        if self.cookies:
            cmd += ["--cookie", self.cookies]

        # Always set User-Agent explicitly; default is the Chrome UA that
        # was observed to bypass Cloudflare in testing.
        ua = self.user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/91.0.4472.114 Safari/537.36"
        )
        cmd += ["--user-agent", ua]

        if self.proxy:
            cmd += ["--proxy", self.proxy]

        if self.follow_redirects:
            cmd += ["--follow-redirects"]

        if self.recursion_depth > 0:
            cmd += ["-r", "--max-recursion-depth", str(self.recursion_depth)]

        # Build compact range-notation status filter (e.g. "200,300-399").
        cmd += ["-i", _build_status_arg(self.status_filter)]

        if self.wildcard_size is not None:
            cmd += ["--exclude-sizes", str(self.wildcard_size)]

        return cmd

    def parse_output(self, raw: str, log_path: str) -> List[Finding]:
        findings: List[Finding] = []

        if os.path.isfile(self._json_out):
            try:
                with open(self._json_out, "r", encoding="utf-8") as fh:
                    data = json.load(fh)

                for item in data.get("results", []):
                    url    = item.get("url", "")
                    status = int(item.get("status", 0))
                    length = int(item.get("content-length") or item.get("length") or 0)
                    if url and status:
                        findings.append(
                            self._make_finding(
                                url=url,
                                status=status,
                                length=length,
                                source_log=self._json_out,
                            )
                        )
                return findings
            except (json.JSONDecodeError, OSError):
                pass

        # Fallback: parse text output
        for line in raw.splitlines():
            m = _TEXT_RE.search(line)
            if m:
                status = int(m.group("status"))
                length = _parse_size(m.group("size"))
                path   = m.group("path")
                url    = self.target.rstrip("/") + path
                findings.append(
                    self._make_finding(
                        url=url, status=status, length=length, source_log=log_path
                    )
                )

        return findings
