"""
dirsearch tool wrapper — uses JSON output mode for reliable parsing.

JSON result structure:
  {"results": [{"url": "...", "status": 200, "content-length": 1234, "redirect": "..."}, ...]}
"""

import json
import os
import re
from typing import List

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


class DirsearchTool(BaseTool):
    name = "dirsearch"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._json_out = os.path.join(
            os.path.dirname(self._raw_log_path), "dirsearch_results.json"
        )

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
            "dirsearch",
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
