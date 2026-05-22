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

    def build_command(self) -> List[str]:
        cmd = [
            "dirsearch",
            "-u", self.target,
            "-w", self.wordlist,
            "-t", str(self.threads),
            "--timeout", str(self.timeout),
            "-o", self._json_out,
            "--format", "json",
            "--no-color",
            "--quiet",
        ]

        if self.extensions:
            cmd += ["-e", ",".join(e.lstrip(".") for e in self.extensions)]
            cmd += ["--force-extensions"]

        for key, val in self.headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if self.cookies:
            cmd += ["--cookie", self.cookies]

        if self.user_agent:
            cmd += ["-H", f"User-Agent: {self.user_agent}"]

        if self.proxy:
            cmd += ["--proxy", self.proxy]

        if self.follow_redirects:
            cmd += ["--follow-redirects"]

        if self.recursion_depth > 0:
            cmd += ["-r", "--max-recursion-depth", str(self.recursion_depth)]

        cmd += [
            "-i", ",".join(str(s) for s in self.status_filter),
        ]

        if self.delay > 0:
            cmd += ["--delay", str(self.delay)]

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
