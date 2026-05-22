"""
ffuf tool wrapper — uses JSON output mode for reliable parsing.
"""

import json
import os
import tempfile
from typing import Dict, List, Optional

from .base import BaseTool, Finding


class FfufTool(BaseTool):
    name = "ffuf"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # ffuf will write JSON to a temp file we control
        self._json_out = os.path.join(
            os.path.dirname(self._raw_log_path), "ffuf_results.json"
        )

    def build_command(self) -> List[str]:
        cmd = [
            "ffuf",
            "-u", f"{self.target}/FUZZ",
            "-w", self.wordlist,
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-o", self._json_out,
            "-of", "json",
            "-s",           # silent (no banner)
        ]

        if self.extensions:
            exts = ",".join("." + e.lstrip(".") for e in self.extensions)
            cmd += ["-e", exts]

        for key, val in self.headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if self.cookies:
            cmd += ["-b", self.cookies]

        if self.user_agent:
            cmd += ["-H", f"User-Agent: {self.user_agent}"]

        if self.proxy:
            cmd += ["-x", self.proxy]

        if self.follow_redirects:
            cmd += ["-r"]

        # Status filter
        cmd += [
            "-mc", ",".join(str(s) for s in self.status_filter),
        ]

        # Rate control via delay
        if self.delay > 0:
            # ffuf -p accepts delay in seconds (float)
            cmd += ["-p", str(self.delay)]

        if self.recursion_depth > 0:
            cmd += ["-recursion", "-recursion-depth", str(self.recursion_depth)]

        return cmd

    def parse_output(self, raw: str, log_path: str) -> List[Finding]:
        findings: List[Finding] = []

        if not os.path.isfile(self._json_out):
            # Fall back to stdout parsing
            return self._parse_stdout(raw, log_path)

        try:
            with open(self._json_out, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return self._parse_stdout(raw, log_path)

        for item in data.get("results", []):
            url = item.get("url", "")
            status = int(item.get("status", 0))
            length = int(item.get("length", 0))
            content_type = item.get("content-type", "")
            duration_ns = item.get("duration", 0)
            response_time = f"{duration_ns / 1e9:.3f}s" if duration_ns else ""

            if url and status:
                findings.append(
                    self._make_finding(
                        url=url,
                        status=status,
                        length=length,
                        response_time=response_time,
                        content_type=content_type,
                        source_log=self._json_out,
                    )
                )

        return findings

    def _parse_stdout(self, raw: str, log_path: str) -> List[Finding]:
        """Fallback: parse ffuf text output lines."""
        import re
        findings = []
        # Example: admin                   [Status: 200, Size: 1234, Words: 42, Lines: 10]
        pattern = re.compile(
            r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
            re.IGNORECASE,
        )
        for line in raw.splitlines():
            m = pattern.search(line)
            if m:
                path, status, size = m.group(1), int(m.group(2)), int(m.group(3))
                url = f"{self.target.rstrip('/')}/{path.lstrip('/')}"
                findings.append(
                    self._make_finding(
                        url=url, status=status, length=size, source_log=log_path
                    )
                )
        return findings
