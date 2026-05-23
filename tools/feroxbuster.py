"""
feroxbuster tool wrapper.
Output format: 200      GET     1l     10w    100c https://example.com/admin
"""

import re
from typing import Dict, List, Optional

from .base import BaseTool, Finding


# feroxbuster line: STATUS  METHOD  LINES  WORDS  CHARS  URL  [redirects]
_LINE_RE = re.compile(
    r"^(?P<status>\d{3})\s+"
    r"(?P<method>[A-Z]+)\s+"
    r"(?P<lines>\d+)l\s+"
    r"(?P<words>\d+)w\s+"
    r"(?P<chars>\d+)c\s+"
    r"(?P<url>https?://\S+)",
    re.IGNORECASE,
)


class FeroxbusterTool(BaseTool):
    name = "feroxbuster"

    def build_command(self) -> List[str]:
        cmd = [
            "feroxbuster",
            "--url", self.target,
            "--wordlist", self.wordlist,
            "--threads", str(self.threads),
            "--timeout", str(self.timeout),
            # No --output / --silent: with both set nothing goes to stdout.
            # base.py captures stdout and writes the raw log file itself.
            "--quiet",
        ]

        if self.recursion_depth == 0:
            cmd += ["--no-recursion"]
        else:
            cmd += ["--depth", str(self.recursion_depth)]

        if self.extensions:
            cmd += [
                "--extensions",
                ",".join(e.lstrip(".") for e in self.extensions),
            ]

        for key, val in self.headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if self.cookies:
            cmd += ["-b", self.cookies]

        if self.user_agent:
            cmd += ["--user-agent", self.user_agent]

        if self.proxy:
            cmd += ["--proxy", self.proxy]

        if self.follow_redirects:
            cmd += ["--redirects"]

        cmd += [
            "--status-codes",
            ",".join(str(s) for s in self.status_filter),
        ]

        if self.wildcard_size is not None:
            cmd += ["--filter-size", str(self.wildcard_size)]

        if self.delay > 0:
            rate = max(1, int(1.0 / self.delay))
            cmd += ["--rate-limit", str(rate)]

        return cmd

    def parse_output(self, raw: str, log_path: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LINE_RE.match(line)
            if m:
                status = int(m.group("status"))
                chars = int(m.group("chars"))
                url = m.group("url")
                findings.append(
                    self._make_finding(
                        url=url,
                        status=status,
                        length=chars,
                        source_log=log_path,
                    )
                )
        return findings
