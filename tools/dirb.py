"""
dirb tool wrapper.
Output format: + https://example.com/admin (CODE:200|SIZE:1234)
"""

import re
from typing import Dict, List, Optional

from .base import BaseTool, Finding


# dirb line: + URL (CODE:NNN|SIZE:NNN)
_LINE_RE = re.compile(
    r"^\+\s+(?P<url>https?://\S+)\s+\(CODE:(?P<status>\d+)\|SIZE:(?P<size>\d+)\)",
    re.IGNORECASE,
)


class DirbTool(BaseTool):
    name = "dirb"

    def build_command(self) -> List[str]:
        cmd = [
            "dirb",
            self.target,
            self.wordlist,
            "-o", self._raw_log_path,
            "-S",           # silent (no progress bar)
            "-r",           # don't search recursively (we manage depth ourselves)
        ]

        if self.extensions:
            cmd += ["-X", ",".join("." + e.lstrip(".") for e in self.extensions)]

        for key, val in self.headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if self.cookies:
            cmd += ["-c", self.cookies]

        if self.user_agent:
            cmd += ["-a", self.user_agent]

        if self.proxy:
            cmd += ["-p", self.proxy]

        if not self.follow_redirects:
            cmd += ["-N", "301"]  # ignore 301 redirects (dirb follows by default)

        # dirb -z adds delay in milliseconds
        if self.delay > 0:
            cmd += ["-z", str(int(self.delay * 1000))]

        # Filter codes via -N (not-found)
        all_common = {200, 204, 301, 302, 307, 308, 400, 401, 403, 404, 500}
        show = set(self.status_filter)
        for code in all_common - show:
            cmd += ["-N", str(code)]

        return cmd

    def parse_output(self, raw: str, log_path: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _LINE_RE.match(line)
            if m:
                url = m.group("url")
                status = int(m.group("status"))
                size = int(m.group("size"))
                findings.append(
                    self._make_finding(
                        url=url,
                        status=status,
                        length=size,
                        source_log=log_path,
                    )
                )
        return findings
