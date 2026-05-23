"""
Gobuster tool wrapper.
Output line format (after stripping ANSI): /path (Status: 200) [Size: 1234]
"""

import re
from typing import List

from .base import BaseTool, Finding, _ANSI_RE


# Example (after ANSI strip): /admin                (Status: 200) [Size: 4096]
# or:                          /backup               (Status: 301) [Size: 220] [--> /backup/]
_LINE_RE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)"
    r"(?:\s+\[Size:\s*(?P<size>\d+)\])?",
    re.IGNORECASE,
)


class GobusterTool(BaseTool):
    name = "gobuster"

    def build_command(self) -> List[str]:
        cmd = [
            "gobuster", "dir",
            "-u", self.target,
            "-w", self.wordlist,
            "-t", str(self.threads),
            "--timeout", f"{self.timeout}s",
            # No -o: we capture stdout and write the file ourselves.
            # No -q: with -q the findings only go to -o and stdout is empty.
            "--no-progress",    # suppress the no-newline progress bar
        ]

        if self.extensions:
            cmd += ["-x", ",".join(e.lstrip(".") for e in self.extensions)]

        for key, val in self.headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if self.cookies:
            cmd += ["-c", self.cookies]

        if self.user_agent:
            cmd += ["-a", self.user_agent]

        if self.proxy:
            cmd += ["--proxy", self.proxy]

        if self.follow_redirects:
            cmd += ["-r"]

        # status-codes and status-codes-blacklist are mutually exclusive in
        # gobuster; pass an empty blacklist so --status-codes takes effect.
        cmd += [
            "--status-codes", ",".join(str(s) for s in self.status_filter),
            "--status-codes-blacklist", "",
        ]

        # Wildcard: server returns success for non-existent paths; exclude by size.
        if self.wildcard_size is not None:
            cmd += ["--exclude-length", str(self.wildcard_size)]

        # Delay (gobuster uses milliseconds)
        if self.delay > 0:
            ms = int(self.delay * 1000)
            cmd += ["--delay", f"{ms}ms"]

        return cmd

    def parse_output(self, raw: str, log_path: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in raw.splitlines():
            # Strip ANSI codes gobuster emits (\x1b[2K prefix on finding lines)
            line = _ANSI_RE.sub("", line).strip()
            if not line or line.startswith("[") or line.startswith("="):
                continue
            m = _LINE_RE.match(line)
            if m:
                path = m.group("path")
                status = int(m.group("status"))
                size = int(m.group("size") or 0)
                url = self.target.rstrip("/") + path
                findings.append(
                    self._make_finding(
                        url=url,
                        status=status,
                        length=size,
                        source_log=log_path,
                    )
                )
        return findings
