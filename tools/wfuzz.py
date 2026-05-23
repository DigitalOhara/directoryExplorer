"""
wfuzz tool wrapper.
Output format: 000000001:  200    1 L      10 W    100 Ch    "admin"
"""

import re
from typing import Dict, List, Optional

from .base import BaseTool, Finding


# wfuzz line: ID: STATUS  LINES W  WORDS W  CHARS Ch  "FUZZ"
_LINE_RE = re.compile(
    r"^\d+:\s+"
    r"(?P<status>\d{3})\s+"
    r"(?P<lines>\d+)\s+L\s+"
    r"(?P<words>\d+)\s+W\s+"
    r"(?P<chars>\d+)\s+Ch\s+"
    r'"(?P<fuzz>[^"]*)"',
    re.IGNORECASE,
)


class WfuzzTool(BaseTool):
    name = "wfuzz"

    def build_command(self) -> List[str]:
        # Build hidden codes (inverse of filter)
        all_common = set(range(100, 600))
        desired = set(self.status_filter)
        hide_codes = sorted(all_common - desired)
        # wfuzz --hc takes a comma-separated list
        hc_arg = ",".join(str(c) for c in hide_codes[:20])  # limit arg length

        cmd = [
            "wfuzz",
            "-w", self.wordlist,
            "-u", f"{self.target}/FUZZ",
            "--hc", hc_arg,
            "-t", str(self.threads),
            "-o", "raw",          # raw output format
            "--oF", self._raw_log_path,
        ]

        if self.wildcard_size is not None:
            cmd += ["--hs", str(self.wildcard_size)]

        for key, val in self.headers.items():
            cmd += ["-H", f"{key}: {val}"]

        if self.cookies:
            cmd += ["-b", self.cookies]

        if self.user_agent:
            cmd += ["-H", f"User-Agent: {self.user_agent}"]

        if self.proxy:
            cmd += ["-p", self.proxy]

        if self.follow_redirects:
            cmd += ["-L"]

        if self.extensions:
            # wfuzz doesn't natively support extension lists;
            # append a FUZZ2 approach via the wordlist instead
            pass

        return cmd

    def parse_output(self, raw: str, log_path: str) -> List[Finding]:
        findings: List[Finding] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            m = _LINE_RE.match(line)
            if m:
                status = int(m.group("status"))
                chars = int(m.group("chars"))
                fuzz_value = m.group("fuzz")
                url = f"{self.target.rstrip('/')}/{fuzz_value.lstrip('/')}"
                findings.append(
                    self._make_finding(
                        url=url,
                        status=status,
                        length=chars,
                        source_log=log_path,
                    )
                )
        return findings
