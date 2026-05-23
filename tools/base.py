"""
Abstract base class shared by all tool wrappers.
"""

import asyncio
import os
import shlex
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from utils.logging_utils import get_logger

log = get_logger()


@dataclass
class Finding:
    """Normalised finding from any tool."""
    target: str
    url: str
    status: int
    length: int
    tool: str
    response_time: str = ""
    content_type: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source_log: str = ""
    confidence: float = 1.0

    def to_dict(self) -> Dict:
        return {
            "target":        self.target,
            "url":           self.url,
            "status":        self.status,
            "length":        self.length,
            "tool":          self.tool,
            "response_time": self.response_time,
            "content_type":  self.content_type,
            "timestamp":     self.timestamp,
            "source_log":    self.source_log,
            "confidence":    self.confidence,
        }


@dataclass
class ToolResult:
    tool_name: str
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""
    stderr_output: str = ""
    returncode: int = 0
    duration: float = 0.0
    error: Optional[str] = None


class BaseTool(ABC):
    """Abstract wrapper for an external discovery tool."""

    name: str = "base"

    def __init__(
        self,
        target: str,
        wordlist: str,
        output_dir: str,
        extensions: Optional[List[str]] = None,
        threads: int = 10,
        delay: float = 1.0,
        timeout: int = 30,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        auth: Optional[str] = None,
        proxy: Optional[str] = None,
        user_agent: Optional[str] = None,
        follow_redirects: bool = False,
        recursion_depth: int = 0,
        status_filter: Optional[List[int]] = None,
        verbose: bool = False,
    ):
        self.target = target.rstrip("/")
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.extensions = extensions or []
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies
        self.auth = auth
        self.proxy = proxy
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.recursion_depth = recursion_depth
        self.status_filter = status_filter or [200, 301, 302, 307, 308]
        self.verbose = verbose
        self._raw_log_path = os.path.join(output_dir, "raw", f"{self.name}_output.txt")
        Path(self._raw_log_path).parent.mkdir(parents=True, exist_ok=True)

    def is_available(self) -> bool:
        """Check the tool binary is on PATH."""
        return shutil.which(self.name) is not None

    @abstractmethod
    def build_command(self) -> List[str]:
        """Return the command + arguments list."""

    @abstractmethod
    def parse_output(self, raw: str, log_path: str) -> List[Finding]:
        """Parse raw stdout into normalised Finding objects."""

    def run(self) -> ToolResult:
        """Execute the tool synchronously and return a ToolResult."""
        result = ToolResult(tool_name=self.name)

        if not self.is_available():
            result.error = f"{self.name} not found on PATH — skipping"
            log.warning(result.error)
            return result

        cmd = self.build_command()
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        print(f"\n  \033[36m[{self.name}]\033[0m $ {cmd_str}\n")
        log.debug("[%s] Command: %s", self.name, cmd_str)

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            stdout, stderr = proc.communicate(timeout=None)
            result.returncode = proc.returncode
            result.raw_output = stdout
            result.stderr_output = stderr
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            result.error = f"{self.name} timed out"
            log.error(result.error)
            result.raw_output = stdout or ""
            result.stderr_output = stderr or ""
        except FileNotFoundError:
            result.error = f"{self.name} binary not found"
            log.error(result.error)
            return result
        except Exception as exc:
            result.error = str(exc)
            log.error("[%s] Unexpected error: %s", self.name, exc)
            return result
        finally:
            result.duration = time.monotonic() - start

        # Persist raw output
        try:
            with open(self._raw_log_path, "w", encoding="utf-8") as fh:
                fh.write(result.raw_output)
        except OSError:
            pass

        result.findings = self.parse_output(result.raw_output, self._raw_log_path)
        log.info(
            "[%s] Finished in %.1fs — %d findings",
            self.name, result.duration, len(result.findings),
        )
        return result

    async def run_async(self) -> ToolResult:
        """Async wrapper around run()."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run)

    def _make_finding(
        self,
        url: str,
        status: int,
        length: int = 0,
        response_time: str = "",
        content_type: str = "",
        source_log: str = "",
    ) -> Finding:
        from config import CONFIDENCE_WEIGHTS
        confidence = (
            CONFIDENCE_WEIGHTS["status_200"]
            if status == 200
            else CONFIDENCE_WEIGHTS["status_3xx"]
        )
        return Finding(
            target=self.target,
            url=url,
            status=status,
            length=length,
            tool=self.name,
            response_time=response_time,
            content_type=content_type,
            source_log=source_log,
            confidence=confidence,
        )
