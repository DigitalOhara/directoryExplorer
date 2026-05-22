"""
URL validation and multi-target file parsing.
"""

import csv
import json
import re
from pathlib import Path
from typing import List, NamedTuple, Optional
from urllib.parse import urlparse


class Target(NamedTuple):
    name: str
    url: str


def validate_url(url: str) -> bool:
    """Return True if url is a well-formed http/https URL with a real hostname."""
    try:
        result = urlparse(url.strip())
        if result.scheme not in ("http", "https"):
            return False
        netloc = result.hostname or ""
        if not netloc:
            return False
        # Require at least one dot (real FQDN) OR be a valid IPv4/IPv6/localhost
        import ipaddress
        try:
            ipaddress.ip_address(netloc)
            return True  # valid IP
        except ValueError:
            pass
        if netloc == "localhost":
            return True
        return "." in netloc
    except Exception:
        return False


def _sanitise(url: str) -> str:
    url = url.strip()
    if url and not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def _name_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.replace(":", "_")
    except Exception:
        return re.sub(r"[^a-zA-Z0-9_.-]", "_", url)[:64]


def parse_targets_file(path: str, fmt: str = "plain") -> List[Target]:
    """
    Parse a targets file in plain / csv / json format.
    Returns a list of validated Target namedtuples.
    Malformed entries are skipped with a warning printed to stderr.
    """
    import sys

    file_path = Path(path)
    if not file_path.is_file():
        print(f"[!] Targets file not found: {path}", file=sys.stderr)
        return []

    targets: List[Target] = []
    fmt = fmt.lower()

    try:
        if fmt == "plain":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                for lineno, raw in enumerate(fh, 1):
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    url = _sanitise(line)
                    if validate_url(url):
                        targets.append(Target(name=_name_from_url(url), url=url))
                    else:
                        print(
                            f"[!] Skipping malformed URL on line {lineno}: {line}",
                            file=sys.stderr,
                        )

        elif fmt == "csv":
            with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as fh:
                reader = csv.DictReader(fh)
                for lineno, row in enumerate(reader, 2):
                    url = _sanitise(row.get("url", row.get("URL", "")).strip())
                    name = row.get("name", row.get("Name", "")).strip() or _name_from_url(url)
                    if validate_url(url):
                        targets.append(Target(name=name, url=url))
                    else:
                        print(
                            f"[!] Skipping malformed CSV row {lineno}: {row}",
                            file=sys.stderr,
                        )

        elif fmt == "json":
            with open(file_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for idx, entry in enumerate(data):
                url = _sanitise(entry.get("url", entry.get("URL", "")).strip())
                name = entry.get("name", entry.get("Name", "")).strip() or _name_from_url(url)
                if validate_url(url):
                    targets.append(Target(name=name, url=url))
                else:
                    print(
                        f"[!] Skipping malformed JSON entry {idx}: {entry}",
                        file=sys.stderr,
                    )

        else:
            print(f"[!] Unknown target format: {fmt}", file=sys.stderr)

    except Exception as exc:
        print(f"[!] Error parsing targets file: {exc}", file=sys.stderr)

    return targets
