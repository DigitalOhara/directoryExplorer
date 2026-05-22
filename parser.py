"""
Post-processing: deduplication, confidence scoring, and normalization.
"""

from collections import defaultdict
from typing import Dict, List

from tools.base import Finding
from config import CONFIDENCE_WEIGHTS


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate by URL.  When a URL is found by multiple tools, keep one entry
    with the best status / length and bump the confidence score.
    """
    by_url: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_url[f.url].append(f)

    merged: List[Finding] = []
    for url, group in by_url.items():
        # Prefer 200 over redirects when multiple tools agree
        group.sort(key=lambda f: (f.status != 200, f.status))
        primary = group[0]

        # Bonus confidence for multi-tool confirmation
        extra = (len(group) - 1) * CONFIDENCE_WEIGHTS["multi_tool"]
        primary.confidence = min(1.0, primary.confidence + extra)

        # Aggregate source tools
        tools = list({f.tool for f in group})
        primary.tool = ",".join(sorted(tools))

        merged.append(primary)

    return merged


def filter_by_status(
    findings: List[Finding], allowed: List[int]
) -> List[Finding]:
    return [f for f in findings if f.status in allowed]


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (f.status, f.url))


def normalize_all(
    findings: List[Finding],
    status_filter: List[int],
) -> List[Finding]:
    """Full normalization pipeline."""
    findings = filter_by_status(findings, status_filter)
    findings = deduplicate(findings)
    findings = sort_findings(findings)
    return findings
