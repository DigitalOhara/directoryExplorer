"""
Orchestration engine: runs tools sequentially or concurrently per target,
handles multi-target parallelism, resume support, and SQLite persistence.
"""

import asyncio
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from config import (
    OUTPUT_ROOT, SUMMARY_DIR, TARGETS_DIR, TARGET_SUBDIRS,
    SQLITE_DB_NAME, SUPPORTED_TOOLS,
)
from parser import normalize_all
from tools import TOOL_REGISTRY
from tools.base import Finding, ToolResult
from utils.logging_utils import get_logger
from utils.network import Target
from utils.fingerprint import fingerprint_target, parse_robots_txt

log = get_logger()


# ── SQLite helpers ─────────────────────────────────────────────────────────────

def _init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target          TEXT,
            url             TEXT,
            status          INTEGER,
            length          INTEGER,
            tool            TEXT,
            response_time   TEXT,
            content_type    TEXT,
            timestamp       TEXT,
            source_log      TEXT,
            confidence      REAL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_state (
            target TEXT PRIMARY KEY,
            status TEXT,   -- pending / running / completed / failed
            started_at TEXT,
            finished_at TEXT
        )
    """)
    conn.commit()
    return conn


def _mark_target(conn: sqlite3.Connection, target_url: str, status: str):
    now = datetime.now(timezone.utc).isoformat()
    existing = conn.execute(
        "SELECT 1 FROM scan_state WHERE target=?", (target_url,)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE scan_state SET status=?, finished_at=? WHERE target=?",
            (status, now, target_url),
        )
    else:
        conn.execute(
            "INSERT INTO scan_state (target, status, started_at, finished_at) VALUES (?,?,?,?)",
            (target_url, status, now, now),
        )
    conn.commit()


def _is_completed(conn: sqlite3.Connection, target_url: str) -> bool:
    row = conn.execute(
        "SELECT status FROM scan_state WHERE target=?", (target_url,)
    ).fetchone()
    return row is not None and row["status"] == "completed"


def _save_findings(conn: sqlite3.Connection, findings: List[Finding]):
    rows = [
        (
            f.target, f.url, f.status, f.length, f.tool,
            f.response_time, f.content_type, f.timestamp,
            f.source_log, f.confidence,
        )
        for f in findings
    ]
    conn.executemany(
        """INSERT INTO findings
           (target,url,status,length,tool,response_time,content_type,
            timestamp,source_log,confidence)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.commit()


# ── Target directory helpers ───────────────────────────────────────────────────

def _target_dir(output_root: str, target_name: str) -> str:
    path = os.path.join(output_root, TARGETS_DIR, target_name)
    for sub in TARGET_SUBDIRS:
        Path(os.path.join(path, sub)).mkdir(parents=True, exist_ok=True)
    return path


# ── Single target scan ─────────────────────────────────────────────────────────

def scan_target(
    target: Target,
    args: Any,
    output_root: str,
    db_conn: sqlite3.Connection,
    wordlist_path: str,
) -> Dict:
    """
    Run all selected tools against one target, normalize results, persist, and
    return a summary dict.
    """
    tdir = _target_dir(output_root, target.name)
    start_time = time.monotonic()
    scan_start_ts = datetime.now(timezone.utc).isoformat()

    log.info("=" * 70)
    log.info("Scanning target: %s  (%s)", target.name, target.url)
    log.info("=" * 70)

    _mark_target(db_conn, target.url, "running")

    all_findings: List[Finding] = []
    tool_results: List[ToolResult] = []
    errors: List[str] = []

    # Fingerprint first
    fingerprint = {}
    try:
        log.info("[%s] Fingerprinting target…", target.name)
        fingerprint = fingerprint_target(
            target.url,
            headers=_build_headers(args),
            timeout=args.timeout,
            proxy=args.proxy,
        )
        robots_paths = parse_robots_txt(target.url, timeout=args.timeout, proxy=args.proxy)
        fingerprint["robots_paths"] = robots_paths
        _save_fingerprint(tdir, fingerprint)
    except Exception as exc:
        log.warning("[%s] Fingerprinting failed: %s", target.name, exc)

    # Tool execution
    selected_tools = _resolve_tools(args)
    common_kwargs = _build_tool_kwargs(args, target.url, tdir, wordlist_path)

    for tool_name in selected_tools:
        ToolClass = TOOL_REGISTRY.get(tool_name)
        if not ToolClass:
            continue

        tool = ToolClass(**common_kwargs)
        if not tool.is_available():
            log.warning("[%s] %s not installed — skipping", target.name, tool_name)
            continue

        log.info("[%s] Running %s…", target.name, tool_name)
        try:
            result = tool.run()
        except Exception as exc:
            err = f"{tool_name} error: {exc}"
            log.error("[%s] %s", target.name, err)
            errors.append(err)
            continue

        if result.error:
            errors.append(result.error)

        tool_results.append(result)
        all_findings.extend(result.findings)

        # Save raw stderr
        if result.stderr_output:
            stderr_path = os.path.join(tdir, "logs", f"{tool_name}_stderr.txt")
            with open(stderr_path, "w", encoding="utf-8") as fh:
                fh.write(result.stderr_output)

    # Normalize & deduplicate
    normalized = normalize_all(all_findings, args.status_filter or [200, 301, 302, 307, 308])

    # Persist
    _save_findings(db_conn, normalized)
    _save_parsed_json(tdir, normalized)

    duration = time.monotonic() - start_time
    _mark_target(db_conn, target.url, "completed" if not errors else "failed")

    # Build summary
    status_dist: Dict[int, int] = {}
    for f in normalized:
        status_dist[f.status] = status_dist.get(f.status, 0) + 1

    summary = {
        "target_name":       target.name,
        "target_url":        target.url,
        "findings_count":    len(normalized),
        "status_distribution": status_dist,
        "tools_used":        [r.tool_name for r in tool_results],
        "duration_seconds":  round(duration, 2),
        "scan_start":        scan_start_ts,
        "scan_end":          datetime.now(timezone.utc).isoformat(),
        "errors":            errors,
        "fingerprint":       fingerprint,
        "findings":          [f.to_dict() for f in normalized],
        "output_dir":        tdir,
    }

    return summary


# ── Multi-target orchestration ─────────────────────────────────────────────────

def run_scan(targets: List[Target], args: Any, wordlist_path: str) -> Dict:
    """
    Entry point for all scanning.  Handles sequential and parallel execution.
    Returns master summary dict.
    """
    output_root = args.output or OUTPUT_ROOT
    Path(os.path.join(output_root, SUMMARY_DIR)).mkdir(parents=True, exist_ok=True)

    db_path = os.path.join(output_root, SQLITE_DB_NAME)
    db_conn = _init_db(db_path)

    parallel = getattr(args, "parallel_targets", 2)
    resume = getattr(args, "resume", False)

    # Filter already-completed targets when resuming
    pending = []
    skipped = []
    for t in targets:
        if resume and _is_completed(db_conn, t.url):
            log.info("Skipping completed target (resume): %s", t.url)
            skipped.append(t)
        else:
            pending.append(t)

    all_summaries: List[Dict] = []

    # Reload previously completed summaries for the master report
    for t in skipped:
        partial = _load_saved_summary(output_root, t)
        if partial:
            all_summaries.append(partial)

    if parallel > 1 and len(pending) > 1:
        summaries = asyncio.run(
            _run_parallel(pending, args, output_root, db_conn, wordlist_path, parallel)
        )
    else:
        summaries = []
        for t in pending:
            try:
                s = scan_target(t, args, output_root, db_conn, wordlist_path)
                summaries.append(s)
                _save_target_summary(output_root, t, s)
            except Exception as exc:
                log.error("Fatal error scanning %s: %s", t.url, exc)
                summaries.append({
                    "target_url": t.url,
                    "target_name": t.name,
                    "findings_count": 0,
                    "errors": [str(exc)],
                    "findings": [],
                })

    all_summaries.extend(summaries)

    master = {
        "total_targets": len(targets),
        "completed":     len([s for s in all_summaries if not s.get("errors")]),
        "failed":        len([s for s in all_summaries if s.get("errors")]),
        "skipped":       len(skipped),
        "total_findings": sum(s.get("findings_count", 0) for s in all_summaries),
        "targets":       all_summaries,
        "generated_at":  datetime.now(timezone.utc).isoformat(),
    }

    db_conn.close()
    return master


async def _run_parallel(
    targets: List[Target],
    args: Any,
    output_root: str,
    db_conn: sqlite3.Connection,
    wordlist_path: str,
    parallel: int,
) -> List[Dict]:
    semaphore = asyncio.Semaphore(parallel)
    loop = asyncio.get_event_loop()

    async def _one(t: Target) -> Dict:
        async with semaphore:
            try:
                summary = await loop.run_in_executor(
                    None, scan_target, t, args, output_root, db_conn, wordlist_path
                )
                _save_target_summary(output_root, t, summary)
                return summary
            except Exception as exc:
                log.error("Fatal error scanning %s: %s", t.url, exc)
                return {
                    "target_url": t.url, "target_name": t.name,
                    "findings_count": 0, "errors": [str(exc)], "findings": [],
                }

    return list(await asyncio.gather(*[_one(t) for t in targets]))


# ── Helpers ────────────────────────────────────────────────────────────────────

def _build_headers(args: Any) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for h in (args.header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.auth:
        headers["Authorization"] = args.auth
    if not args.random_agent:
        ua = getattr(args, "user_agent", None)
        if ua:
            headers["User-Agent"] = ua
    return headers


def _build_tool_kwargs(
    args: Any, target_url: str, tdir: str, wordlist_path: str
) -> Dict:
    import random
    from config import USER_AGENTS, DEFAULT_USER_AGENT

    ua = DEFAULT_USER_AGENT
    if args.random_agent:
        ua = random.choice(USER_AGENTS)
    elif getattr(args, "user_agent", None):
        ua = args.user_agent

    headers = _build_headers(args)

    return dict(
        target=target_url,
        wordlist=wordlist_path,
        output_dir=tdir,
        extensions=args.extensions or [],
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        headers=headers,
        cookies=args.cookies,
        auth=args.auth,
        proxy=args.proxy,
        user_agent=ua,
        follow_redirects=args.follow_redirects,
        recursion_depth=args.recursion_depth,
        status_filter=args.status_filter or [200, 301, 302, 307, 308],
        verbose=args.verbose,
    )


def _resolve_tools(args: Any) -> List[str]:
    if args.tool:
        requested = [t.strip().lower() for t in args.tool]
        return [t for t in requested if t in SUPPORTED_TOOLS]
    return list(SUPPORTED_TOOLS)


def _save_fingerprint(tdir: str, fp: Dict):
    path = os.path.join(tdir, "parsed", "fingerprint.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(fp, fh, indent=2)


def _save_parsed_json(tdir: str, findings: List[Finding]):
    path = os.path.join(tdir, "parsed", "findings.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2)


def _save_target_summary(output_root: str, target: Target, summary: Dict):
    path = os.path.join(
        output_root, TARGETS_DIR, target.name, "parsed", "summary.json"
    )
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)


def _load_saved_summary(output_root: str, target: Target) -> Optional[Dict]:
    path = os.path.join(
        output_root, TARGETS_DIR, target.name, "parsed", "summary.json"
    )
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return None
