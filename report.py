"""
Report generation: HTML, CSV, TXT, JSON for individual targets and master summary.
"""

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import VERSION


# ── Template loader ────────────────────────────────────────────────────────────

def _load_template(name: str) -> str:
    tpl_path = os.path.join(os.path.dirname(__file__), "templates", name)
    if os.path.isfile(tpl_path):
        with open(tpl_path, "r", encoding="utf-8") as fh:
            return fh.read()
    return ""


# ── Individual target reports ──────────────────────────────────────────────────

def write_target_reports(summary: Dict, output_dir: str, args: Any):
    reports_dir = os.path.join(output_dir, "reports")
    Path(reports_dir).mkdir(parents=True, exist_ok=True)

    findings = summary.get("findings", [])

    write_json(findings, os.path.join(reports_dir, "findings.json"))
    write_csv(findings, os.path.join(reports_dir, "findings.csv"), summary)
    write_txt(summary, os.path.join(reports_dir, "summary.txt"))
    write_html_target(summary, os.path.join(reports_dir, "report.html"))


def write_json(findings: List[Dict], path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)


def write_csv(findings: List[Dict], path: str, summary: Optional[Dict] = None):
    fieldnames = [
        "target", "url", "status", "length", "tool",
        "response_time", "content_type", "timestamp", "confidence",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)


def write_txt(summary: Dict, path: str):
    lines = [
        "=" * 70,
        f"  directoryExplorer v{VERSION} — Scan Report",
        "=" * 70,
        f"  Target  : {summary.get('target_url', 'N/A')}",
        f"  Started : {summary.get('scan_start', 'N/A')}",
        f"  Finished: {summary.get('scan_end', 'N/A')}",
        f"  Duration: {summary.get('duration_seconds', 0):.1f}s",
        f"  Tools   : {', '.join(summary.get('tools_used', []))}",
        f"  Findings: {summary.get('findings_count', 0)}",
        "",
        "  Status Distribution:",
    ]
    for code, count in sorted(summary.get("status_distribution", {}).items()):
        lines.append(f"    HTTP {code}: {count}")

    fp = summary.get("fingerprint", {})
    if fp.get("technologies"):
        lines += ["", "  Detected Technologies:"]
        for tech in fp["technologies"]:
            lines.append(f"    - {tech}")

    if summary.get("errors"):
        lines += ["", "  Errors:"]
        for err in summary["errors"]:
            lines.append(f"    [!] {err}")

    lines += [
        "",
        "  Discovered Endpoints:",
        "-" * 70,
    ]
    for f in summary.get("findings", []):
        lines.append(
            f"  [{f['status']}] {f['url']:<60}  ({f['tool']})  [{f['length']} bytes]"
        )

    lines += ["", "=" * 70, "  END OF REPORT", "=" * 70]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_html_target(summary: Dict, path: str):
    tpl = _load_template("report_template.html")
    if not tpl:
        return

    findings = summary.get("findings", [])
    fp = summary.get("fingerprint", {})

    rows_html = _findings_to_rows(findings)
    status_chart_data = json.dumps(summary.get("status_distribution", {}))
    tools_list = ", ".join(summary.get("tools_used", []))
    technologies = ", ".join(fp.get("technologies", [])) or "N/A"

    html = tpl.replace("{{TITLE}}", f"Scan Report — {summary.get('target_url', '')}")
    html = html.replace("{{TARGET_URL}}", summary.get("target_url", "N/A"))
    html = html.replace("{{SCAN_START}}", summary.get("scan_start", "N/A"))
    html = html.replace("{{SCAN_END}}", summary.get("scan_end", "N/A"))
    html = html.replace("{{DURATION}}", str(summary.get("duration_seconds", 0)))
    html = html.replace("{{FINDINGS_COUNT}}", str(summary.get("findings_count", 0)))
    html = html.replace("{{TOOLS_USED}}", tools_list)
    html = html.replace("{{TECHNOLOGIES}}", technologies)
    html = html.replace("{{FINDINGS_ROWS}}", rows_html)
    html = html.replace("{{STATUS_CHART_DATA}}", status_chart_data)
    html = html.replace("{{VERSION}}", VERSION)
    html = html.replace("{{IS_MASTER}}", "false")
    html = html.replace("{{MASTER_TARGETS_DATA}}", "[]")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ── Master summary report ──────────────────────────────────────────────────────

def write_master_reports(master: Dict, output_root: str, args: Any):
    from config import SUMMARY_DIR
    summary_dir = os.path.join(output_root, SUMMARY_DIR)
    Path(summary_dir).mkdir(parents=True, exist_ok=True)

    # Flatten all findings
    all_findings = []
    for t in master.get("targets", []):
        all_findings.extend(t.get("findings", []))

    write_json(master, os.path.join(summary_dir, "master_report.json"))
    write_csv(all_findings, os.path.join(summary_dir, "master_report.csv"))
    write_master_txt(master, os.path.join(summary_dir, "master_report.txt"))
    write_master_html(master, os.path.join(summary_dir, "master_report.html"))


def write_master_txt(master: Dict, path: str):
    lines = [
        "=" * 70,
        f"  directoryExplorer v{VERSION} — Master Report",
        "=" * 70,
        f"  Generated : {master.get('generated_at', 'N/A')}",
        f"  Targets   : {master.get('total_targets', 0)}",
        f"  Completed : {master.get('completed', 0)}",
        f"  Failed    : {master.get('failed', 0)}",
        f"  Findings  : {master.get('total_findings', 0)}",
        "",
        "  Target Summary:",
        "-" * 70,
    ]

    for t in master.get("targets", []):
        status = "FAILED" if t.get("errors") else "OK"
        lines.append(
            f"  [{status}] {t.get('target_url', 'N/A'):<50}  "
            f"{t.get('findings_count', 0)} findings  "
            f"{t.get('duration_seconds', 0):.1f}s"
        )

    lines += ["", "=" * 70, "  END OF MASTER REPORT", "=" * 70]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_master_html(master: Dict, path: str):
    tpl = _load_template("report_template.html")
    if not tpl:
        return

    all_findings = []
    for t in master.get("targets", []):
        all_findings.extend(t.get("findings", []))

    rows_html = _findings_to_rows(all_findings)

    # Aggregate status distribution
    status_dist: Dict[str, int] = {}
    for t in master.get("targets", []):
        for code, cnt in t.get("status_distribution", {}).items():
            key = str(code)
            status_dist[key] = status_dist.get(key, 0) + cnt

    targets_data = json.dumps([
        {
            "name":        t.get("target_name", ""),
            "url":         t.get("target_url", ""),
            "findings":    t.get("findings_count", 0),
            "duration":    t.get("duration_seconds", 0),
            "tools":       ", ".join(t.get("tools_used", [])),
            "status":      "Failed" if t.get("errors") else "OK",
            "errors":      "; ".join(t.get("errors", [])),
        }
        for t in master.get("targets", [])
    ])

    html = tpl.replace("{{TITLE}}", "directoryExplorer — Master Report")
    html = html.replace("{{TARGET_URL}}", f"{master.get('total_targets', 0)} targets")
    html = html.replace("{{SCAN_START}}", master.get("generated_at", "N/A"))
    html = html.replace("{{SCAN_END}}", master.get("generated_at", "N/A"))
    html = html.replace("{{DURATION}}", "N/A")
    html = html.replace("{{FINDINGS_COUNT}}", str(master.get("total_findings", 0)))
    html = html.replace("{{TOOLS_USED}}", "Multiple")
    html = html.replace("{{TECHNOLOGIES}}", "N/A")
    html = html.replace("{{FINDINGS_ROWS}}", rows_html)
    html = html.replace("{{STATUS_CHART_DATA}}", json.dumps(status_dist))
    html = html.replace("{{VERSION}}", VERSION)
    html = html.replace("{{IS_MASTER}}", "true")
    html = html.replace("{{MASTER_TARGETS_DATA}}", targets_data)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _findings_to_rows(findings: List[Dict]) -> str:
    rows = []
    for f in findings:
        status = f.get("status", 0)
        status_class = (
            "status-ok" if status == 200 else
            "status-redirect" if 300 <= status < 400 else
            "status-error"
        )
        confidence_pct = int(f.get("confidence", 1.0) * 100)
        rows.append(
            f'<tr>'
            f'<td><span class="badge {status_class}">{status}</span></td>'
            f'<td class="url-cell"><a href="{_esc(f.get("url",""))}" target="_blank">'
            f'{_esc(f.get("url",""))}</a></td>'
            f'<td>{_esc(f.get("target",""))}</td>'
            f'<td>{f.get("length",0)}</td>'
            f'<td><span class="tool-tag">{_esc(f.get("tool",""))}</span></td>'
            f'<td>{_esc(f.get("content_type",""))}</td>'
            f'<td>{_esc(f.get("response_time",""))}</td>'
            f'<td>{confidence_pct}%</td>'
            f'<td>{_esc(f.get("timestamp","")[:19])}</td>'
            f'</tr>'
        )
    return "\n".join(rows)


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
