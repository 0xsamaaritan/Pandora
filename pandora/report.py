"""Reporting + optional notifications for a scan run."""
from __future__ import annotations

import json
import logging
import os
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText

import requests

from .model import Finding, SEVERITY_ORDER

log = logging.getLogger("pandora.report")


def _sort(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.source))


def write_reports(mode: str, out_dir: str, new: list[Finding],
                  total: list[Finding]) -> str:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")

    # full snapshot as JSON
    with open(os.path.join(out_dir, f"{mode}-latest.json"), "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in _sort(total)], fh, indent=2, ensure_ascii=False)

    # human-readable markdown summary for THIS run
    md_path = os.path.join(out_dir, f"{mode}-{ts}.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(_markdown(mode, ts, new, total))
    return md_path


def _markdown(mode: str, ts: str, new: list[Finding], total: list[Finding]) -> str:
    lines = [f"# Pandora — {mode} run @ {ts}", ""]
    lines.append(f"- New findings this run: **{len(new)}**")
    lines.append(f"- Total tracked ({mode}): **{len(total)}**")
    lines.append("")
    if not new:
        lines.append("_No new findings since last run._")
        return "\n".join(lines)
    lines.append("## New findings")
    for f in _sort(new):
        terms = ", ".join(f.matched_terms) if f.matched_terms else "-"
        lines.append(f"### [{f.severity.upper()}] {f.title}")
        lines.append(f"- source: `{f.source}`  |  matched: {terms}")
        if f.url:
            lines.append(f"- url: {f.url}")
        if f.snippet:
            lines.append(f"- context: {f.snippet}")
        lines.append("")
    return "\n".join(lines)


def console_summary(mode: str, new: list[Finding], total: list[Finding]) -> None:
    print(f"\n=== pandora [{mode}] : {len(new)} new / {len(total)} total ===")
    for f in _sort(new):
        url = f" -> {f.url}" if f.url else ""
        print(f"  [{f.severity.upper():8}] ({f.source}) {f.title}{url}")
    if not new:
        print("  (nothing new)")


def notify(cfg: dict, mode: str, new: list[Finding]) -> None:
    """Fire optional alerts only when there are new findings."""
    if not new:
        return
    text = f"[pandora/{mode}] {len(new)} NEW finding(s):\n" + "\n".join(
        f"- [{f.severity}] ({f.source}) {f.title} {f.url}".strip() for f in _sort(new)[:25])

    hook = cfg.get("webhook_url")
    if hook:
        try:
            requests.post(hook, json={"text": text}, timeout=15)
        except Exception as e:  # noqa: BLE001
            log.warning("webhook notify failed: %s", e)

    smtp = cfg.get("smtp") or {}
    if smtp.get("host") and smtp.get("to"):
        try:
            msg = MIMEText(text)
            msg["Subject"] = f"[pandora/{mode}] {len(new)} new finding(s)"
            msg["From"] = smtp.get("from", smtp["to"])
            msg["To"] = smtp["to"]
            with smtplib.SMTP(smtp["host"], smtp.get("port", 587), timeout=20) as s:
                if smtp.get("starttls", True):
                    s.starttls()
                if smtp.get("user"):
                    s.login(smtp["user"], smtp.get("password", ""))
                s.send_message(msg)
        except Exception as e:  # noqa: BLE001
            log.warning("email notify failed: %s", e)
