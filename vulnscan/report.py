from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from vulnscan.banner import banner_html, banner_md, banner_txt
from vulnscan.models import Finding, ScanResult, Severity
from vulnscan.owasp import top10_reference


SEV_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_summary(console: Console, result: ScanResult) -> None:
    sev = result.summary()
    table = Table(title="summary", border_style="magenta", show_lines=False)
    table.add_column("severity", style="bold")
    table.add_column("count", justify="right")
    for s in ("critical", "high", "medium", "low", "info"):
        color = SEV_COLOR[Severity(s)]
        table.add_row(f"[{color}]{s}[/]", f"[{color}]{sev[s]}[/]")
    console.print(table)

    if result.findings:
        top = Table(title="top findings", border_style="cyan", show_lines=False)
        top.add_column("sev", width=9)
        top.add_column("tool", width=10)
        top.add_column("title")
        top.add_column("owasp", width=10)
        for f in result.findings[:15]:
            title = f.title[:70] + ("…" if len(f.title) > 70 else "")
            top.add_row(
                f"[{SEV_COLOR[f.severity]}]{f.severity.value}[/]",
                f.tool,
                title,
                f.owasp_id,
            )
        console.print(top)


def write_all(result: ScanResult, out_dir: str, formats: list[str]) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base = _slug(result.target)

    if "json" in formats:
        (out / f"{base}.json").write_text(
            json.dumps(result_payload(result), indent=2), encoding="utf-8"
        )
    if "md" in formats:
        (out / f"{base}.md").write_text(_md(result), encoding="utf-8")
    if "html" in formats:
        (out / f"{base}.html").write_text(_html(result), encoding="utf-8")
    if "txt" in formats:
        (out / f"{base}.txt").write_text(_txt(result), encoding="utf-8")

    return out


def result_payload(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "owasp_reference": top10_reference(),
        "summary": result.summary(),
        "meta": result.meta,
        "findings": [f.to_dict() for f in result.findings],
    }


def _slug(s: str) -> str:
    keep = "".join(c if c.isalnum() or c in "-._" else "_" for c in s)
    return keep[:80] or "scan"


def _wrap_code(s: str) -> str:
    return "```\n" + s.replace("```", "'''") + "\n```"


def _md(result: ScanResult) -> str:
    s = result.summary()
    out: list[str] = [banner_md(), ""]
    out.append(f"## Scan: `{result.target}`")
    out.append("")
    out.append(f"- started: `{result.started_at}`")
    out.append(f"- finished: `{result.finished_at}`")
    out.append("")
    out.append("### Summary")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---|")
    for k in ("critical", "high", "medium", "low", "info"):
        out.append(f"| {k} | {s[k]} |")
    out.append("")

    tech = result.meta.get("tech") or {}
    if any(tech.values()):
        out.append("### Fingerprint")
        out.append("")
        for k, v in tech.items():
            if v:
                out.append(f"- **{k}**: {v}")
        out.append("")

    waf = result.meta.get("waf") or {}
    if waf.get("detected"):
        out.append("### WAF")
        out.append("")
        out.append(f"- **{waf['name']}** — {waf.get('evidence', '')}")
        out.append("")

    out.append("### Findings")
    out.append("")
    for i, f in enumerate(result.findings, 1):
        out.append(f"#### {i}. [{f.severity.value.upper()}] {f.title}")
        out.append("")
        out.append(f"- **tool**: `{f.tool}` · **confidence**: `{f.confidence.value}`")
        out.append(f"- **owasp**: [{f.owasp_id} {f.owasp_name}]({f.owasp_url})")
        if f.cwe:
            out.append(f"- **cwe**: `{f.cwe}`")
        if f.cve:
            out.append(f"- **cve**: [`{f.cve}`](https://nvd.nist.gov/vuln/detail/{f.cve})")
        if f.cvss is not None:
            out.append(f"- **cvss**: `{f.cvss}`")
        if f.host:
            host_line = f"- **host**: `{f.host}`"
            if f.port:
                host_line += f":{f.port}"
            out.append(
