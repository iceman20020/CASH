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
            out.append(host_line)
        if f.url:
            out.append(f"- **url**: `{f.url}`")
        out.append("")
        out.append(_wrap_code(f.description))
        if f.evidence:
            out.append("")
            out.append("<details><summary>evidence</summary>")
            out.append("")
            out.append(_wrap_code(f.evidence[:2000]))
            out.append("</details>")
        if f.references:
            out.append("")
            for ref in f.references[:5]:
                if ref:
                    out.append(f"- {ref}")
        out.append("")

    return "\n".join(out)


_HTML_HEAD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>vulnscan — __TITLE__</title>
<style>
 :root{
   --bg:#0a0e17; --panel:#0f1421; --panel2:#131a2b; --line:#1e2740;
   --fg:#c8d3e8; --dim:#7a8699; --accent:#00e5ff; --magenta:#d61f9e;
   --crit:#ff3355; --high:#ff6644; --med:#ffcc44; --low:#44ccff; --info:#8899aa;
 }
 *{box-sizing:border-box}
 html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);
   font-family:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
   font-size:14px;line-height:1.55}
 body::before{content:"";position:fixed;inset:0;pointer-events:none;
   background:radial-gradient(1200px 800px at 20% -10%, rgba(0,229,255,.10), transparent 60%),
              radial-gradient(900px 600px at 110% 10%, rgba(214,31,158,.10), transparent 60%);
   z-index:0}
 .wrap{position:relative;z-index:1;max-width:1200px;margin:0 auto;padding:32px 24px 80px}
 .banner{color:var(--accent);font-size:11px;line-height:1.05;margin:0 0 8px;
   text-shadow:0 0 12px rgba(0,229,255,.35);filter:saturate(1.15)}
 .brandline{display:flex;gap:14px;flex-wrap:wrap;align-items:baseline;
   color:var(--dim);font-size:12px;letter-spacing:.04em;margin-bottom:28px}
 .brandline b{color:var(--accent)}
 h1{font-size:22px;margin:0 0 6px;color:#fff;letter-spacing:.03em}
 h1 code{color:var(--accent);background:transparent;font-weight:inherit}
 h2{font-size:16px;margin:32px 0 12px;color:#fff;letter-spacing:.05em;text-transform:uppercase}
 .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
   gap:10px;margin:14px 0 6px}
 .meta div{background:var(--panel);border:1px solid var(--line);border-radius:6px;
   padding:10px 12px;font-size:12px;color:var(--dim)}
 .meta div b{color:var(--fg);display:block;font-size:13px;margin-top:2px}
 .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
   gap:10px;margin:14px 0 4px}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:6px;
   padding:14px 16px}
 .card .n{font-size:28px;font-weight:700;color:#fff}
 .card .l{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim)}
 .card.crit{border-color:rgba(255,51,85,.5)} .card.crit .n{color:var(--crit)}
 .card.high{border-color:rgba(255,102,68,.5)} .card.high .n{color:var(--high)}
 .card.med{border-color:rgba(255,204,68,.4)} .card.med .n{color:var(--med)}
 .card.low{border-color:rgba(68,204,255,.4)} .card.low .n{color:var(--low)}
 .card.info .n{color:var(--info)}
 .f{background:var(--panel);border:1px solid var(--line);border-left-width:3px;
   border-radius:6px;padding:14px 16px;margin:10px 0;position:relative}
 .f.crit{border-left-color:var(--crit)} .f.high{border-left-color:var(--high)}
 .f.med{border-left-color:var(--med)} .f.low{border-left-color:var(--low)}
 .f.info{border-left-color:var(--info)}
 .f .head{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}
 .f .sev{font-size:10px;letter-spacing:.1em;text-transform:uppercase;font-weight:700;
   padding:2px 8px;border-radius:3px;background:var(--panel2)}
 .f.crit .sev{color:var(--crit)} .f.high .sev{color:var(--high)}
 .f.med .sev{color:var(--med)} .f.low .sev{color:var(--low)} .f.info .sev{color:var(--info)}
 .f .title{font-size:15px;color:#fff;font-weight:600;flex:1 1 auto;min-width:0}
 .f .tool{font-size:11px;color:var(--dim)}
 .f .tags{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 4px}
 .f .tag{font-size:11px;padding:2px 8px;border:1px solid var(--line);border-radius:3px;
   color:var(--dim)}
 .f .tag a{color:inherit;text-decoration:none;border-bottom:1px dotted var(--dim)}
 .f .tag.owasp{color:var(--accent);border-color:rgba(0,229,255,.35)}
 .f p{margin:10px 0 0;color:var(--fg)}
 .f details{margin-top:10px}
 .f summary{cursor:pointer;color:var(--dim);font-size:12px}
 .f pre{background:#050810;border:1px solid var(--line);border-radius:4px;
   padding:10px;overflow:auto;font-size:12px;color:#a9b8d0;max-height:320px}
 a{color:var(--accent)}
 footer{margin-top:60px;padding-top:20px;border-top:1px solid var(--line);
   color:var(--dim);font-size:12px}
</style></head><body><div class="wrap">
"""


def _html_escape(s: str) -> str:
    return ((s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _html(result: ScanResult) -> str:
    s = result.summary()
    parts: list[str] = [_HTML_HEAD.replace("__TITLE__", _html_escape(result.target))]
    parts.append(banner_html())
    parts.append(
        '<div class="brandline">'
        '<span><b>vulnscan</b></span>'
        f'<span>started {_html_escape(result.started_at)}</span>'
        f'<span>finished {_html_escape(result.finished_at)}</span>'
        f'<span>findings {len(result.findings)}</span>'
        "</div>"
    )
    parts.append(f"<h1>scan: <code>{_html_escape(result.target)}</code></h1>")

    tech = result.meta.get("tech") or {}
    waf = result.meta.get("waf") or {}
    if any(tech.values()) or waf.get("detected"):
        parts.append('<div class="meta">')
        for key, label in (("server", "server"), ("powered_by", "powered-by"),
                           ("language", "language"), ("framework", "framework"),
                           ("cms", "cms"), ("cdn", "cdn")):
            v = tech.get(key)
            if v:
                parts.append(f"<div>{label}<b>{_html_escape(v)}</b></div>")
        if waf.get("detected"):
            parts.append(f"<div>waf<b>{_html_escape(waf.get('name', ''))}</b></div>")
        parts.append("</div>")

    parts.append('<div class="cards">')
    for key, cls in [("critical", "crit"), ("high", "high"), ("medium", "med"),
                     ("low", "low"), ("info", "info")]:
        parts.append(
            f'<div class="card {cls}"><div class="n">{s[key]}</div>'
            f'<div class="l">{key}</div></div>'
        )
    parts.append("</div>")

    parts.append("<h2>findings</h2>")
    for f in result.findings:
        cls = {"critical": "crit", "high": "high", "medium": "med",
               "low": "low", "info": "info"}[f.severity.value]
        parts.append(f'<div class="f {cls}">')
        parts.append('<div class="head">')
        parts.append(f'<span class="sev">{f.severity.value}</span>')
        parts.append(f'<span class="title">{_html_escape(f.title)}</span>')
        parts.append(
            f'<span class="tool">{_html_escape(f.tool)} · '
            f'{_html_escape(f.confidence.value)}</span>'
        )
        parts.append("</div>")
        parts.append('<div class="tags">')
        parts.append(
            f'<span class="tag owasp">'
            f'<a href="{_html_escape(f.owasp_url)}" target="_blank" rel="noopener">'
            f'{f.owasp_id} {_html_escape(f.owasp_name)}</a></span>'
        )
        if f.cwe:
            parts.append(f'<span class="tag">cwe {_html_escape(f.cwe)}</span>')
        if f.cve:
            parts.append(
                f'<span class="tag"><a href="https://nvd.nist.gov/vuln/detail/{_html_escape(f.cve)}" '
                f'target="_blank" rel="noopener">{_html_escape(f.cve)}</a></span>'
            )
        if f.cvss is not None:
            parts.append(f'<span class="tag">cvss {f.cvss}</span>')
        if f.host:
            host_str = f.host + (f":{f.port}" if f.port else "")
            parts.append(f'<span class="tag">{_html_escape(host_str)}</span>')
        parts.append("</div>")
        parts.append(f"<p>{_html_escape(f.description)}</p>")
        if f.url:
            parts.append(
                f'<p><a href="{_html_escape(f.url)}" target="_blank" rel="noopener">'
                f'{_html_escape(f.url)}</a></p>'
            )
        if f.evidence:
            parts.append("<details><summary>evidence</summary>")
            parts.append(f"<pre>{_html_escape(f.evidence[:4000])}</pre>")
            parts.append("</details>")
        if f.references:
            for r in f.references[:5]:
                if r:
                    parts.append(
                        f'<p><a href="{_html_escape(r)}" target="_blank" rel="noopener">'
                        f'{_html_escape(r)}</a></p>'
                    )
        parts.append("</div>")

    parts.append(
        '<footer>vulnscan · owasp reference '
        f'<a href="{top10_reference()}" target="_blank" rel="noopener">owasp.org/Top10</a></footer>'
    )
    parts.append("</div></body></html>")
    return "".join(parts)


def _txt(result: ScanResult) -> str:
    s = result.summary()
    lines: list[str] = [banner_txt(), ""]
    lines.append(f"target:   {result.target}")
    lines.append(f"started:  {result.started_at}")
    lines.append(f"finished: {result.finished_at}")
    lines.append("")
    lines.append("summary:")
    for k in ("critical", "high", "medium", "low", "info"):
        lines.append(f"  {k:9s} {s[k]}")
    lines.append("")
    lines.append("=" * 78)
    for i, f in enumerate(result.findings, 1):
        lines.append(f"[{i}] {f.severity.value.upper():8s} {f.title}")
        lines.append(f"    tool={f.tool} confidence={f.confidence.value}")
        lines.append(f"    owasp={f.owasp_id} {f.owasp_name}  {f.owasp_url}")
        if f.cwe:
            lines.append(f"    cwe={f.cwe}")
        if f.cve:
            lines.append(f"    cve={f.cve}")
        if f.host:
            lines.append(f"    host={f.host}" + (f":{f.port}" if f.port else ""))
        if f.url:
            lines.append(f"    url={f.url}")
        lines.append(f"    {f.description}")
        if f.evidence:
            lines.append("    evidence:")
            for el in f.evidence.splitlines()[:15]:
                lines.append(f"      {el}")
        lines.append("-" * 78)
    return "\n".join(lines)
