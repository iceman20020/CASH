from __future__ import annotations

import datetime as _dt

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnscan.config import Config
from vulnscan.crawler import crawl
from vulnscan.models import Confidence, Finding, ScanResult, Severity
from vulnscan.owasp import map_owasp
from vulnscan.runners.base import Runner
from vulnscan.runners.curl_check import CurlCheckRunner
from vulnscan.runners.exposed_files import ExposedFilesRunner
from vulnscan.runners.nikto import NiktoRunner
from vulnscan.runners.nmap import NmapRunner
from vulnscan.runners.nslookup import NslookupRunner
from vulnscan.runners.openvas import OpenVASRunner
from vulnscan.runners.sqlmap import SQLMapRunner
from vulnscan.runners.subdomain import SubdomainRunner
from vulnscan.runners.tls_check import TLSCheckRunner
from vulnscan.target import Target, normalize_target
from vulnscan.tech_fingerprint import fingerprint
from vulnscan.waf_detect import detect as detect_waf


console = Console()


def _sort_runners(cfg: Config) -> list[Runner]:
    candidates: list[Runner] = [
        CurlCheckRunner(),
        NslookupRunner(),
        TLSCheckRunner(),
        ExposedFilesRunner(),
        SubdomainRunner(),
        NmapRunner(),
        NiktoRunner(),
        SQLMapRunner(),
        OpenVASRunner(),
    ]
    return [r for r in candidates if cfg.enabled(r.name)]


def self_fill(finding: Finding, target: Target) -> None:
    if not finding.host:
        finding.host = target.host
    if not finding.target:
        finding.target = target.raw
    oid, name, url = map_owasp(finding.category, finding.title, finding.description)
    finding.owasp_id = oid
    finding.owasp_name = name
    finding.owasp_url = url


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple, Finding] = {}
    for f in findings:
        k = f.dedupe_key()
        if k in merged:
            existing = merged[k]
            if f.evidence and f.evidence not in existing.evidence:
                existing.evidence = (existing.evidence + "\n---\n" + f.evidence)[:2000]
            if f.severity.rank > existing.severity.rank:
                existing.severity = f.severity
            if f.cve and not existing.cve:
                existing.cve = f.cve
        else:
            merged[k] = f
    out = list(merged.values())
    out.sort(key=lambda f: (-f.severity.rank, -f.confidence.rank, f.tool, f.title))
    return out


def _preflight(target: Target, cfg: Config, context: dict, result: ScanResult) -> None:
    session = requests.Session()
    session.headers["User-Agent"] = cfg.user_agent

    if target.is_cidr:
        result.meta["reachable"] = None
        return

    if target.scheme:
        candidates = [target.base_url]
    else:
        candidates = [target.url_for("/", "https"), target.url_for("/", "http")]

    chosen = None
    for url in candidates:
        try:
            r = session.get(url, timeout=8, verify=not cfg.insecure, allow_redirects=True)
            chosen = (url, r)
            break
        except requests.RequestException:
            continue

    if not chosen:
        result.meta["reachable"] = False
        return

    url, resp = chosen
    target.scheme = url.split(":", 1)[0]
    result.meta["reachable"] = True
    result.meta["final_url"] = resp.url

    prof = fingerprint(resp)
    result.meta["tech"] = prof.to_dict()

    waf = detect_waf(resp)
    result.meta["waf"] = {"detected": waf.detected, "name": waf.name, "evidence": waf.evidence}
    if waf.detected:
        result.add([Finding(
            tool="preflight",
            title=f"WAF detected: {waf.name}",
            description=f"Traffic passes through {waf.name}. Some probes may be blocked.",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            host=target.host, url=url, category="waf",
            evidence=waf.evidence,
        )])


def run_scan(raw_target: str, cfg: Config) -> ScanResult:
    target = normalize_target(raw_target)
    result = ScanResult(target=raw_target)
    result.meta["target_normalized"] = {
        "host": target.host,
        "port": target.port,
        "scheme": target.scheme,
        "is_ip": target.is_ip,
        "is_cidr": target.is_cidr,
    }

    console.print(
        f"[bold cyan]vulnscan[/] → [bold]{target.host}[/]"
        + (f":{target.port}" if target.port else "")
    )

    context: dict = {}
    _preflight(target, cfg, context, result)

    if cfg.crawl and not target.is_cidr and not target.is_ip and result.meta.get("reachable"):
        with console.status("[cyan]crawling...[/]"):
            try:
                context["crawl"] = crawl(
                    target.base_url,
                    depth=cfg.crawl_depth,
                    max_urls=cfg.crawl_max,
                    timeout=max(cfg.timeout // 10, 8),
                    verify=not cfg.insecure,
                    user_agent=cfg.user_agent,
                )
            except Exception:
                context["crawl"] = None
        if context.get("crawl"):
            result.meta["crawl"] = {
                "urls": len(context["crawl"].urls),
                "param_urls": len(context["crawl"].param_urls),
                "forms": len(context["crawl"].forms),
            }

    runners = _sort_runners(cfg)
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        for runner in runners:
            task_id = progress.add_task(f"[cyan]{runner.name}[/]...", total=None)
            try:
                fs = runner.run(target, cfg, context)
            except Exception as e:
                fs = [Finding(
                    tool=runner.name,
                    title=f"runner exception: {e.__class__.__name__}",
                    description=str(e)[:300],
                    severity=Severity.INFO,
                    confidence=Confidence.TENTATIVE,
                    host=target.host, category="info_disclosure",
                )]
            for f in fs:
                self_fill(f, target)
            result.add(fs)
            progress.update(
                task_id,
                description=f"[green]{runner.name}[/] ✓ {len(fs)} finding(s)",
                completed=1,
            )

    result.findings = dedupe(result.findings)
    result.finished_at = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    return result
