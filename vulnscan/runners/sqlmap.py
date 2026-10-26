"""sqlmap against discovered parameterized URLs (from crawler)."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity
from vulnscan.runners.base import Runner
from vulnscan.target import Target


INJECT_TYPE_RE = re.compile(r"Type:\s*([^\n]+)")
PAYLOAD_RE = re.compile(r"Payload:\s*([^\n]+)")
DBMS_RE = re.compile(r"back-end DBMS:\s*([^\n]+)")
PARAM_RE = re.compile(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)")


class SQLMapRunner(Runner):
    name = "sqlmap"
    binary = "sqlmap"

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if target.is_cidr:
            return []
        if not self.is_available():
            return [Finding(
                tool=self.name, title="sqlmap not installed",
                description="Install sqlmap to enable SQL injection scanning.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]

        crawl = context.get("crawl")
        param_urls: list[str] = []
        if crawl:
            param_urls = list(crawl.param_urls)[:8]
            for form in crawl.forms[:8]:
                if form.get("inputs") and form.get("method") == "get":
                    pairs = "&".join(f"{i['name']}=test" for i in form["inputs"])
                    sep = "&" if "?" in form["action"] else "?"
                    param_urls.append(form["action"] + sep + pairs)

        if not param_urls:
            return [Finding(
                tool=self.name, title="No parameterized URLs for sqlmap",
                description="Crawler found no query-string URLs or GET forms.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]

        findings: list[Finding] = []
        for url in param_urls:
            findings.extend(self._scan(url, target, cfg))
        return findings

    def _scan(self, url: str, target: Target, cfg: Config) -> list[Finding]:
        level = "3" if cfg.aggressive else "2"
        risk = "2" if cfg.aggressive else "1"
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "sqlmap"
            args = [
                "sqlmap", "-u", url,
                "--batch", "--random-agent",
                "--level", level, "--risk", risk,
                "--timeout", "20", "--retries", "0",
                "--output-dir", str(out_dir),
                "--flush-session",
                "--technique", "BEUSTQ",
            ]
            _, stdout, _ = self.run_cmd(args, timeout=max(cfg.timeout, 300))
        return self._parse(stdout, url, target)

    def _parse(self, out: str, url: str, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        low = out.lower()
        if "is vulnerable" not in low and "injectable" not in low and "Parameter:" not in out:
            return findings

        blocks = re.split(r"\n(?=Parameter:)", out)
        for block in blocks:
            pm = PARAM_RE.search(block)
            if not pm:
                continue
            param, place = pm.group(1), pm.group(2)
            types = INJECT_TYPE_RE.findall(block)
            payloads = PAYLOAD_RE.findall(block)
            dbms = DBMS_RE.search(block)

            desc_parts = [f"Parameter {param} is injectable."]
            if types:
                desc_parts.append("Technique(s): " + ", ".join(t.strip() for t in types[:4]))
            if dbms:
                desc_parts.append(f"Back-end DBMS: {dbms.group(1).strip()}")

            findings.append(Finding(
                tool=self.name,
                title=f"SQL injection: parameter '{param}' ({place})",
                description=" ".join(desc_parts),
                severity=Severity.CRITICAL,
                confidence=Confidence.CERTAIN,
                url=url, host=target.host, port=target.port,
                category="sqli", cwe="CWE-89",
                evidence=(payloads[0].strip()[:400] if payloads else "") + f"\n[param={param} {place}]",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ))
        return findings
