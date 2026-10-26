"""OpenVAS / GVM. Two modes: parse an existing XML report, or drive gvm-cli."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from xml.etree import ElementTree as ET

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity, severity_from_cvss
from vulnscan.runners.base import Runner
from vulnscan.target import Target


class OpenVASRunner(Runner):
    name = "openvas"
    binary = "gvm-cli"

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if cfg.openvas_report:
            return self._from_report(cfg.openvas_report, target)

        if not self.is_available() or not cfg.gvm_socket:
            return [Finding(
                tool=self.name, title="OpenVAS not configured",
                description="Provide --openvas-report <xml> or --gvm-socket with credentials.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]

        return self._live_scan(target, cfg)

    def _from_report(self, path: str, target: Target) -> list[Finding]:
        p = Path(path)
        if not p.exists():
            return [Finding(
                tool=self.name, title="OpenVAS report missing",
                description=f"Report file not found: {path}",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]
        try:
            tree = ET.parse(p)
        except ET.ParseError as e:
            return [Finding(
                tool=self.name, title="OpenVAS report parse failed",
                description=str(e), severity=Severity.INFO,
                confidence=Confidence.TENTATIVE, host=target.host,
                category="info_disclosure",
            )]
        return self._parse_report_root(tree.getroot(), target)

    def _parse_report_root(self, root, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for result in root.iter("result"):
            name_el = result.find("name")
            host_el = result.find("host")
            port_el = result.find("port")
            threat = (result.findtext("threat") or "").strip().lower()
            severity_str = result.findtext("severity") or "0"
            desc = result.findtext("description") or ""
            nvt = result.find("nvt")
            cve = nvt.findtext("cve") if nvt is not None else None
            try:
                cvss = float(severity_str) if severity_str else None
            except ValueError:
                cvss = None

            sev = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "log": Severity.INFO,
                "debug": Severity.INFO,
            }.get(threat)
            if not sev and cvss is not None:
                sev = severity_from_cvss(cvss)
            if not sev:
                sev = Severity.MEDIUM

            port = None
            if port_el is not None and port_el.text:
                digits = re.sub(r"\D", "", port_el.text)
                if digits:
                    port = int(digits)

            cve_first = None
            if cve:
                parts = [c.strip() for c in cve.split(",") if c.strip()]
                if parts:
                    cve_first = parts[0]

            findings.append(Finding(
                tool=self.name,
                title=(name_el.text if name_el is not None and name_el.text else "OpenVAS finding")[:160],
                description=(desc or "")[:1000],
                severity=sev, confidence=Confidence.FIRM,
                host=host_el.text if host_el is not None and host_el.text else target.host,
                port=port,
                category="cve" if cve_first else "misconfig",
                cve=cve_first, cvss=cvss, cwe="CWE-1395",
                evidence=desc[:400],
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_first}"] if cve_first else [],
            ))
        return findings

    def _live_scan(self, target: Target, cfg: Config) -> list[Finding]:
        def gvm(xml: str) -> tuple[int, str, str]:
            args = [
                "gvm-cli", "socket",
                "--socketpath", cfg.gvm_socket or "",
                "--gmp-username", cfg.gvm_user or "",
                "--gmp-password", cfg.gvm_pass or "",
                "--xml", xml,
            ]
            try:
                proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
                return proc.returncode, proc.stdout, proc.stderr
            except subprocess.TimeoutExpired:
                return -9, "", "timeout"

        rc, out, err = gvm("<get_tasks/>")
        if rc != 0:
            return [Finding(
                tool=self.name, title="gvm-cli task listing failed",
                description=f"gvm-cli returned {rc}: {err[:300]}",
                severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                host=target.host, category="info_disclosure",
            )]

        task_id = None
        try:
            root = ET.fromstring(out)
            for task in root.iter("task"):
                name = task.findtext("name") or ""
                if target.host in name:
                    task_id = task.get("id")
                    break
        except ET.ParseError:
            pass

        if not task_id:
            return [Finding(
                tool=self.name, title="No GVM task matches target",
                description="Create a task in Greenbone named after the target, then re-run.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]

        gvm(f'<start_task task_id="{task_id}"/>')
        rc, out, _ = gvm(f'<get_reports filter="task_id={task_id} rows=1"/>')
        try:
            root = ET.fromstring(out)
        except ET.ParseError:
            return [Finding(
                tool=self.name, title="GVM report fetch failed",
                description="Non-XML response from gvm-cli.",
                severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                host=target.host, category="info_disclosure",
            )]
        return self._parse_report_root(root, target)
