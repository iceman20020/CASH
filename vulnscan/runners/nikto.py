"""Nikto web server scanner — JSON preferred, XML fallback, txt last resort."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity
from vulnscan.runners.base import Runner
from vulnscan.target import Target


KEYWORD_SEVERITY = [
    (("sql injection", "sqli", "blind sql", "union select"), Severity.CRITICAL),
    (("remote code execution", "rce", "command execution"), Severity.CRITICAL),
    (("default password", "default cred", "admin:admin", "root:root"), Severity.HIGH),
    (("directory traversal", "path traversal", "../"), Severity.HIGH),
    (("arbitrary file", "file read", "file upload"), Severity.HIGH),
    (("outdated", "eol", "end of life"), Severity.MEDIUM),
    (("xss", "cross site scripting", "cross-site scripting"), Severity.MEDIUM),
    (("csrf", "cross-site request"), Severity.MEDIUM),
    (("directory indexing", "directory listing"), Severity.MEDIUM),
    (("information disclosure", "discloses", "reveals", "exposes"), Severity.LOW),
    (("missing", "not set", "header"), Severity.LOW),
]


class NiktoRunner(Runner):
    name = "nikto"
    binary = "nikto"

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if target.is_cidr:
            return []
        if not self.is_available():
            return [Finding(
                tool=self.name, title="nikto not installed",
                description="Install nikto to enable web-server scanning.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]

        url = target.base_url

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            json_path = Path(tmp.name)

        args = [
            "nikto", "-h", url,
            "-Format", "json",
            "-output", str(json_path),
            "-nointeractive",
            "-maxtime", f"{max(cfg.timeout, 300)}s",
        ]
        if cfg.insecure:
            args.append("-ssl")
        if cfg.aggressive:
            args.extend(["-Tuning", "123456789abc"])

        self.run_cmd(args, timeout=max(cfg.timeout, 600))
        findings = self._parse_json(json_path, target, url)
        json_path.unlink(missing_ok=True)

        if findings is None:
            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp2:
                xml_path = Path(tmp2.name)
            args_xml = list(args)
            args_xml[args_xml.index("json")] = "xml"
            args_xml[args_xml.index(str(json_path))] = str(xml_path)
            self.run_cmd(args_xml, timeout=max(cfg.timeout, 600))
            findings = self._parse_xml(xml_path, target, url)
            xml_path.unlink(missing_ok=True)

        return findings or []

    def _parse_json(self, path: Path, target: Target, url: str) -> list[Finding] | None:
        if not path.exists() or path.stat().st_size == 0:
            return None
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (json.JSONDecodeError, OSError):
            return None

        vulns = []
        if isinstance(data, dict):
            host_list = data.get("host", [])
            if isinstance(host_list, list):
                for host in host_list:
                    vulns.extend(host.get("vulnerabilities", []) or host.get("items", []) or [])
            else:
                vulns.extend(data.get("vulnerabilities", []) or data.get("items", []) or [])
        elif isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    vulns.extend(entry.get("vulnerabilities", []) or [])
        else:
            return None

        out: list[Finding] = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            msg = v.get("msg") or v.get("message") or v.get("description") or ""
            if not msg:
                continue
            out.append(Finding(
                tool=self.name,
                title=msg[:160],
                description=msg,
                severity=self._severity_for(msg),
                confidence=Confidence.FIRM,
                host=target.host, url=v.get("url") or url,
                category=self._categorize(msg),
                evidence=json.dumps(v)[:400],
            ))
        return out

    def _parse_xml(self, path: Path, target: Target, url: str) -> list[Finding] | None:
        if not path.exists() or path.stat().st_size == 0:
            return None
        try:
            tree = ET.parse(path)
        except ET.ParseError:
            return None
        out: list[Finding] = []
        for item in tree.getroot().iter("item"):
            desc = item.get("description") or (item.text or "")
            if not desc or not desc.strip():
                continue
            out.append(Finding(
                tool=self.name, title=desc.strip()[:160], description=desc.strip(),
                severity=self._severity_for(desc), confidence=Confidence.FIRM,
                host=target.host, url=item.get("uri") or url,
                category=self._categorize(desc),
                evidence=f"method={item.get('method', '')} uri={item.get('uri', '')}",
            ))
        return out

    @staticmethod
    def _severity_for(msg: str) -> Severity:
        lc = msg.lower()
        for keys, sev in KEYWORD_SEVERITY:
            if any(k in lc for k in keys):
                return sev
        return Severity.LOW

    @staticmethod
    def _categorize(msg: str) -> str:
        lc = msg.lower()
        if "sql" in lc or "injection" in lc:
            return "injection"
        if "xss" in lc or "cross-site" in lc:
            return "xss"
        if "directory" in lc:
            return "dir_listing"
        if "default" in lc and ("pass" in lc or "cred" in lc):
            return "default_creds"
        if "header" in lc:
            return "missing_header"
        if "outdated" in lc or "eol" in lc:
            return "outdated"
        return "info_disclosure"
