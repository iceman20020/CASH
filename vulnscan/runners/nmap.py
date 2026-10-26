"""Service/version scan + vuln scripts. Parses nmap XML, correlates CVEs."""

from __future__ import annotations

import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

from vulnscan.config import Config
from vulnscan.cve_map import lookup_cves, lookup_eol
from vulnscan.models import Confidence, Finding, Severity, severity_from_cvss
from vulnscan.runners.base import Runner
from vulnscan.target import Target


VULN_SCRIPTS = "vuln,safe and not broadcast"


SCRIPT_SEVERITY = {
    "ssl-heartbleed": ("Heartbleed (CVE-2014-0160)", Severity.CRITICAL, "CVE-2014-0160"),
    "ssl-poodle": ("POODLE SSLv3 (CVE-2014-3566)", Severity.HIGH, "CVE-2014-3566"),
    "ssl-ccs-injection": ("CCS Injection (CVE-2014-0224)", Severity.HIGH, "CVE-2014-0224"),
    "ssl-dh-params": ("Weak DH parameters", Severity.MEDIUM, None),
    "ssl-weak-ciphers": ("Weak SSL ciphers offered", Severity.MEDIUM, None),
    "smb-vuln-ms17-010": ("MS17-010 EternalBlue", Severity.CRITICAL, "CVE-2017-0144"),
    "smb-vuln-ms08-067": ("MS08-067 NetAPI RCE", Severity.CRITICAL, "CVE-2008-4250"),
    "smb-vuln-cve-2017-7494": ("SambaCry (CVE-2017-7494)", Severity.CRITICAL, "CVE-2017-7494"),
    "http-shellshock": ("Shellshock (CVE-2014-6271)", Severity.CRITICAL, "CVE-2014-6271"),
    "http-vuln-cve2017-5638": ("Struts2 Jakarta RCE (CVE-2017-5638)", Severity.CRITICAL, "CVE-2017-5638"),
    "http-vuln-cve2014-3704": ("Drupalgeddon SQLi (CVE-2014-3704)", Severity.CRITICAL, "CVE-2014-3704"),
    "http-vuln-cve2021-41773": ("Apache path traversal (CVE-2021-41773)", Severity.CRITICAL, "CVE-2021-41773"),
    "http-vuln-cve2021-42013": ("Apache path traversal (CVE-2021-42013)", Severity.CRITICAL, "CVE-2021-42013"),
    "http-vuln-cve2019-19781": ("Citrix ADC RCE (CVE-2019-19781)", Severity.CRITICAL, "CVE-2019-19781"),
    "http-vuln-cve2019-11510": ("Pulse Secure file read (CVE-2019-11510)", Severity.CRITICAL, "CVE-2019-11510"),
    "http-vuln-cve2018-13379": ("FortiOS path traversal (CVE-2018-13379)", Severity.CRITICAL, "CVE-2018-13379"),
    "http-vuln-cve2021-26855": ("Exchange ProxyLogon (CVE-2021-26855)", Severity.CRITICAL, "CVE-2021-26855"),
    "ftp-vsftpd-backdoor": ("vsftpd backdoor (CVE-2011-2523)", Severity.CRITICAL, "CVE-2011-2523"),
    "ftp-proftpd-backdoor": ("ProFTPD mod_copy RCE (CVE-2015-3306)", Severity.CRITICAL, "CVE-2015-3306"),
}


class NmapRunner(Runner):
    name = "nmap"
    binary = "nmap"

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if not self.is_available():
            return [Finding(
                tool=self.name, title="nmap not installed",
                description="Install nmap to enable service/version detection.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]

        scan_host = target.host
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = Path(tmp.name)

        args = [
            "nmap", "-sV", "-sC", "--script", VULN_SCRIPTS,
            "--version-intensity", "7",
            "-T4",
            "-oX", str(xml_path),
            scan_host,
        ]
        if cfg.aggressive:
            args = ["nmap", "-sV", "-sC", "-O", "--osscan-guess",
                    "--script", VULN_SCRIPTS, "-T4",
                    "-oX", str(xml_path), scan_host]

        self.run_cmd(args, timeout=max(cfg.timeout, 600))

        if not xml_path.exists() or xml_path.stat().st_size == 0:
            xml_path.unlink(missing_ok=True)
            return [Finding(
                tool=self.name, title="nmap returned no output",
                description="nmap produced no XML — check installation/permissions.",
                severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                host=target.host, category="info_disclosure",
            )]

        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as e:
            xml_path.unlink(missing_ok=True)
            return [Finding(
                tool=self.name, title="nmap XML parse failed",
                description=str(e),
                severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                host=target.host, category="info_disclosure",
            )]
        finally:
            xml_path.unlink(missing_ok=True)

        findings: list[Finding] = []
        root = tree.getroot()
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else target.host

            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    portid = int(port.get("portid", "0"))
                    proto = port.get("protocol", "tcp")
                    svc = port.find("service")
                    findings.extend(self._handle_service(addr, portid, proto, svc))

                    for script in port.findall("script"):
                        findings.extend(self._handle_script(addr, portid, script))

            hs = host.find("hostscript")
            if hs is not None:
                for script in hs.findall("script"):
                    findings.extend(self._handle_script(addr, None, script))

        return findings

    def _handle_service(self, addr, portid, proto, svc) -> list[Finding]:
        out: list[Finding] = []
        if svc is None:
            return out
        name = svc.get("name", "")
        product = svc.get("product", "")
        version = svc.get("version", "")
        extra = svc.get("extrainfo", "")
        tunnel = svc.get("tunnel", "")
        banner = " ".join(x for x in [product, version, extra] if x).strip()

        sev = Severity.INFO
        sensitive = {"ftp", "telnet", "smtp", "pop3", "imap", "rdp", "vnc",
                     "mssql", "mysql", "postgresql", "redis", "mongodb",
                     "elasticsearch", "smb", "netbios-ssn"}
        if name in sensitive:
            sev = Severity.MEDIUM
        if name in ("telnet", "rdp", "vnc"):
            sev = Severity.HIGH

        out.append(Finding(
            tool=self.name,
            title=f"Open port {portid}/{proto} ({name or 'unknown'})",
            description=f"Service {name or '?'} exposed. {banner}".strip(),
            severity=sev, confidence=Confidence.CERTAIN,
            host=addr, port=portid, category="open_port",
            evidence=f"{name} {product} {version} {extra}".strip(),
        ))

        if name == "ftp" and "anonymous" in (extra or "").lower():
            out.append(Finding(
                tool=self.name, title="Anonymous FTP access",
                description=f"FTP on {portid} allows anonymous login.",
                severity=Severity.HIGH, confidence=Confidence.FIRM,
                host=addr, port=portid, category="misconfig", cwe="CWE-287",
                evidence=banner,
            ))
        if name == "telnet":
            out.append(Finding(
                tool=self.name, title="Telnet exposed (plaintext)",
                description=f"Telnet on {portid} transmits credentials in the clear.",
                severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                host=addr, port=portid, category="misconfig", cwe="CWE-319",
            ))
        if tunnel == "ssl":
            out.append(Finding(
                tool=self.name, title=f"TLS-wrapped service on {portid}",
                description=f"{name} served over TLS.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=addr, port=portid, category="info_disclosure",
            ))

        for hit in lookup_cves(product, version):
            out.append(Finding(
                tool=self.name,
                title=f"{hit['cve']}: {hit['title']}",
                description=f"{product} {version} on {portid}/{proto} matches {hit['cve']}.",
                severity=severity_from_cvss(hit["cvss"]),
                confidence=Confidence.FIRM,
                host=addr, port=portid, category="cve",
                cve=hit["cve"], cvss=hit["cvss"], cwe="CWE-1395",
                evidence=banner,
                references=[f"https://nvd.nist.gov/vuln/detail/{hit['cve']}"],
            ))

        eol = lookup_eol(product, version)
        if eol:
            out.append(Finding(
                tool=self.name, title=f"End-of-life software: {product} {version}",
                description=eol,
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                host=addr, port=portid, category="outdated",
                cwe="CWE-1104", evidence=banner,
            ))

        return out

    def _handle_script(self, addr, portid, script) -> list[Finding]:
        out: list[Finding] = []
        sid = script.get("id", "")
        output = script.get("output", "") or ""
        if not output.strip():
            return out

        if sid in SCRIPT_SEVERITY:
            title, sev, cve = SCRIPT_SEVERITY[sid]
            upper = output.upper()
            if "NOT VULNERABLE" in upper or "LIKELY NOT" in upper:
                return out
            out.append(Finding(
                tool=self.name, title=title,
                description=f"nmap script {sid} reports a hit.",
                severity=sev, confidence=Confidence.FIRM,
                host=addr, port=portid,
                category="cve" if cve else "tls_weak",
                cve=cve, cwe="CWE-1395",
                evidence=output[:500],
                references=[f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve else [],
            ))
            return out

        upper = output.upper()
        if "VULNERABLE" in upper and "NOT VULNERABLE" not in upper:
            out.append(Finding(
                tool=self.name, title=f"nmap vuln script reported: {sid}",
                description=f"nmap script {sid} reports vulnerabilities.",
                severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE,
                host=addr, port=portid, category="cve",
                evidence=output[:500],
            ))
        return out
