"""DNS recon: records, SPF/DMARC/DKIM hygiene, zone transfer, dangling CNAME."""

from __future__ import annotations

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity
from vulnscan.runners.base import Runner
from vulnscan.target import Target


try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


DKIM_SELECTORS = ["default", "google", "k1", "mail", "s1", "s2", "selector1", "selector2"]


class NslookupRunner(Runner):
    name = "dns"
    binary = None

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if target.is_cidr or target.is_ip:
            return []
        if not HAVE_DNSPYTHON:
            return [Finding(
                tool=self.name, title="DNS module not available",
                description="dnspython not installed — skipping DNS checks.",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=target.host, category="info_disclosure",
            )]

        findings: list[Finding] = []
        host = target.host

        addresses = self._resolve(host, "A")
        if not addresses:
            findings.append(Finding(
                tool=self.name, title="No A record found",
                description=f"{host} has no A record.",
                severity=Severity.INFO, confidence=Confidence.FIRM,
                host=host, category="info_disclosure",
            ))
        else:
            findings.append(Finding(
                tool=self.name, title=f"Resolved A records ({len(addresses)})",
                description=f"A records: {', '.join(addresses[:5])}",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=host, category="info_disclosure",
                evidence=", ".join(addresses[:10]),
            ))

        ns_records = self._resolve(host, "NS")
        for ns in ns_records[:5]:
            if self._attempt_axfr(host, ns):
                findings.append(Finding(
                    tool=self.name, title="DNS zone transfer succeeded",
                    description=f"AXFR allowed against {ns} — full zone disclosed.",
                    severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                    host=host, category="dns_zone_transfer", cwe="CWE-16",
                    evidence=f"NS={ns}",
                ))

        txt_records = self._resolve(host, "TXT")
        spf = next((t for t in txt_records if t.startswith("v=spf1")), None)
        if not spf:
            findings.append(Finding(
                tool=self.name, title="SPF record missing",
                description="No v=spf1 TXT record. Email spoofing easier.",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                host=host, category="dns_hygiene", cwe="CWE-290",
            ))
        else:
            tokens = spf.strip().split()
            if tokens and tokens[-1] in ("+all", "?all"):
                findings.append(Finding(
                    tool=self.name, title="SPF record permits spoofing",
                    description=f"SPF ends with {tokens[-1]} — allows any sender.",
                    severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                    host=host, category="dns_hygiene", cwe="CWE-290",
                    evidence=spf,
                ))

        dmarc = self._resolve(f"_dmarc.{host}", "TXT")
        dmarc_rec = next((t for t in dmarc if t.startswith("v=DMARC1")), None)
        if not dmarc_rec:
            findings.append(Finding(
                tool=self.name, title="DMARC record missing",
                description="_dmarc TXT not present.",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                host=host, category="dns_hygiene", cwe="CWE-290",
            ))
        elif "p=none" in dmarc_rec:
            findings.append(Finding(
                tool=self.name, title="DMARC policy is none",
                description="DMARC p=none — monitor only, spoofed mail not blocked.",
                severity=Severity.LOW, confidence=Confidence.CERTAIN,
                host=host, category="dns_hygiene",
                evidence=dmarc_rec,
            ))

        dkim_found = False
        for sel in DKIM_SELECTORS:
            recs = self._resolve(f"{sel}._domainkey.{host}", "TXT")
            if any("v=DKIM1" in r or "p=" in r for r in recs):
                dkim_found = True
                break
        if not dkim_found:
            findings.append(Finding(
                tool=self.name, title="No DKIM selector found",
                description=f"Common selectors ({', '.join(DKIM_SELECTORS[:4])}...) did not resolve.",
                severity=Severity.LOW, confidence=Confidence.TENTATIVE,
                host=host, category="dns_hygiene",
            ))

        cname = self._resolve(host, "CNAME")
        if cname:
            findings.append(Finding(
                tool=self.name, title="CNAME record present",
                description=f"CNAME → {cname[0]}",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                host=host, category="info_disclosure",
                evidence=cname[0],
            ))
            takeover_hints = ("amazonaws.com", "github.io", "herokuapp.com",
                              "azurewebsites.net", "cloudfront.net", "trafficmanager.net",
                              "netlify.app", "vercel.app", "surge.sh")
            if any(h in cname[0] for h in takeover_hints):
                target_a = self._resolve(cname[0], "A")
                if not target_a:
                    findings.append(Finding(
                        tool=self.name, title="Possible subdomain takeover (dangling CNAME)",
                        description=f"CNAME points to {cname[0]} (unresolvable). Claimable service.",
                        severity=Severity.HIGH, confidence=Confidence.FIRM,
                        host=host, category="dns_takeover", cwe="CWE-350",
                        evidence=f"CNAME={cname[0]} (NXDOMAIN)",
                    ))

        caa = self._resolve(host, "CAA")
        if not caa:
            findings.append(Finding(
                tool=self.name, title="CAA record missing",
                description="No CAA — any CA may issue certs for this domain.",
                severity=Severity.LOW, confidence=Confidence.CERTAIN,
                host=host, category="dns_hygiene",
            ))

        return findings

    def _resolve(self, name: str, rtype: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(name, rtype, lifetime=6)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception:
            return []
        out = []
        for r in answers:
            try:
                if rtype == "MX":
                    out.append(f"{r.preference} {r.exchange}".strip().rstrip("."))
                elif rtype in ("CNAME", "NS"):
                    out.append(str(r.target).rstrip("."))
                elif rtype == "TXT":
                    if hasattr(r, "strings"):
                        out.append(b"".join(r.strings).decode(errors="replace"))
                    else:
                        out.append(str(r).strip('"'))
                else:
                    out.append(str(r))
            except Exception:
                continue
        return out

    def _attempt_axfr(self, zone: str, nameserver: str) -> bool:
        try:
            ns_ip = self._resolve(nameserver, "A")
            if not ns_ip:
                return False
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip[0], zone, timeout=6, lifetime=6))
            return z is not None and len(list(z.nodes)) > 0
        except Exception:
            return False
