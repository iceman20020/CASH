"""Passive subdomain enumeration via crt.sh + optional brute."""

from __future__ import annotations

import concurrent.futures as cf
import socket

import requests

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity
from vulnscan.runners.base import Runner
from vulnscan.target import Target


BRUTE_WORDLIST = [
    "www", "mail", "api", "dev", "staging", "stage", "test", "qa", "uat", "prod",
    "admin", "portal", "vpn", "internal", "intranet", "gitlab", "git", "jenkins",
    "ci", "cd", "grafana", "prometheus", "monitor", "kibana", "elastic", "db",
    "mysql", "postgres", "redis", "s3", "static", "assets", "cdn", "media",
    "img", "docs", "help", "support", "auth", "sso", "id", "oauth", "app",
    "web", "app1", "app2", "beta", "alpha", "sandbox", "demo", "backup",
]


class SubdomainRunner(Runner):
    name = "subdomains"
    binary = None

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if target.is_ip or target.is_cidr:
            return []
        if not cfg.subdomain_enum:
            return []

        apex = target.host
        parts = apex.split(".")
        if len(parts) >= 3 and not apex.replace(".", "").isdigit():
            # crude public-suffix shrink — keep last two labels for anything 3+ deep
            # unless it's a known 2-part ccTLD pattern like example.co.uk
            if parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
                apex = ".".join(parts[-3:])
            else:
                apex = ".".join(parts[-2:])

        subs = self._from_crtsh(apex, cfg)
        if cfg.subdomain_brute:
            subs |= self._brute(apex, cfg)

        subs.discard(apex)
        subs.discard(target.host)

        if not subs:
            return []

        findings = [Finding(
            tool=self.name,
            title=f"Subdomains discovered ({len(subs)})",
            description=f"Passive+active enumeration found {len(subs)} subdomains.",
            severity=Severity.INFO,
            confidence=Confidence.FIRM,
            host=apex, category="subdomain",
            evidence=", ".join(sorted(subs)[:30]),
        )]

        risky = [s for s in subs if any(k in s.split(".")[0] for k in
                 ("dev", "test", "stage", "staging", "qa", "uat", "admin",
                  "internal", "intranet", "backup", "jenkins", "gitlab", "jira"))]
        for s in risky[:15]:
            findings.append(Finding(
                tool=self.name,
                title=f"Potentially sensitive subdomain: {s}",
                description="Naming convention suggests non-production / internal surface.",
                severity=Severity.LOW,
                confidence=Confidence.TENTATIVE,
                host=s, category="subdomain",
            ))

        context["subdomains"] = sorted(subs)
        return findings

    def _from_crtsh(self, apex: str, cfg: Config) -> set[str]:
        out: set[str] = set()
        try:
            r = requests.get(
                f"https://crt.sh/?q=%25.{apex}&output=json",
                timeout=15, headers={"User-Agent": cfg.user_agent},
            )
            if r.status_code == 200:
                for row in r.json():
                    for name in (row.get("name_value") or "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(apex):
                            out.add(name)
        except Exception:
            pass
        return out

    def _brute(self, apex: str, cfg: Config) -> set[str]:
        found: set[str] = set()

        def check(sub: str) -> str | None:
            host = f"{sub}.{apex}"
            try:
                socket.gethostbyname(host)
                return host
            except (socket.gaierror, OSError):
                return None

        with cf.ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for r in ex.map(check, BRUTE_WORDLIST):
                if r:
                    found.add(r)
        return found
