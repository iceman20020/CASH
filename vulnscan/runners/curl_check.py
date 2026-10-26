"""Header / cookie / CORS / method / redirect / SRI / source-map checks."""

from __future__ import annotations

import re

import requests

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity
from vulnscan.runners.base import Runner
from vulnscan.target import Target


SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS not set", "medium",
        "Set Strict-Transport-Security: max-age>=31536000; includeSubDomains; preload"),
    "content-security-policy": ("CSP not set", "medium",
        "Set Content-Security-Policy to restrict script/style/connect sources"),
    "x-frame-options": ("X-Frame-Options not set", "low",
        "Set X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors"),
    "x-content-type-options": ("X-Content-Type-Options not set", "low",
        "Set X-Content-Type-Options: nosniff"),
    "referrer-policy": ("Referrer-Policy not set", "low",
        "Set Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy": ("Permissions-Policy not set", "info",
        "Set Permissions-Policy to restrict powerful features"),
}

BANNER_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                  "x-aspnetmvc-version", "x-generator"]


class CurlCheckRunner(Runner):
    name = "curl"
    binary = None

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        findings: list[Finding] = []
        if target.is_cidr:
            return findings

        session = requests.Session()
        session.headers["User-Agent"] = cfg.user_agent

        url = target.base_url
        try:
            resp = session.get(url, timeout=15, verify=not cfg.insecure, allow_redirects=True)
        except requests.RequestException as e:
            return [Finding(
                tool=self.name,
                title=f"Request failed: {url}",
                description=f"Could not reach {url}: {e.__class__.__name__}",
                severity=Severity.INFO,
                confidence=Confidence.TENTATIVE,
                host=target.host, url=url, category="info_disclosure",
            )]

        findings.extend(self._check_headers(url, resp))
        findings.extend(self._check_cookies(url, resp))
        findings.extend(self._check_cors(url, session, cfg))
        findings.extend(self._check_methods(url, session, cfg))
        findings.extend(self._check_redirects(url, session, cfg))
        findings.extend(self._check_banner(url, resp))
        findings.extend(self._check_directory_listing(url, resp))
        findings.extend(self._check_sri(url, resp))
        findings.extend(self._check_source_maps(url, resp))
        return findings

    def _check_headers(self, url, resp) -> list[Finding]:
        findings = []
        h = {k.lower(): v for k, v in resp.headers.items()}
        is_https = url.lower().startswith("https")

        for header, (title, sev, fix) in SECURITY_HEADERS.items():
            if header == "strict-transport-security" and not is_https:
                continue
            if header not in h:
                findings.append(Finding(
                    tool=self.name, title=title,
                    description=f"Response from {url} is missing {header}. {fix}.",
                    severity=Severity(sev), confidence=Confidence.CERTAIN,
                    url=url, category="missing_header", cwe="CWE-693",
                    evidence=f"header absent: {header}",
                    references=["https://owasp.org/www-project-secure-headers/"],
                ))
            elif header == "strict-transport-security":
                m = re.search(r"max-age=(\d+)", h[header], re.I)
                if m and int(m.group(1)) < 15552000:
                    findings.append(Finding(
                        tool=self.name, title="HSTS max-age below recommended",
                        description=f"HSTS max-age={m.group(1)}s is below recommended 15552000s.",
                        severity=Severity.LOW, confidence=Confidence.CERTAIN,
                        url=url, category="missing_header", cwe="CWE-319",
                        evidence=h[header],
                    ))
            elif header == "content-security-policy":
                csp = h[header]
                if "unsafe-inline" in csp or "unsafe-eval" in csp:
                    findings.append(Finding(
                        tool=self.name, title="CSP allows unsafe-inline/unsafe-eval",
                        description="CSP contains 'unsafe-inline' or 'unsafe-eval' — weakens XSS defenses.",
                        severity=Severity.LOW, confidence=Confidence.FIRM,
                        url=url, category="missing_header", cwe="CWE-693",
                        evidence=csp[:300],
                    ))
                if "*" in csp and "script-src" in csp:
                    findings.append(Finding(
                        tool=self.name, title="CSP script-src allows wildcard",
                        description="CSP script-src uses '*' — defeats most of CSP's XSS mitigation.",
                        severity=Severity.MEDIUM, confidence=Confidence.FIRM,
                        url=url, category="missing_header", cwe="CWE-693",
                        evidence=csp[:300],
                    ))
        return findings

    def _check_cookies(self, url, resp) -> list[Finding]:
        findings = []
        is_https = url.lower().startswith("https")
        raw_cookies: list[str] = []
        try:
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
        except (AttributeError, Exception):
            pass
        if not raw_cookies:
            sc = resp.headers.get("Set-Cookie")
            if sc:
                raw_cookies = [sc]

        for c in raw_cookies:
            name = c.split("=", 1)[0].strip()
            lc = c.lower()
            if is_https and "secure" not in lc:
                findings.append(Finding(
                    tool=self.name, title=f"Cookie '{name}' missing Secure flag",
                    description="Cookie set over HTTPS without Secure attribute — can leak over plaintext.",
                    severity=Severity.LOW, confidence=Confidence.CERTAIN,
                    url=url, category="cookie_flags", cwe="CWE-614", evidence=c,
                ))
            if "httponly" not in lc:
                findings.append(Finding(
                    tool=self.name, title=f"Cookie '{name}' missing HttpOnly flag",
                    description="Cookie accessible to JavaScript — amplifies XSS impact.",
                    severity=Severity.LOW, confidence=Confidence.CERTAIN,
                    url=url, category="cookie_flags", cwe="CWE-1004", evidence=c,
                ))
            if "samesite" not in lc:
                findings.append(Finding(
                    tool=self.name, title=f"Cookie '{name}' missing SameSite",
                    description="No SameSite attribute — cross-site requests may carry the cookie.",
                    severity=Severity.INFO, confidence=Confidence.CERTAIN,
                    url=url, category="cookie_flags", cwe="CWE-1275", evidence=c,
                ))
        return findings

    def _check_cors(self, url, session, cfg) -> list[Finding]:
        findings = []
        evil = "https://evil.vulnscan.invalid"
        try:
            r = session.get(url, headers={"Origin": evil}, timeout=10, verify=not cfg.insecure)
        except requests.RequestException:
            return findings

        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(Finding(
                tool=self.name, title="CORS: wildcard origin with credentials",
                description="ACAO=* with ACAC=true — spec violation, exploitable if browser accepts.",
                severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                url=url, category="cors_misconfig", cwe="CWE-942",
                evidence=f"ACAO={acao} ACAC={acac}",
            ))
        elif acao == evil:
            findings.append(Finding(
                tool=self.name, title="CORS: arbitrary origin reflected",
                description=f"Server reflects Origin ({evil}) — any site can read authenticated responses.",
                severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                url=url, category="cors_misconfig", cwe="CWE-942",
                evidence=f"ACAO={acao} ACAC={acac}",
            ))
        elif acao == "*":
            findings.append(Finding(
                tool=self.name, title="CORS: wildcard origin",
                description="ACAO=* allows any origin to read responses.",
                severity=Severity.LOW, confidence=Confidence.FIRM,
                url=url, category="cors_misconfig", cwe="CWE-942",
                evidence=f"ACAO={acao}",
            ))
        return findings

    def _check_methods(self, url, session, cfg) -> list[Finding]:
        findings = []
        try:
            r = session.options(url, timeout=10, verify=not cfg.insecure)
        except requests.RequestException:
            return findings
        allow = r.headers.get("Allow", "")
        if "TRACE" in allow.upper():
            findings.append(Finding(
                tool=self.name, title="HTTP TRACE enabled",
                description="Server advertises TRACE — can be abused for Cross-Site Tracing (XST).",
                severity=Severity.LOW, confidence=Confidence.FIRM,
                url=url, category="misconfig", cwe="CWE-693",
                evidence=f"Allow: {allow}",
            ))
        if any(m in allow.upper() for m in ("PUT", "DELETE")) and "GET" in allow.upper():
            findings.append(Finding(
                tool=self.name, title="HTTP PUT/DELETE advertised",
                description="Server advertises state-changing methods on the base URL.",
                severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE,
                url=url, category="misconfig",
                evidence=f"Allow: {allow}",
            ))
        return findings

    def _check_redirects(self, url, session, cfg) -> list[Finding]:
        findings = []
        base = url.split("?", 1)[0]
        for param in ("next", "url", "redirect", "return", "continue"):
            test = f"{base}?{param}=https://evil.vulnscan.invalid"
            try:
                r = session.get(test, timeout=8, verify=not cfg.insecure, allow_redirects=False)
            except requests.RequestException:
                continue
            loc = r.headers.get("Location", "")
            if "evil.vulnscan.invalid" in loc:
                findings.append(Finding(
                    tool=self.name, title=f"Open redirect via '{param}' parameter",
                    description=f"Server redirects to attacker-controlled {param} value.",
                    severity=Severity.MEDIUM, confidence=Confidence.FIRM,
                    url=test, category="open_redirect", cwe="CWE-601",
                    evidence=f"Location: {loc}",
                ))
        return findings

    def _check_banner(self, url, resp) -> list[Finding]:
        findings = []
        h = {k.lower(): v for k, v in resp.headers.items()}
        for header in BANNER_HEADERS:
            if header in h and h[header]:
                findings.append(Finding(
                    tool=self.name, title=f"Banner leak: {header}",
                    description=f"Header '{header}' exposes version or framework: {h[header]}",
                    severity=Severity.INFO, confidence=Confidence.CERTAIN,
                    url=url, category="banner_leak", cwe="CWE-200",
                    evidence=f"{header}: {h[header]}",
                ))
        return findings

    def _check_directory_listing(self, url, resp) -> list[Finding]:
        text = resp.text or ""
        if resp.status_code == 200 and "<title>Index of /" in text[:4000]:
            return [Finding(
                tool=self.name, title="Directory listing enabled",
                description=f"{url} returns an index page listing directory contents.",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                url=url, category="dir_listing", cwe="CWE-548",
                evidence=text[:200],
            )]
        return []

    def _check_sri(self, url, resp) -> list[Finding]:
        findings = []
        body = (resp.text or "")[:100000]
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body, re.I):
            tag = m.group(0)
            src = m.group(1)
            if "integrity=" in tag.lower():
                continue
            if src.startswith(("http://", "https://", "//")):
                host = re.sub(r"^https?://", "", src).split("/", 1)[0]
                if host and host not in url:
                    findings.append(Finding(
                        tool=self.name,
                        title="External script without Subresource Integrity",
                        description=f"External script {src} lacks integrity= — supply-chain risk.",
                        severity=Severity.LOW, confidence=Confidence.FIRM,
                        url=url, category="sri_missing", cwe="CWE-353",
                        evidence=tag[:200],
                    ))
                    break
        return findings

    def _check_source_maps(self, url, resp) -> list[Finding]:
        body = (resp.text or "")[:200000]
        if "sourceMappingURL=" in body:
            return [Finding(
                tool=self.name, title="Source maps referenced in production",
                description="Page references .map files — source code may be publicly readable.",
                severity=Severity.LOW, confidence=Confidence.FIRM,
                url=url, category="info_disclosure", cwe="CWE-540",
                evidence="sourceMappingURL present",
            )]
        return []
