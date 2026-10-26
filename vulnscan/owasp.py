"""OWASP Top 10 (2021) mapping for findings."""

from __future__ import annotations

OWASP_TOP10 = {
    "A01": ("A01:2021", "Broken Access Control", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "A02": ("A02:2021", "Cryptographic Failures", "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "A03": ("A03:2021", "Injection", "https://owasp.org/Top10/A03_2021-Injection/"),
    "A04": ("A04:2021", "Insecure Design", "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    "A05": ("A05:2021", "Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "A06": ("A06:2021", "Vulnerable and Outdated Components", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    "A07": ("A07:2021", "Identification and Authentication Failures", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    "A08": ("A08:2021", "Software and Data Integrity Failures", "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    "A09": ("A09:2021", "Security Logging and Monitoring Failures", "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    "A10": ("A10:2021", "Server-Side Request Forgery (SSRF)", "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
}

_CATEGORY_MAP = {
    "exposed_file": "A05",
    "exposed_config": "A05",
    "exposed_secret": "A02",
    "exposed_creds": "A07",
    "dir_listing": "A05",
    "admin_panel": "A05",
    "default_creds": "A07",
    "auth_bypass": "A01",
    "access_control": "A01",
    "missing_header": "A05",
    "security_header": "A05",
    "banner_leak": "A05",
    "cors_misconfig": "A05",
    "cookie_flags": "A02",
    "tls_weak": "A02",
    "tls_cert": "A02",
    "injection": "A03",
    "sqli": "A03",
    "xss": "A03",
    "rce": "A03",
    "vulnerable_component": "A06",
    "outdated": "A06",
    "cve": "A06",
    "dns_hygiene": "A05",
    "dns_zone_transfer": "A01",
    "dns_takeover": "A05",
    "subdomain": "A05",
    "ssrf": "A10",
    "open_redirect": "A01",
    "graphql_introspection": "A01",
    "swagger_exposed": "A05",
    "debug_exposed": "A05",
    "waf": "A05",
    "info_disclosure": "A05",
    "open_port": "A05",
    "default_service": "A05",
    "misconfig": "A05",
    "sri_missing": "A08",
}


def map_owasp(category: str, title: str = "", description: str = "") -> tuple[str, str, str]:
    key = (category or "").lower()
    oid = _CATEGORY_MAP.get(key)

    if not oid:
        blob = f"{title} {description}".lower()
        if any(k in blob for k in ("sql inject", "sqli", "injectable", "blind sql", "union select")):
            oid = "A03"
        elif any(k in blob for k in ("cve-", "outdated", "vulnerable version", "eol", "end of life", "known vulnerab")):
            oid = "A06"
        elif any(k in blob for k in ("tls", "ssl", "cipher", "certificate", "cookie", ".env", "secret", "api key", "password")):
            oid = "A02"
        elif any(k in blob for k in ("admin", "login", "auth", "default cred")):
            oid = "A07"
        elif any(k in blob for k in ("cors", "header", "banner", "misconfig", "directory listing", "index of /")):
            oid = "A05"
        elif any(k in blob for k in ("ssrf", "redirect", "url param")):
            oid = "A10"
        else:
            oid = "A05"

    ident, name, url = OWASP_TOP10[oid]
    return ident, name, url


def top10_reference() -> str:
    return "https://owasp.org/www-project-top-ten/"
