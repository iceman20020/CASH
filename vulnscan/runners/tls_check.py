"""Deep TLS: cert chain, expiry, self-signed, protocol, cipher."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity
from vulnscan.runners.base import Runner
from vulnscan.target import Target


WEAK_CIPHERS = ("RC4", "3DES", "DES-CBC", "EXPORT", "NULL", "MD5")
WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


class TLSCheckRunner(Runner):
    name = "tls"
    binary = None

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if target.is_cidr:
            return []

        # skip unless https or explicitly port 443
        if target.is_ip and target.scheme != "https" and target.port not in (None, 443):
            return []

        findings: list[Finding] = []
        host = target.host
        port = target.port or 443

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()
        except (socket.timeout, ConnectionError, ssl.SSLError, OSError) as e:
            return [Finding(
                tool=self.name, title="TLS handshake failed",
                description=f"Could not establish TLS to {host}:{port}: {e.__class__.__name__}",
                severity=Severity.INFO, confidence=Confidence.TENTATIVE,
                host=host, port=port, category="tls_cert",
            )]

        if proto in WEAK_PROTOCOLS:
            findings.append(Finding(
                tool=self.name, title=f"Weak TLS protocol negotiated: {proto}",
                description=f"{proto} is deprecated/unsafe.",
                severity=Severity.HIGH if proto in ("SSLv2", "SSLv3") else Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                host=host, port=port, category="tls_weak", cwe="CWE-326",
                evidence=f"version={proto}",
            ))

        if cipher and any(w in cipher[0] for w in WEAK_CIPHERS):
            findings.append(Finding(
                tool=self.name, title=f"Weak cipher negotiated: {cipher[0]}",
                description="Cipher suite is known-weak.",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                host=host, port=port, category="tls_weak", cwe="CWE-327",
                evidence=f"cipher={cipher[0]} bits={cipher[2]}",
            ))

        if not cert:
            findings.append(Finding(
                tool=self.name, title="No certificate returned",
                description="Server returned no certificate during handshake.",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                host=host, port=port, category="tls_cert",
            ))
            return findings

        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if exp < now:
                findings.append(Finding(
                    tool=self.name, title="TLS certificate expired",
                    description=f"Certificate expired {exp.date()}.",
                    severity=Severity.HIGH, confidence=Confidence.CERTAIN,
                    host=host, port=port, category="tls_cert", cwe="CWE-298",
                    evidence=f"notAfter={not_after}",
                ))
            elif (exp - now).days < 30:
                findings.append(Finding(
                    tool=self.name, title="TLS certificate expiring soon",
                    description=f"Certificate expires in {(exp - now).days} days.",
                    severity=Severity.LOW, confidence=Confidence.CERTAIN,
                    host=host, port=port, category="tls_cert",
                    evidence=f"notAfter={not_after}",
                ))

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        if subject == issuer:
            findings.append(Finding(
                tool=self.name, title="Self-signed TLS certificate",
                description="Certificate is self-signed — not trusted by default browsers.",
                severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                host=host, port=port, category="tls_cert", cwe="CWE-295",
                evidence=f"subject=issuer={subject.get('commonName', '')}",
            ))

        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        if sans and host not in sans and not any(
            s.startswith("*.") and host.endswith(s[1:]) for s in sans
        ):
            findings.append(Finding(
                tool=self.name, title="Certificate name mismatch",
                description=f"Host {host} not in CN/SAN ({sans[:3]}...).",
                severity=Severity.MEDIUM, confidence=Confidence.FIRM,
                host=host, port=port, category="tls_cert", cwe="CWE-297",
                evidence=f"CN={subject.get('commonName')} SAN={sans[:5]}",
            ))

        return findings
