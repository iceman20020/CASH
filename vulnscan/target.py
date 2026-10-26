from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse
import ipaddress
import re


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


@dataclass
class Target:
    raw: str
    scheme: str | None
    host: str
    port: int | None
    path: str
    is_ip: bool
    is_cidr: bool

    @property
    def base_url(self) -> str:
        if self.is_cidr:
            return self.host
        scheme = self.scheme or "https"
        return self.url_for(self.path or "/", scheme)

    @property
    def bare_host(self) -> str:
        return self.host

    def url_for(self, path: str, scheme: str | None = None) -> str:
        s = scheme or self.scheme or "https"
        if not path.startswith("/"):
            path = "/" + path
        port = f":{self.port}" if self.port and self.port not in (80, 443) else ""
        return f"{s}://{self.host}{port}{path}"


def normalize_target(raw: str) -> Target:
    raw = raw.strip()
    scheme = None
    host = ""
    port: int | None = None
    path = "/"

    if _SCHEME_RE.match(raw):
        parsed = urlparse(raw)
        scheme = parsed.scheme
        host = parsed.hostname or ""
        port = parsed.port
        path = parsed.path or "/"
    else:
        if "/" in raw and not raw.startswith("/"):
            host_part, _, path_part = raw.partition("/")
            path = "/" + path_part
        else:
            host_part = raw
        # handle IPv6 in brackets: [::1]:8080
        if host_part.startswith("[") and "]" in host_part:
            host, _, rest = host_part[1:].partition("]")
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except ValueError:
                    port = None
        elif host_part.count(":") == 1:
            h, _, p = host_part.partition(":")
            host = h
            try:
                port = int(p)
            except ValueError:
                port = None
        else:
            host = host_part

    is_ip = False
    is_cidr = False
    host_check = host
    if "/" in raw and not _SCHEME_RE.match(raw):
        # raw may be a CIDR like 10.0.0.0/24
        try:
            ipaddress.ip_network(raw, strict=False)
            is_cidr = True
            host = raw
            host_check = raw.split("/", 1)[0]
        except ValueError:
            pass
    try:
        ipaddress.ip_address(host_check)
        is_ip = True
    except ValueError:
        pass

    return Target(
        raw=raw,
        scheme=scheme,
        host=host,
        port=port,
        path=path or "/",
        is_ip=is_ip,
        is_cidr=is_cidr,
    )
