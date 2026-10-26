"""Lightweight same-origin crawler. Feeds sqlmap + curl checks with real URLs."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urldefrag
import re

import requests

try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    BeautifulSoup = None  # type: ignore[assignment]
    HAVE_BS4 = False


LINK_ATTRS = [("a", "href"), ("link", "href"), ("script", "src"),
              ("img", "src"), ("form", "action"), ("iframe", "src")]


@dataclass
class CrawlResult:
    urls: list[str] = field(default_factory=list)
    param_urls: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)


def _extract_links_regex(html: str, base: str) -> tuple[list[str], list[dict]]:
    links: list[str] = []
    for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', html, re.I):
        links.append(m.group(1))
    return [urljoin(base, l) for l in links], []


def _extract_links(html: str, base: str) -> tuple[list[str], list[dict]]:
    if not HAVE_BS4:
        return _extract_links_regex(html, base)

    links: list[str] = []
    forms: list[dict] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return _extract_links_regex(html, base)

    for tag, attr in LINK_ATTRS:
        for el in soup.find_all(tag):
            val = el.get(attr)
            if val:
                links.append(urljoin(base, val))

    for form in soup.find_all("form"):
        action = form.get("action") or base
        method = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append({"name": name, "type": inp.get("type", "text")})
        forms.append({"action": urljoin(base, action), "method": method, "inputs": inputs})

    return links, forms


def crawl(base_url: str, *, depth: int = 2, max_urls: int = 200,
          timeout: int = 10, verify: bool = True,
          user_agent: str = "vulnscan/1.1") -> CrawlResult:
    result = CrawlResult()
    seen: set[str] = set()
    origin = urlparse(base_url).netloc

    q: deque[tuple[str, int]] = deque([(base_url, 0)])
    session = requests.Session()
    session.headers["User-Agent"] = user_agent

    while q and len(seen) < max_urls:
        url, d = q.popleft()
        url, _ = urldefrag(url)
        if url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != origin:
            continue

        try:
            resp = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
        except requests.RequestException:
            continue

        ctype = resp.headers.get("Content-Type", "")
        result.urls.append(url)
        if parsed.query:
            result.param_urls.append(url)

        if "text/html" not in ctype:
            continue

        links, forms = _extract_links(resp.text, url)
        result.forms.extend(forms)

        for link in links:
            lparsed = urlparse(link)
            if not lparsed.scheme.startswith("http"):
                continue
            if lparsed.netloc != origin:
                continue
            if lparsed.query and link not in result.param_urls:
                result.param_urls.append(link)
            if d < depth and link not in seen:
                q.append((link, d + 1))

    def _dedupe(seq):
        out, s = [], set()
        for x in seq:
            if x not in s:
                s.add(x)
                out.append(x)
        return out

    result.urls = _dedupe(result.urls)
    result.param_urls = _dedupe(result.param_urls)
    result.endpoints = _dedupe([urlparse(u).path for u in result.urls if urlparse(u).path])
    return result
