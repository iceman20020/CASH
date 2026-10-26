"""Fingerprint server stack, framework, CMS from a probe response."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class TechProfile:
    server: str = ""
    powered_by: str = ""
    language: str = ""
    framework: str = ""
    cms: str = ""
    cdn: str = ""
    cookies: list[str] = field(default_factory=list)
    meta_generator: str = ""
    headers: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "powered_by": self.powered_by,
            "language": self.language,
            "framework": self.framework,
            "cms": self.cms,
            "cdn": self.cdn,
            "cookies": self.cookies,
            "meta_generator": self.meta_generator,
        }


COOKIE_SIGNATURES = {
    "PHPSESSID": ("language", "PHP"),
    "JSESSIONID": ("language", "Java"),
    "ASP.NET_SessionId": ("language", "ASP.NET"),
    "laravel_session": ("framework", "Laravel"),
    "ci_session": ("framework", "CodeIgniter"),
    "symfony": ("framework", "Symfony"),
    "_rails_session": ("framework", "Ruby on Rails"),
    "django_session": ("framework", "Django"),
    "wp-settings": ("cms", "WordPress"),
    "wordpress_": ("cms", "WordPress"),
}


def fingerprint(resp) -> TechProfile:
    prof = TechProfile()
    h = {k.lower(): v for k, v in resp.headers.items()}
    prof.headers = dict(resp.headers)
    prof.server = h.get("server", "")
    prof.powered_by = h.get("x-powered-by", "")

    srv = prof.server.lower()
    if "cloudflare" in srv:
        prof.cdn = "Cloudflare"
    elif "akamai" in srv or "akamaighost" in srv:
        prof.cdn = "Akamai"
    elif "amazons3" in srv or "cloudfront" in h.get("via", "").lower():
        prof.cdn = "AWS"

    setcookie = resp.headers.get("Set-Cookie", "")
    for sig, (field_name, value) in COOKIE_SIGNATURES.items():
        if sig in setcookie:
            setattr(prof, field_name, value)
            prof.cookies.append(sig)

    body = (resp.text or "")[:20000]

    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        prof.meta_generator = m.group(1)
        mg = prof.meta_generator.lower()
        for cms, key in (("wordpress", "WordPress"), ("drupal", "Drupal"),
                         ("joomla", "Joomla"), ("hugo", "Hugo"), ("jekyll", "Jekyll")):
            if cms in mg:
                prof.cms = prof.cms or key
                break

    if not prof.cms:
        if "wp-content" in body or "wp-includes" in body:
            prof.cms = "WordPress"
        elif "/sites/default/files" in body or "drupal" in body.lower()[:3000]:
            prof.cms = "Drupal"
        elif "joomla" in body.lower()[:3000]:
            prof.cms = "Joomla"

    if not prof.framework:
        if "__next_data__" in body or "_next/static" in body:
            prof.framework = "Next.js"
        elif 'id="root"' in body and "react" in body.lower()[:4000]:
            prof.framework = "React"
        elif "_nuxt/" in body:
            prof.framework = "Nuxt"
        elif "ng-version" in body:
            prof.framework = "Angular"
        elif 'id="app"' in body and "vue" in body.lower()[:4000]:
            prof.framework = "Vue"

    if not prof.language and prof.powered_by:
        pb = prof.powered_by.lower()
        if "php" in pb:
            prof.language = "PHP"
        elif "asp.net" in pb:
            prof.language = "ASP.NET"
        elif "express" in pb:
            prof.language = "Node.js/Express"

    return prof
