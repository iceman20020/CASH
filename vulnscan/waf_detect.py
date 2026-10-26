"""Fingerprint WAF from headers / cookies / server."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class WAFInfo:
    detected: bool
    name: str = ""
    confidence: str = "tentative"
    evidence: str = ""


SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status"], ["__cfduid", "cf_clearance"], ["cloudflare"]),
    ("Akamai", ["akamai-grn", "x-akamai-transformed"], ["ak_bmsc", "bm_sv"], ["akamai"]),
    ("AWS WAF", ["x-amzn-requestid", "x-amz-cf-id"], ["awsalb", "awsalbcors"], ["awselb"]),
    ("Imperva Incapsula", ["x-iinfo"], ["incap_ses", "visid_incap"], []),
    ("F5 BIG-IP", ["x-wa-info"], ["bigipserver", "ts", "f5_cspm"], []),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], [], []),
    ("Barracuda", ["barra_counter_session"], [], []),
    ("Fortinet FortiWeb", [], ["fortiwafsid"], []),
    ("ModSecurity", [], [], ["mod_security", "modsecurity"]),
    ("Wordfence", [], ["wfvt_", "wordfence_verifiedHuman"], []),
    ("Azure Front Door", ["x-azure-ref"], [], []),
    ("Fastly", ["x-fastly-request-id"], [], []),
    ("CloudFront", ["x-amz-cf-pop"], [], ["cloudfront"]),
]


def detect(resp) -> WAFInfo:
    h = {k.lower(): v for k, v in resp.headers.items()}
    setcookie = resp.headers.get("Set-Cookie", "").lower()
    server = h.get("server", "").lower()

    for name, hdr_sigs, cookie_sigs, srv_sigs in SIGNATURES:
        ev = []
        for s in hdr_sigs:
            if s in h:
                ev.append(f"header:{s}")
        for s in cookie_sigs:
            if s in setcookie:
                ev.append(f"cookie:{s}")
        for s in srv_sigs:
            if s in server:
                ev.append(f"server:{s}")
        if ev:
            return WAFInfo(True, name, "firm", ", ".join(ev))

    return WAFInfo(False, "", "tentative", "")
