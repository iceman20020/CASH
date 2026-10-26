"""Curated CVE + EOL database keyed by (product_substring, version_prefix)."""

from __future__ import annotations

from typing import Optional


CVE_DB: list[tuple[str, Optional[str], str, str, float]] = [
    ("openssh", "7.4", "CVE-2018-15473", "OpenSSH username enumeration", 5.3),
    ("openssh", "5.3", "CVE-2016-0777", "OpenSSH roaming client memory disclosure", 7.5),
    ("openssh", "8.5", "CVE-2021-41617", "OpenSSH privilege escalation (AuthorizedKeysCommand)", 7.0),
    ("openssh", "8.9", "CVE-2023-38408", "OpenSSH agent forwarding RCE", 9.8),
    ("apache httpd", "2.4.49", "CVE-2021-41773", "Apache path traversal / RCE", 9.8),
    ("apache httpd", "2.4.50", "CVE-2021-42013", "Apache path traversal / RCE", 9.8),
    ("apache httpd", "2.4.48", "CVE-2021-40438", "Apache mod_proxy SSRF", 9.0),
    ("apache httpd", "2.4.51", "CVE-2021-44790", "Apache mod_lua buffer overflow", 9.8),
    ("nginx", "1.16", "CVE-2019-20372", "nginx HTTP request smuggling", 5.3),
    ("vsftpd", "2.3.4", "CVE-2011-2523", "vsftpd backdoor command execution", 10.0),
    ("proftpd", "1.3.5", "CVE-2015-3306", "ProFTPD mod_copy unauthenticated RCE", 9.8),
    ("samba", "3.5", "CVE-2017-7494", "SambaCry remote code execution", 9.8),
    ("samba", "3.6", "CVE-2017-7494", "SambaCry remote code execution", 9.8),
    ("microsoft iis", "6.0", "CVE-2017-7269", "IIS 6.0 WebDAV remote code execution", 9.8),
    ("exim", "4.87", "CVE-2017-16943", "Exim use-after-free RCE", 9.8),
    ("exim", "4.88", "CVE-2017-16943", "Exim use-after-free RCE", 9.8),
    ("exim", "4.89", "CVE-2017-16943", "Exim use-after-free RCE", 9.8),
    ("struts", None, "CVE-2017-5638", "Apache Struts2 Jakarta multipart RCE", 10.0),
    ("log4j", None, "CVE-2021-44228", "Log4Shell RCE", 10.0),
    ("citrix", None, "CVE-2019-19781", "Citrix ADC directory traversal RCE", 9.8),
    ("fortinet", "6.0", "CVE-2018-13379", "FortiOS SSL-VPN path traversal", 9.8),
    ("pulse secure", "8.1", "CVE-2019-11510", "Pulse Secure arbitrary file read", 10.0),
    ("exchange", None, "CVE-2021-26855", "Exchange ProxyLogon SSRF", 9.8),
    ("jenkins", None, "CVE-2024-23897", "Jenkins arbitrary file read (CLI)", 9.8),
    ("drupal", "7.", "CVE-2014-3704", "Drupal SQL injection", 9.8),
    ("wordpress", "4.7", "CVE-2017-1001000", "WordPress REST API content injection", 7.5),
    ("tomcat", "7.", "CVE-2020-1938", "Apache Tomcat AJP Ghostcat file read/RCE", 9.8),
    ("tomcat", "8.", "CVE-2020-1938", "Apache Tomcat AJP Ghostcat file read/RCE", 9.8),
    ("tomcat", "9.", "CVE-2020-1938", "Apache Tomcat AJP Ghostcat file read/RCE", 9.8),
]

EOL_DB: list[tuple[str, str, str]] = [
    ("php", "5.", "PHP 5.x reached end-of-life 2018-12-31"),
    ("php", "7.0", "PHP 7.0 reached end-of-life 2019-01-01"),
    ("php", "7.1", "PHP 7.1 reached end-of-life 2019-12-01"),
    ("php", "7.2", "PHP 7.2 reached end-of-life 2020-11-30"),
    ("php", "7.3", "PHP 7.3 reached end-of-life 2021-12-06"),
    ("php", "7.4", "PHP 7.4 reached end-of-life 2022-11-28"),
    ("python", "2.", "Python 2 reached end-of-life 2020-01-01"),
    ("openssl", "1.0.1", "OpenSSL 1.0.1 is end-of-life"),
    ("openssl", "1.0.2", "OpenSSL 1.0.2 is end-of-life"),
    ("apache httpd", "2.2", "Apache httpd 2.2 is end-of-life"),
    ("microsoft iis", "6.0", "IIS 6.0 ships on Windows Server 2003 (end-of-life)"),
    ("microsoft iis", "7.0", "IIS 7.0 ships on Windows Server 2008 (end-of-life)"),
    ("nginx", "1.12", "nginx 1.12 is legacy"),
]


def lookup_cves(product: str, version: str) -> list[dict]:
    if not product:
        return []
    prod = product.lower().strip()
    ver = (version or "").lower().strip()
    out = []
    for db_prod, db_ver, cve, title, cvss in CVE_DB:
        if db_prod in prod:
            if db_ver is None or ver.startswith(db_ver):
                out.append({"cve": cve, "title": title, "cvss": cvss})
    return out


def lookup_eol(product: str, version: str) -> Optional[str]:
    if not product:
        return None
    prod = product.lower()
    ver = (version or "").lower()
    for db_prod, db_ver, note in EOL_DB:
        if db_prod in prod and ver.startswith(db_ver):
            return note
    return None
