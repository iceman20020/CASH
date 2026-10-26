"""Parallel probe for commonly leaked files, endpoints, panels."""

from __future__ import annotations

import concurrent.futures as cf

import requests

from vulnscan.config import Config
from vulnscan.models import Confidence, Finding, Severity
from vulnscan.runners.base import Runner
from vulnscan.target import Target


TARGETS = [
    # secrets / source
    ("/.git/HEAD", "Exposed .git directory", "critical",
     "Source code may be fully recoverable.", "exposed_secret"),
    ("/.git/config", "Exposed .git/config", "high",
     "Git config may include remotes and credential helpers.", "exposed_secret"),
    ("/.svn/entries", "Exposed .svn directory", "high",
     "Subversion metadata leak.", "exposed_secret"),
    ("/.hg/requires", "Exposed .hg directory", "high",
     "Mercurial metadata leak.", "exposed_secret"),
    ("/.env", "Exposed .env file", "critical",
     "Environment file commonly contains DB creds, API keys.", "exposed_creds"),
    ("/.env.local", "Exposed .env.local", "critical",
     "Local env override file exposed.", "exposed_creds"),
    ("/.env.production", "Exposed .env.production", "critical",
     "Production env file exposed.", "exposed_creds"),
    ("/.env.backup", "Exposed .env.backup", "critical",
     "Backup env file exposed.", "exposed_creds"),
    ("/.aws/credentials", "Exposed AWS credentials file", "critical",
     "AWS access keys may be present.", "exposed_secret"),
    ("/credentials.json", "Exposed credentials.json", "critical",
     "Google Cloud service account key likely.", "exposed_secret"),
    ("/service-account.json", "Exposed GCP service account key", "critical",
     "GCP key — grants cloud access.", "exposed_secret"),
    ("/id_rsa", "Exposed private SSH key", "critical",
     "RSA private key leaked.", "exposed_secret"),
    ("/server.key", "Exposed TLS private key", "critical",
     "TLS key exposure enables decryption/MITM.", "exposed_secret"),
    ("/private.key", "Exposed private key", "critical",
     "Private key exposure.", "exposed_secret"),

    # config
    ("/web.config", "Exposed web.config", "high",
     "IIS config with app settings / creds.", "exposed_config"),
    ("/wp-config.php.bak", "WordPress config backup", "critical",
     "DB credentials for WordPress.", "exposed_creds"),
    ("/config.php.bak", "Config backup", "high",
     "App config backup leaked.", "exposed_config"),
    ("/config.json", "Exposed config.json", "medium",
     "App config may include secrets.", "exposed_config"),
    ("/composer.json", "Composer manifest exposed", "low",
     "Dependency list leak.", "info_disclosure"),
    ("/package.json", "package.json exposed", "low",
     "Dependency list leak.", "info_disclosure"),
    ("/Dockerfile", "Dockerfile exposed", "low",
     "Build context leak.", "info_disclosure"),
    ("/docker-compose.yml", "docker-compose.yml exposed", "medium",
     "Compose file may include creds and internal topology.", "exposed_config"),

    # backups
    ("/backup.sql", "Database backup exposed", "critical",
     "Full SQL dump available.", "exposed_secret"),
    ("/db.sql", "Database dump exposed", "critical",
     "SQL dump available.", "exposed_secret"),
    ("/dump.sql", "Database dump exposed", "critical",
     "SQL dump available.", "exposed_secret"),
    ("/backup.zip", "Archive backup exposed", "high",
     "ZIP archive contains source or data.", "exposed_secret"),
    ("/backup.tar.gz", "Archive backup exposed", "high",
     "Tarball contains source or data.", "exposed_secret"),

    # debug / admin / metrics
    ("/phpinfo.php", "phpinfo() exposed", "medium",
     "Full PHP config, env vars, paths disclosed.", "info_disclosure"),
    ("/server-status", "Apache server-status exposed", "medium",
     "Active requests, client IPs, URLs exposed.", "debug_exposed"),
    ("/actuator", "Spring Boot Actuator exposed", "medium",
     "Actuator root — enumerate child endpoints.", "debug_exposed"),
    ("/actuator/env", "Spring Actuator /env exposed", "high",
     "Environment variables (incl. secrets) exposed.", "exposed_secret"),
    ("/actuator/health", "Spring Actuator /health exposed", "info",
     "Health details may reveal downstream services.", "debug_exposed"),
    ("/metrics", "Metrics endpoint exposed", "low",
     "Application metrics leaked.", "info_disclosure"),
    ("/debug", "Debug endpoint exposed", "medium",
     "Debug console reachable.", "debug_exposed"),
    ("/console", "Debug console exposed", "high",
     "Interactive console reachable.", "debug_exposed"),
    ("/elmah.axd", "ELMAH log exposed (.NET)", "high",
     "Error log with stack traces and data.", "debug_exposed"),
    ("/trace.axd", "ASP.NET trace exposed", "high",
     "Request trace data exposed.", "debug_exposed"),

    # API docs
    ("/swagger.json", "Swagger spec exposed", "low",
     "API surface disclosed.", "swagger_exposed"),
    ("/openapi.json", "OpenAPI spec exposed", "low",
     "API surface disclosed.", "swagger_exposed"),
    ("/swagger-ui/", "Swagger UI exposed", "low",
     "Interactive API docs exposed.", "swagger_exposed"),
    ("/api-docs", "API docs exposed", "low",
     "API documentation reachable.", "swagger_exposed"),
    ("/graphql", "GraphQL endpoint discovered", "info",
     "GraphQL endpoint — test introspection.", "graphql_introspection"),

    # admin panels
    ("/admin/", "Admin panel reachable", "medium",
     "Administrative UI exposed.", "admin_panel"),
    ("/administrator/", "Joomla admin reachable", "medium",
     "Joomla admin.", "admin_panel"),
    ("/wp-admin/", "WordPress admin reachable", "info",
     "WP admin login.", "admin_panel"),
    ("/wp-login.php", "WordPress login reachable", "info",
     "WP login.", "admin_panel"),
    ("/manager/html", "Tomcat manager reachable", "high",
     "Tomcat manager — default creds often present.", "admin_panel"),
    ("/jenkins/", "Jenkins reachable", "high",
     "Jenkins often unauthenticated.", "admin_panel"),
    ("/phpmyadmin/", "phpMyAdmin reachable", "medium",
     "DB UI exposed.", "admin_panel"),
    ("/adminer.php", "Adminer reachable", "medium",
     "DB UI exposed.", "admin_panel"),

    # misc leaks
    ("/.DS_Store", ".DS_Store exposed", "low",
     "macOS metadata — file names leak.", "info_disclosure"),
    ("/robots.txt", "robots.txt present", "info",
     "Review for hidden paths.", "info_disclosure"),
    ("/sitemap.xml", "sitemap.xml present", "info",
     "URL inventory.", "info_disclosure"),
    ("/crossdomain.xml", "crossdomain.xml present", "low",
     "Permissive Flash cross-domain policy possible.", "misconfig"),
    ("/.well-known/security.txt", "security.txt present", "info",
     "Responsible disclosure contact.", "info_disclosure"),
]


# file-like paths where an HTML response means SPA catchall, not a real leak
_BINARY_PATHS = (".env", ".git/HEAD", ".git/config", ".svn/entries",
                 ".hg/requires", ".aws/credentials", "credentials.json",
                 "service-account.json", "id_rsa", "server.key", "private.key",
                 ".sql", ".zip", ".tar.gz", ".bak", ".axd", "wp-config.php.bak",
                 "config.php.bak", "composer.json", "Dockerfile", "docker-compose.yml")


class ExposedFilesRunner(Runner):
    name = "files"
    binary = None

    def run(self, target: Target, cfg: Config, context: dict) -> list[Finding]:
        if target.is_cidr:
            return []

        findings: list[Finding] = []
        session = requests.Session()
        session.headers["User-Agent"] = cfg.user_agent

        def probe(item) -> Finding | None:
            path, title, sev, desc, cat = item
            url = target.url_for(path)
            try:
                r = session.get(url, timeout=6, verify=not cfg.insecure, allow_redirects=False)
            except requests.RequestException:
                return None
            if r.status_code not in (200, 206):
                return None

            ct = r.headers.get("Content-Type", "").lower()
            body_snippet = (r.text or "")[:500].lower()

            # reject SPA catchall: HTML response for file-like path
            if any(m in path for m in _BINARY_PATHS) and "text/html" in ct:
                if "<html" in body_snippet or "<!doctype" in body_snippet:
                    return None

            # reject obvious soft-404s
            if r.status_code == 200 and "<title>404" in body_snippet:
                return None

            return Finding(
                tool=self.name, title=title, description=desc,
                severity=Severity(sev), confidence=Confidence.CERTAIN,
                url=url, host=target.host, port=target.port,
                category=cat, cwe="CWE-538",
                evidence=f"HTTP {r.status_code} len={len(r.content)} ct={ct}",
            )

        with cf.ThreadPoolExecutor(max_workers=cfg.threads) as ex:
            for result in ex.map(probe, TARGETS):
                if result:
                    findings.append(result)
        return findings
