from __future__ import annotations

from dataclasses import dataclass, field


DEFAULT_OUT = "./vulnscan-out"


@dataclass
class Config:
    target: str = ""
    out_dir: str = DEFAULT_OUT
    scheme: str = "https"
    timeout: int = 300
    threads: int = 16
    insecure: bool = False
    user_agent: str = "vulnscan/1.1 (+recon)"
    verbose: bool = False

    skip_tools: set[str] = field(default_factory=set)
    only_tools: set[str] = field(default_factory=set)

    crawl: bool = True
    crawl_depth: int = 2
    crawl_max: int = 200

    subdomain_enum: bool = True
    subdomain_brute: bool = False

    aggressive: bool = False

    gvm_socket: str | None = None
    gvm_user: str | None = None
    gvm_pass: str | None = None
    openvas_report: str | None = None

    report_formats: list[str] = field(default_factory=lambda: ["json", "md", "html", "txt"])

    fail_on: str | None = None

    def enabled(self, tool: str) -> bool:
        if self.only_tools:
            return tool in self.only_tools
        return tool not in self.skip_tools
