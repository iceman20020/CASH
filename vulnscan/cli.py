from __future__ import annotations

import argparse
import sys

from rich.console import Console

from vulnscan import __version__
from vulnscan.banner import render_splash, render_splash_panel
from vulnscan.config import Config, DEFAULT_OUT
from vulnscan.models import Severity
from vulnscan.orchestrator import run_scan
from vulnscan.report import write_all, print_summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="Aggregated web + network vulnerability scanner.",
    )
    p.add_argument("target", nargs="?", help="host, URL, IP, or CIDR")
    p.add_argument("--out", default=DEFAULT_OUT, help=f"output dir (default: {DEFAULT_OUT})")
    p.add_argument("--skip", default="", help="comma-separated tools to skip "
                   "(curl,dns,tls,files,subdomains,nmap,nikto,sqlmap,openvas)")
    p.add_argument("--only", default="", help="comma-separated tools to run exclusively")
    p.add_argument("--timeout", type=int, default=300, help="per-tool timeout seconds")
    p.add_argument("--threads", type=int, default=16, help="parallel probes")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification during probes")
    p.add_argument("--aggressive", action="store_true", help="higher sqlmap level/risk, nmap OS")
    p.add_argument("--no-crawl", action="store_true", help="disable crawler")
    p.add_argument("--crawl-depth", type=int, default=2)
    p.add_argument("--crawl-max", type=int, default=200)
    p.add_argument("--subdomain-brute", action="store_true", help="brute-force subdomains")
    p.add_argument("--gvm-socket", default=None)
    p.add_argument("--gvm-user", default=None)
    p.add_argument("--gvm-pass", default=None)
    p.add_argument("--openvas-report", default=None)
    p.add_argument("--formats", default="json,md,html,txt", help="report formats")
    p.add_argument("--fail-on", default=None,
                   choices=["low", "medium", "high", "critical"],
                   help="exit non-zero if any finding meets this severity")
    p.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--version", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    console = Console()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        console.print(f"vulnscan [bold cyan]{__version__}[/]")
        return 0

    if not args.target:
        render_splash(console)
        parser.print_help()
        return 2

    if not args.no_banner:
        if args.verbose:
            render_splash_panel(console, target=args.target)
        else:
            render_splash(console, target=args.target)

    cfg = Config(
        target=args.target,
        out_dir=args.out,
        timeout=args.timeout,
        threads=args.threads,
        insecure=args.insecure,
        verbose=args.verbose,
        aggressive=args.aggressive,
        crawl=not args.no_crawl,
        crawl_depth=args.crawl_depth,
        crawl_max=args.crawl_max,
        subdomain_brute=args.subdomain_brute,
        gvm_socket=args.gvm_socket,
        gvm_user=args.gvm_user,
        gvm_pass=args.gvm_pass,
        openvas_report=args.openvas_report,
        fail_on=args.fail_on,
        report_formats=[f.strip() for f in args.formats.split(",") if f.strip()],
    )
    if args.skip:
        cfg.skip_tools = {s.strip() for s in args.skip.split(",") if s.strip()}
    if args.only:
        cfg.only_tools = {s.strip() for s in args.only.split(",") if s.strip()}

    result = run_scan(args.target, cfg)

    print_summary(console, result)
    out_path = write_all(result, cfg.out_dir, cfg.report_formats)
    console.print(f"\n[dim]reports written to[/] [bold cyan]{out_path}[/]")

    if cfg.fail_on:
        threshold = Severity(cfg.fail_on)
        if result.highest().rank >= threshold.rank:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
