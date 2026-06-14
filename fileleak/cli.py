"""FileLeak CLI entry point – Click + Rich powered command-line interface."""

import asyncio
import logging
import os
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from fileleak.__version__ import __version__
from fileleak.core.http import AsyncHTTPClient
from fileleak.dumpers import (
    BzrDumper,
    CvsDumper,
    DirectoryDumper,
    DsStoreDumper,
    GitDumper,
    HgDumper,
    SvnDumper,
)

console = Console()

BANNER = r"""
  _____ _ _      _                _
 |  ___(_) | ___| |    ___  __ _| | __
 | |_  | | |/ _ \ |   / _ \/ _` | |/ /
 |  _| | | |  __/ |__|  __/ (_| |   <
 |_|   |_|_|\___|_____\___|\__,_|_|\_\
"""

DUMPER_MAP = {
    "git": GitDumper,
    "svn": SvnDumper,
    "hg": HgDumper,
    "bzr": BzrDumper,
    "cvs": CvsDumper,
    "ds_store": DsStoreDumper,
    "dir": DirectoryDumper,
}


def detect_leak_type(url: str) -> str:
    """Auto-detect leak type from URL pattern."""
    url_lower = url.lower().rstrip("/")

    if "/.git" in url_lower or url_lower.endswith(".git"):
        return "git"
    elif "/.svn" in url_lower or url_lower.endswith(".svn"):
        return "svn"
    elif "/.hg" in url_lower or url_lower.endswith(".hg"):
        return "hg"
    elif "/.bzr" in url_lower or url_lower.endswith(".bzr"):
        return "bzr"
    elif "/cvs" in url_lower or url_lower.endswith("cvs"):
        return "cvs"
    elif ".ds_store" in url_lower:
        return "ds_store"
    else:
        return "dir"


@click.command()
@click.option("-u", "--url", required=True, help="Target URL")
@click.option("-o", "--output", default=None, help="Output directory")
@click.option("-t", "--threads", default=20, show_default=True, help="Concurrency level")
@click.option("--proxy", default=None, help="Proxy URL (http/socks5)")
@click.option("--full", is_flag=True, help="Full recovery mode (Git)")
@click.option("--quick", is_flag=True, help="Quick mode (default)")
@click.option("--full-copy", is_flag=True, help="Create complete .svn working copy structure (SVN)")
@click.option("--save-raw", is_flag=True, help="Save raw metadata files (.DS_Store, etc.)")
@click.option("--no-ssl-verify", is_flag=True, help="Disable SSL verification")
@click.option("-v", "--verbose", count=True, help="Verbose output (-v, -vv)")
@click.option("--resume", is_flag=True, help="Resume interrupted download")
@click.option("--timeout", default=30, show_default=True, help="Request timeout in seconds")
@click.option(
    "--type",
    "leak_type",
    default=None,
    type=click.Choice(["git", "svn", "hg", "bzr", "cvs", "ds_store", "dir"]),
    help="Force leak type",
)
@click.version_option(version=__version__)
def main(url, output, threads, proxy, full, quick, full_copy, save_raw, no_ssl_verify,
         verbose, resume, timeout, leak_type):
    """FileLeak - Comprehensive file leak exploitation tool."""
    # Display banner
    console.print(BANNER, style="bold cyan")
    console.print(f"[bold]FileLeak v{__version__}[/bold] - File Leak Exploitation Tool\n")

    # Configure logging based on verbosity
    _setup_logging(verbose)

    # Detect or use specified type
    detected_type = leak_type or detect_leak_type(url)
    console.print(f"[*] Target: [bold]{url}[/bold]")
    console.print(f"[*] Type: [bold green]{detected_type}[/bold green]")
    console.print(f"[*] Concurrency: {threads}")
    if proxy:
        console.print(f"[*] Proxy: {proxy}")
    if full:
        console.print("[*] Mode: [bold yellow]Full recovery[/bold yellow]")
    if resume:
        console.print("[*] Resume: [bold yellow]Enabled[/bold yellow]")
    console.print()

    # Set Windows event loop policy for better asyncio compatibility
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # Run async main
    try:
        asyncio.run(
            async_main(
                url=url,
                output=output,
                threads=threads,
                proxy=proxy,
                full=full,
                full_copy=full_copy,
                save_raw=save_raw,
                no_ssl_verify=no_ssl_verify,
                verbose=verbose,
                resume=resume,
                timeout=timeout,
                leak_type=detected_type,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[bold red][!] Error: {exc}[/bold red]")
        if verbose >= 2:
            console.print_exception()
        sys.exit(1)


async def async_main(url, output, threads, proxy, no_ssl_verify,
                     verbose, resume, timeout, leak_type, full=False, full_copy=False, save_raw=False):
    """Async entry point."""
    # Create HTTP client
    http_client = AsyncHTTPClient(
        concurrency=threads,
        proxy=proxy,
        timeout=timeout,
        ssl_verify=not no_ssl_verify,
        retries=3,
        random_ua=True,
    )

    try:
        await http_client.init_session()

        # Detect fake 404 using the site root (not the .hg/.svn subpath)
        # to avoid probing inside version-control directories
        from urllib.parse import urlparse
        parsed = urlparse(url)
        site_root = f"{parsed.scheme}://{parsed.netloc}/"
        console.print("[*] Detecting server behavior...")
        await http_client.detect_fake_404(site_root)

        # Build default output path: output/{leak_type}/{dirname}
        if output is None:
            from fileleak.core.utils import url_to_dirname
            dirname = url_to_dirname(url)
            output = os.path.join("output", leak_type, dirname)

        # Build dumper kwargs (common args passed to BaseDumper)
        kwargs = {
            "output_dir": output,
            "http_client": http_client,
            "resume": resume,
        }

        # Create appropriate dumper
        dumper_cls = DUMPER_MAP[leak_type]

        if leak_type == "git":
            dumper = dumper_cls(url, full_mode=full, **kwargs)
        elif leak_type == "svn":
            dumper = dumper_cls(url, full_copy=full_copy, **kwargs)
        elif leak_type == "ds_store":
            dumper = dumper_cls(url, save_raw=save_raw, **kwargs)
        elif leak_type == "dir":
            dumper = dumper_cls(url, max_depth=10, **kwargs)
        else:
            dumper = dumper_cls(url, **kwargs)

        # Run
        console.print(f"[bold green][+] Starting {leak_type} dump...[/bold green]\n")
        await dumper.start()

        # Print stats
        stats = dumper.get_stats()
        _print_summary(stats, dumper.output_dir)

    except Exception as exc:
        console.print(f"\n[bold red][!] Dump failed: {exc}[/bold red]")
        if verbose >= 2:
            console.print_exception()
        raise
    finally:
        await http_client.close()


def _print_summary(stats: dict, output_dir: str):
    """Print final summary table."""
    table = Table(title="Dump Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Downloaded", str(stats.get("downloaded", 0)))
    table.add_row("Failed", str(stats.get("failed", 0)))
    table.add_row("Skipped", str(stats.get("skipped", 0)))
    table.add_row("Output Dir", str(output_dir))

    console.print()
    console.print(table)
    console.print("\n[bold green][+] Done![/bold green]")


def _setup_logging(verbose: int):
    """Configure logging level based on verbosity flag."""
    if verbose >= 2:
        level = logging.DEBUG
    elif verbose >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


if __name__ == "__main__":
    main()
