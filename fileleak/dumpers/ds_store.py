"""macOS .DS_Store file leak dumper.

Recursively discovers and downloads files by parsing .DS_Store files
exposed on web servers. .DS_Store files are macOS Finder metadata
that contain directory listing information.
"""

import asyncio
import logging
import struct
from urllib.parse import urlparse

from fileleak.core.base import BaseDumper

logger = logging.getLogger(__name__)

# Known DS_Store structure types that follow filename entries
_DS_STORE_STRUCT_TYPES = frozenset({
    b"Iloc", b"bwsp", b"vSrn", b"BKGD", b"icvp", b"lsvp", b"lsvP",
    b"icvo", b"dscl", b"fwi0", b"fwsw", b"fwvh", b"glvp", b"GRP0",
    b"icgo", b"icsp", b"lg1S", b"logS", b"lssp", b"lsSP", b"modD",
    b"moDD", b"pBB0", b"pBBk", b"phyS", b"ph1S", b"pict", b"vstl",
    b"dilc", b"lsvo", b"icvt", b"ptbL", b"ptbN", b"extn", b"clip",
    b"bool", b"type", b"long", b"shor", b"comp", b"dutc", b"lsvt",
    b"blob", b"ustr", b"cmmt", b"ICVO", b"LSVO", b"info",
})


def parse_ds_store(data: bytes) -> set[str]:
    """Parse .DS_Store binary data and extract filenames.

    DS_Store records contain filename entries encoded as:
    - 4 bytes: filename length (big-endian uint32, number of UTF-16 chars)
    - N*2 bytes: filename in UTF-16BE
    - 4 bytes: structure ID
    - 4 bytes: structure type (e.g., 'Iloc', 'bwsp', 'vSrn')

    This function scans through the binary data looking for valid
    filename + structure type patterns.
    """
    filenames: set[str] = set()
    data_len = len(data)
    if data_len < 8:
        return filenames

    offset = 0
    while offset < data_len - 12:
        try:
            str_len = struct.unpack_from(">I", data, offset)[0]
        except struct.error:
            offset += 1
            continue

        # Reasonable filename length: 1-256 UTF-16 characters
        if str_len < 1 or str_len > 256:
            offset += 1
            continue

        name_start = offset + 4
        name_end = name_start + str_len * 2
        struct_type_end = name_end + 8  # 4 bytes struct ID + 4 bytes struct type

        # Ensure we have enough data
        if name_end > data_len or struct_type_end > data_len:
            offset += 1
            continue

        # Decode the filename
        try:
            name_bytes = data[name_start:name_end]
            name = name_bytes.decode("utf-16-be")
        except (UnicodeDecodeError, ValueError):
            offset += 1
            continue

        # Validate: must be printable, no null bytes, non-empty
        if not name or "\x00" in name or not name.isprintable():
            offset += 1
            continue

        # Check that after the name there's a known structure type
        # Skip 4 bytes of structure ID, then read 4 bytes of structure type
        struct_type = data[name_end + 4 : struct_type_end]
        if struct_type not in _DS_STORE_STRUCT_TYPES:
            offset += 1
            continue

        filenames.add(name)
        # Jump past this record for efficiency (4 + str_len*2 + 4 + 4)
        offset = name_end + 8

    return filenames


class DsStoreDumper(BaseDumper):
    """macOS .DS_Store file leak exploiter.

    Recursively discovers files by fetching .DS_Store files from
    directories, parsing filenames from them, then downloading
    discovered files and probing subdirectories for their own
    .DS_Store files.
    
    Can optionally save the raw .DS_Store files for later analysis.
    """

    def __init__(self, url: str, save_raw: bool = False, **kwargs):
        """Initialize DS_Store dumper.
        
        Args:
            url: Target URL
            save_raw: If True, also save raw .DS_Store files
        """
        super().__init__(url, **kwargs)
        self.base_url = self._normalize_url(url)
        self.discovered_urls: set[str] = set()
        self.processed_urls: set[str] = set()
        self.save_raw = save_raw

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL to a base directory path.

        Strips trailing /.DS_Store if present, removes trailing slash.
        """
        cleaned = url.rstrip("/")
        if cleaned.endswith("/.DS_Store"):
            cleaned = cleaned[: -len("/.DS_Store")]
        return cleaned

    async def start(self):
        """Recursively discover and download files via .DS_Store parsing."""
        queue: asyncio.Queue[str] = asyncio.Queue()
        await queue.put(self.base_url)

        while not queue.empty():
            url = await queue.get()
            if url in self.processed_urls:
                continue
            self.processed_urls.add(url)

            # Fetch .DS_Store at this path
            ds_url = url.rstrip("/") + "/.DS_Store"
            try:
                status, data = await self.http.fetch(ds_url)
            except Exception as e:
                logger.warning(f"Failed to fetch {ds_url}: {e}")
                continue

            if status != 200 or not data or not self._is_ds_store(data):
                continue

            # Optionally save raw .DS_Store file
            if self.save_raw:
                ds_rel_path = self._url_to_relpath(ds_url)
                try:
                    await self.download(ds_url, ds_rel_path)
                except Exception as e:
                    logger.warning(f"Failed to save raw .DS_Store {ds_url}: {e}")

            # Parse filenames from .DS_Store
            filenames = parse_ds_store(data)
            if not filenames:
                continue

            base = url.rstrip("/")
            logger.info(f"Found {len(filenames)} entries in {ds_url}")

            for name in filenames:
                file_url = f"{base}/{name}"
                if file_url in self.discovered_urls:
                    continue
                self.discovered_urls.add(file_url)

                # Download the file
                rel_path = self._url_to_relpath(file_url)
                try:
                    await self.download(file_url, rel_path)
                except Exception as e:
                    logger.warning(f"Failed to download {file_url}: {e}")

                # Also probe subdirectories for their .DS_Store
                await queue.put(file_url)

        logger.info(
            f"DS_Store dump complete: "
            f"{self.downloaded_count} downloaded, "
            f"{self.failed_count} failed, "
            f"{self.skipped_count} skipped"
        )

    @staticmethod
    def _is_ds_store(data: bytes) -> bool:
        """Check if data looks like a valid .DS_Store file.

        DS_Store files start with magic bytes: 0x00000001 followed by 'Bud1'.
        The magic appears within the first 36 bytes of the file.
        """
        if len(data) < 8:
            return False
        return b"Bud1" in data[:36]

    @staticmethod
    def _url_to_relpath(url: str) -> str:
        """Convert a URL to a relative file path for saving.

        Removes the scheme and domain, strips leading slashes,
        and ensures non-empty paths end with a meaningful name.
        """
        parsed = urlparse(url)
        path = parsed.path.lstrip("/")
        if not path:
            path = "index.html"
        return path
