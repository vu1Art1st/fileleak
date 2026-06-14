"""Base dumper abstract class for FileLeak."""

import logging
from abc import ABC, abstractmethod

from fileleak.core.http import AsyncHTTPClient
from fileleak.core.utils import sanitize_path, save_file, url_to_dirname

logger = logging.getLogger(__name__)


class BaseDumper(ABC):
    """Abstract base class for all dumpers.

    Provides common download logic, path validation, and statistics tracking.
    Subclasses must implement the `start` method with their specific dump logic.
    """

    def __init__(
        self,
        url: str,
        output_dir: str | None = None,
        http_client: AsyncHTTPClient | None = None,
        **kwargs,
    ):
        # Normalize URL
        self.url = url.rstrip("/") + "/"
        # Base URL without trailing path segments (e.g. .git/)
        self.base_url = url.rstrip("/")
        self.output_dir = output_dir or url_to_dirname(url)
        self.http = http_client or AsyncHTTPClient(**kwargs)

        # Statistics
        self.downloaded_count = 0
        self.failed_count = 0
        self.skipped_count = 0

    @abstractmethod
    async def start(self):
        """Main entry point. Subclasses implement specific dump logic."""
        pass

    async def download(self, url: str, filename: str) -> bool:
        """Download a file and save it to disk.

        - Validates the file path for safety
        - Fetches the URL via the HTTP client
        - Applies data conversion (e.g. zlib decompression)
        - Skips if the file already exists (resume support)
        - Returns True on success, False on failure
        """
        # Validate path safety
        safe_path = self.validate_path(filename)
        if safe_path is None:
            logger.warning(f"Path validation failed for: {filename}")
            self.skipped_count += 1
            return False

        # Resume support: skip if file already exists
        import os
        if os.path.exists(safe_path):
            logger.debug(f"File already exists, skipping: {safe_path}")
            self.skipped_count += 1
            return True

        # Fetch the resource
        try:
            status, content = await self.http.fetch(url)

            if status != 200:
                logger.debug(f"HTTP {status} for {url}")
                self.failed_count += 1
                return False

            # Apply data conversion hook
            converted = self.convert(content)

            # Save to disk
            await save_file(safe_path, converted)
            self.downloaded_count += 1
            logger.debug(f"Downloaded: {filename}")
            return True

        except Exception as e:
            logger.warning(f"Failed to download {url}: {e}")
            self.failed_count += 1
            return False

    def convert(self, data: bytes) -> bytes:
        """Data conversion hook. Subclasses can override this
        (e.g. for Git zlib decompression)."""
        return data

    def validate_path(self, filename: str) -> str | None:
        """Validate a filename for path safety using utils.sanitize_path."""
        return sanitize_path(self.output_dir, filename)

    def get_stats(self) -> dict:
        """Return download statistics."""
        return {
            "downloaded": self.downloaded_count,
            "failed": self.failed_count,
            "skipped": self.skipped_count,
        }
