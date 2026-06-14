"""Directory listing (Index of) crawler and downloader.

Crawls web servers with directory listing enabled, extracting
all file links and downloading them. Supports depth limiting,
same-domain filtering, and concurrent task execution.
"""

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse

from fileleak.core.base import BaseDumper

logger = logging.getLogger(__name__)

# Regex to extract href values from <a> tags
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

# Indicators that a page is a directory listing
_DIR_LISTING_INDICATORS = (
    "index of",
    "parent directory",
    "[dir]",
    "directory listing",
)


class DirectoryDumper(BaseDumper):
    """Directory listing (Index of) crawler and downloader.

    Crawls web servers that expose directory listings, recursively
    following subdirectory links and downloading all discovered files.
    Uses BFS traversal with configurable depth limit and same-domain
    filtering to prevent crawling external sites.
    """

    def __init__(self, url: str, max_depth: int = 10, **kwargs):
        super().__init__(url, **kwargs)
        self.base_url = url.rstrip("/")
        self.max_depth = max_depth
        self.visited: set[str] = set()
        self.base_domain = urlparse(url).netloc

    async def start(self):
        """Crawl directory listing and download all files."""
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((self.base_url, 0))

        # Use a task pool for concurrent processing
        tasks: list[asyncio.Task] = []

        while not queue.empty() or tasks:
            # Drain the queue and create tasks
            while not queue.empty():
                url, depth = await queue.get()
                if url in self.visited or depth > self.max_depth:
                    continue
                self.visited.add(url)
                tasks.append(
                    asyncio.create_task(self._process_page(url, depth, queue))
                )

            # Wait for at least one task to complete
            if tasks:
                done, pending = await asyncio.wait(tasks, timeout=1.0)
                tasks = list(pending)

        logger.info(
            f"Directory listing dump complete: "
            f"{self.downloaded_count} downloaded, "
            f"{self.failed_count} failed, "
            f"{self.skipped_count} skipped"
        )

    async def _process_page(
        self, url: str, depth: int, queue: asyncio.Queue[tuple[str, int]]
    ):
        """Fetch a URL, classify it, and either download or crawl it.

        - If the response is a directory listing, extract and queue links
        - If it's a regular file, download it
        """
        try:
            status, data = await self.http.fetch(url)
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return

        if status != 200 or not data:
            return

        # Check if this is an HTML directory listing page
        if self._is_directory_listing(data):
            logger.info(f"Crawling directory listing: {url}")
            links = self._extract_links(data, url)
            for link in links:
                if link in self.visited or not self._is_same_domain(link):
                    continue
                if link.endswith("/"):
                    # Subdirectory — queue for further crawling
                    await queue.put((link, depth + 1))
                else:
                    # Regular file — download directly
                    self.visited.add(link)
                    rel_path = self._url_to_relpath(link)
                    try:
                        await self.download(link, rel_path)
                    except Exception as e:
                        logger.warning(f"Failed to download {link}: {e}")
        else:
            # It's a regular file, download it
            rel_path = self._url_to_relpath(url)
            try:
                await self.download(url, rel_path)
            except Exception as e:
                logger.warning(f"Failed to download {url}: {e}")

    @staticmethod
    def _is_directory_listing(data: bytes) -> bool:
        """Check if the response is an HTML directory listing page.

        Looks for common indicators like "Index of", "Parent Directory",
        "[dir]", or "Directory Listing" in the first 2048 bytes.
        Also checks for <pre> tag which is commonly used in Apache
        directory listings.
        """
        try:
            text = data[:2048].decode("utf-8", errors="ignore").lower()
        except Exception:
            return False

        # Check for known directory listing indicators
        for indicator in _DIR_LISTING_INDICATORS:
            if indicator in text:
                return True

        # Heuristic: <pre> tag with <a href> links suggests directory listing
        if "<pre>" in text and '<a href' in text:
            return True

        return False

    @staticmethod
    def _extract_links(data: bytes, base_url: str) -> list[str]:
        """Extract href links from an HTML directory listing page.

        Uses regex to find all <a href="..."> tags, resolves relative
        URLs, and filters out parent directory links, anchors, and
        query strings.
        """
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return []

        hrefs = _HREF_RE.findall(text)
        links: list[str] = []

        for href in hrefs:
            # Skip parent directory, anchors, query params, and empty
            if href in ("..", "../", "/", "#") or href.startswith("?") or href.startswith("#"):
                continue
            # Skip mailto: and javascript: links
            if ":" in href.split("/")[0] and not href.startswith(("http://", "https://")):
                continue

            # Resolve relative URLs to absolute
            full_url = urljoin(base_url + "/", href)

            links.append(full_url)

        return links

    def _is_same_domain(self, url: str) -> bool:
        """Check if a URL belongs to the same domain as the target."""
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False

    @staticmethod
    def _url_to_relpath(url: str) -> str:
        """Convert a URL to a relative file path for saving.

        Removes scheme and domain, strips leading slashes.
        Paths ending with '/' get 'index.html' appended.
        """
        parsed = urlparse(url)
        path = parsed.path.lstrip("/")
        if not path or path.endswith("/"):
            path += "index.html"
        return path
