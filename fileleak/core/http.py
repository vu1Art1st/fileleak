"""Asynchronous HTTP client with smart 404 detection and retry logic."""

import asyncio
import logging
import os
import random
from pathlib import Path

import aiohttp
from aiohttp_socks import ProxyConnector

from fileleak.core.utils import random_string

logger = logging.getLogger(__name__)


class AsyncHTTPClient:
    """Async HTTP client with concurrency control, proxy support,
    random User-Agent rotation, and smart fake-404 detection."""

    def __init__(
        self,
        concurrency: int = 20,
        proxy: str | None = None,
        timeout: int = 30,
        ssl_verify: bool = True,
        retries: int = 3,
        random_ua: bool = True,
    ):
        self.concurrency = concurrency
        self.proxy = proxy
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self.retries = retries
        self.random_ua = random_ua

        self.session: aiohttp.ClientSession | None = None
        self._semaphore: asyncio.Semaphore | None = None

        # Fake 404 detection state
        self._fake_404_signature: bytes | None = None
        self._fake_404_detected: bool = False
        self._fake_404_size: int = 0

        # User-Agent pool
        self._user_agents: list[str] = []
        self._load_user_agents()

    def _load_user_agents(self):
        """Load User-Agent strings from the data file."""
        ua_path = Path(__file__).parent.parent / "data" / "user_agents.txt"
        try:
            with open(ua_path, encoding="utf-8") as f:
                self._user_agents = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            logger.warning("user_agents.txt not found, using default UA")
            self._user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ]

    async def init_session(self):
        """Initialize the aiohttp session with proxy and concurrency settings."""
        connector: aiohttp.TCPConnector
        if self.proxy:
            connector = ProxyConnector.from_url(
                self.proxy, ssl=self.ssl_verify
            )
        else:
            connector = aiohttp.TCPConnector(
                limit=self.concurrency,
                limit_per_host=self.concurrency,
                ttl_dns_cache=3600,
                ssl=self.ssl_verify
            )

        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=10,
            sock_read=self.timeout,
            sock_connect=10,
        )
        self.session = aiohttp.ClientSession(
            connector=connector, timeout=timeout
        )
        self._semaphore = asyncio.Semaphore(self.concurrency)

    async def close(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    async def detect_fake_404(self, base_url: str):
        """Smart 404 detection: send 3 requests with random paths.

        If all return 200, cache the first 256 bytes of the response
        as a signature for later comparison.
        """
        signatures: list[bytes] = []
        raw_contents: list[bytes] = []
        for _ in range(3):
            random_path = random_string(32)
            url = f"{base_url.rstrip('/')}/{random_path}"
            try:
                status, content = await self.fetch(url, _skip_fake_404_check=True)
                if status == 200:
                    signatures.append(content[:256])
                    raw_contents.append(content)
            except Exception as e:
                logger.debug(f"Fake 404 probe failed: {e}")

        # If all 3 probes returned 200, the server likely returns 200 for everything
        if len(signatures) >= 3:
            # Check all signatures are similar (same size and prefix)
            sizes = [len(s) for s in raw_contents]
            if len(set(sizes)) == 1:  # all responses same size
                self._fake_404_detected = True
                self._fake_404_signature = signatures[0]
                self._fake_404_size = sizes[0]
                logger.info("Fake 404 detected: server returns 200 for non-existent paths")
            else:
                self._fake_404_detected = False
                logger.info("Standard 404 behavior detected (varying response sizes)")
        else:
            self._fake_404_detected = False
            logger.info("Standard 404 behavior detected")

    async def fetch(self, url: str, _skip_fake_404_check: bool = False) -> tuple[int, bytes]:
        """Perform an HTTP GET request with retry and smart 404 detection.

        - Exponential backoff retry (default 3 attempts)
        - Random User-Agent rotation
        - Smart fake-404 identification

        Returns:
            Tuple of (status_code, response_body_bytes)
        """
        if not self.session or self.session.closed:
            raise RuntimeError("Session not initialized. Call init_session() first.")

        last_error: Exception | None = None
        for attempt in range(self.retries):
            async with self._semaphore:
                try:
                    headers = {}
                    if self.random_ua:
                        headers["User-Agent"] = self._get_random_ua()

                    async with self.session.get(url, headers=headers) as resp:
                        content = await resp.read()
                        status = resp.status

                        # Check for fake 200 responses
                        if (not _skip_fake_404_check and status == 200
                                and self._is_fake_200(content)):
                            logger.debug(f"Fake 200 detected for {url}, treating as 404")
                            return (404, content)

                        return (status, content)

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    last_error = e
                    delay = 2 ** attempt
                    logger.debug(
                        f"Request failed (attempt {attempt + 1}/{self.retries}): {e}, "
                        f"retrying in {delay}s"
                    )
                    await asyncio.sleep(delay)

        logger.warning(f"All {self.retries} attempts failed for {url}: {last_error}")
        return (0, b"")

    def _get_random_ua(self) -> str:
        """Return a random User-Agent from the pool."""
        if not self._user_agents:
            return (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        return random.choice(self._user_agents)

    def _is_fake_200(self, content: bytes) -> bool:
        """Check if a 200 response is actually a fake 200 (i.e., a disguised 404).

        Compares both the content length and first 256 bytes of the response
        against the cached fake-404 signature to reduce false positives.
        """
        if not self._fake_404_detected or self._fake_404_signature is None:
            return False
        # Both size AND content prefix must match to reduce false positives
        if len(content) != self._fake_404_size:
            return False
        return content[:256] == self._fake_404_signature
