"""Utility functions for FileLeak."""

import asyncio
import os
import random
import re
import string
from urllib.parse import urlparse


def sanitize_path(base_dir: str, filename: str) -> str | None:
    """Validate and sanitize a file path.

    - Reject paths containing '..'
    - Reject absolute paths
    - Ensure the final path stays within base_dir
    - Returns the safe full path, or None if unsafe
    """
    # Reject absolute paths
    if os.path.isabs(filename):
        return None

    # Reject path traversal
    if ".." in filename.split(os.sep) or ".." in filename.split("/"):
        return None

    # Build the full path and resolve it
    full_path = os.path.normpath(os.path.join(base_dir, filename))

    # Ensure the resolved path is still within base_dir
    base_resolved = os.path.normpath(base_dir)
    if not full_path.startswith(base_resolved + os.sep) and full_path != base_resolved:
        return None

    return full_path


def ensure_dir(filepath: str):
    """Ensure the directory for a given file path exists."""
    dirpath = os.path.dirname(filepath)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)


async def save_file(filepath: str, content: bytes):
    """Asynchronously save binary content to a file."""
    loop = asyncio.get_running_loop()
    ensure_dir(filepath)
    await loop.run_in_executor(None, _write_file, filepath, content)


def _write_file(filepath: str, content: bytes):
    """Synchronous file write helper."""
    with open(filepath, "wb") as f:
        f.write(content)


def url_to_dirname(url: str) -> str:
    """Convert a URL to a safe directory name (pure domain, no type prefix).

    Examples:
        http://www.example.com:8080/.git/ -> www_example_com_8080
        http://www.example.com/.git/      -> www_example_com
        https://example.com/.svn/         -> example_com
        https://example.com:443/.svn/     -> example_com   (default port skipped)
    """
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    port = parsed.port
    # Replace dots and hyphens with underscores
    host = host.replace(".", "_").replace("-", "_")
    # Skip default ports (80 for http, 443 for https)
    default_ports = {"http": 80, "https": 443}
    if port and port != default_ports.get(parsed.scheme):
        return f"{host}_{port}"
    return host


def random_string(length: int = 32) -> str:
    """Generate a random alphanumeric string of the given length."""
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))
