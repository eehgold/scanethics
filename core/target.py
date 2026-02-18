"""
Target — parse and validate an IP address or URL provided by the user.
"""

import re
import socket
from urllib.parse import urlparse


class Target:
    def __init__(self, raw: str):
        self.raw = raw.strip()
        self._parse()

    def _parse(self):
        # Add scheme if missing so urlparse works correctly
        if not re.match(r"^https?://", self.raw):
            prefixed = "http://" + self.raw
        else:
            prefixed = self.raw

        parsed = urlparse(prefixed)
        self.scheme = parsed.scheme or "http"
        self.hostname = parsed.hostname or self.raw
        self.port = parsed.port
        self.path = parsed.path or "/"
        self.base_url = f"{self.scheme}://{self.hostname}"
        if self.port:
            self.base_url += f":{self.port}"

    @property
    def is_ip(self) -> bool:
        try:
            socket.inet_aton(self.hostname)
            return True
        except socket.error:
            return False

    def resolve(self) -> str | None:
        """Return the resolved IP for this target (None if resolution fails)."""
        try:
            return socket.gethostbyname(self.hostname)
        except socket.gaierror:
            return None

    def __str__(self) -> str:
        return self.base_url
