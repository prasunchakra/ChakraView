"""
ChakraView Scanners — Vulnerability detection modules.

Each scanner targets a specific class of web vulnerability.
Import `ALL_SCANNERS` for the ordered list used by the main runner.
"""

from scanners.discovery import DiscoveryScanner

ALL_SCANNERS = [
    DiscoveryScanner,
]
