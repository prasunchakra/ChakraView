"""Central configuration and constants for ChakraView."""

# ── App metadata ────────────────────────────────────────────────
APP_NAME = "ChakraView"
VERSION = "0.1.0"
DESCRIPTION = "The Ultimate Vibe Auditing Tool for Web Applications"

# ── Display settings ────────────────────────────────────────────
TYPEWRITER_DELAY = 0.006  # seconds per character
BOX_WIDTH = 82  # inner width of the info box

# ── Scan settings ──────────────────────────────────────────────
TARGET_URL = "https://prasunchakra.com"  # URL to scan
MAX_CRAWL_DEPTH = 3                 # how many link-hops deep the crawler goes
MAX_PAGES = 50                      # hard cap on pages fetched per scan
