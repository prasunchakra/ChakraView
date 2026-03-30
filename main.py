import sys
import time

from config import (
    APP_NAME, VERSION, DESCRIPTION,
    TYPEWRITER_DELAY, BOX_WIDTH,
    TARGET_URL, MAX_CRAWL_DEPTH, MAX_PAGES,
)
from scanners import ALL_SCANNERS
from scanners.discovery import DiscoveryScanner

EYE = r"""
                         ▄▄███████▄▄
                      ▄██▀▀       ▀▀██▄
                   ▄█▀   ▄▄█████▄▄   ▀█▄
                 ▄█▀   ▄██▀▀   ▀▀██▄   ▀█▄
                ██   ▄██▀  ▄█████▄  ▀██▄   ██
               ██   ██▀  ██▀▀█▀▀██  ▀██   ██
                ██   ▀██▄  ▀█████▀  ▄██▀   ██
                 ▀█▄   ▀██▄▄   ▄▄██▀   ▄█▀
                   ▀█▄   ▀▀█████▀▀   ▄█▀
                      ▀██▄▄       ▄▄██▀
                         ▀▀███████▀▀
"""

BANNER = r"""
   ░█████╗░██╗░░██╗░█████╗░██╗░░██╗██████╗░░█████╗░██╗░░░██╗██╗███████╗░██╗░░░░░░░██╗
   ██╔══██╗██║░░██║██╔══██╗██║░██╔╝██╔══██╗██╔══██╗██║░░░██║██║██╔════╝░██║░░██╗░░██║
   ██║░░╚═╝███████║███████║█████═╝░██████╔╝███████║╚██╗░██╔╝██║█████╗░░░╚██╗████╗██╔╝
   ██║░░██╗██╔══██║██╔══██║██╔═██╗░██╔══██╗██╔══██║░╚████╔╝░██║██╔══╝░░░░████╔═████║░
   ╚█████╔╝██║░░██║██║░░██║██║░╚██╗██║░░██║██║░░██║░░╚██╔╝░░██║███████╗░░╚██╔╝░╚██╔╝░
   ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚══════╝░░░╚═╝░░░╚═╝░
"""


def print_slow(text, delay=TYPEWRITER_DELAY):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def draw_box(lines):
    print(f"  ╔{'═' * BOX_WIDTH}╗")
    for line in lines:
        padding = BOX_WIDTH - len(line) - 4
        print_slow(f"  ║  {line}{' ' * padding}  ║")
    print(f"  ╚{'═' * BOX_WIDTH}╝")


def print_status(label, status="ready"):
    dots = "." * (44 - len(label))
    print_slow(f"   [✓] {label} {dots} {status}")


def print_scanner_load(scanner_cls):
    s = scanner_cls()
    dots = "." * (48 - len(s.name))
    print_slow(f"   ▸ {s.name} {dots} loaded")


def startup():
    print(EYE)
    print(BANNER)

    draw_box([
        f":: {APP_NAME} ::  (v{VERSION})",
        DESCRIPTION,
    ])
    print()

    print_status("OWASP Top 10 detection engine")
    print_status("Custom rule engine")
    print_status("Report generator")
    print()

    print_slow("   Loading scanner modules...")
    print()
    for scanner_cls in ALL_SCANNERS:
        print_scanner_load(scanner_cls)
    print()

    separator = f"  {'═' * (BOX_WIDTH + 2)}"
    print(separator)
    scanner_count = len(ALL_SCANNERS)
    print_slow(
        f"  ▸ Started {APP_NAME} v{VERSION} on Python {sys.version.split()[0]}"
        f"  ({scanner_count} scanner(s) armed)"
    )
    print_slow(f"  ▸ Target ➜  {TARGET_URL}")
    print(separator)
    print()


def run_discovery() -> dict:
    """Run the Discovery scanner using settings from config.py."""
    separator = f"  {'═' * (BOX_WIDTH + 2)}"
    print(separator)
    print()

    scanner = DiscoveryScanner(max_depth=MAX_CRAWL_DEPTH, max_pages=MAX_PAGES)
    results = scanner.scan(TARGET_URL)

    print(separator)
    print_slow(f"  ▸ Discovery phase complete.")
    print(separator)
    print()
    return results


if __name__ == "__main__":
    startup()
    run_discovery()
