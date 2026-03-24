import sys
import time

from config import APP_NAME, VERSION, DESCRIPTION, TYPEWRITER_DELAY, BOX_WIDTH

BANNER = r"""
   ░█████╗░██╗░░██╗░█████╗░██╗░░██╗██████╗░░█████╗░██╗░░░██╗██╗███████╗░██╗░░░░░░░██╗
   ██╔══██╗██║░░██║██╔══██╗██║░██╔╝██╔══██╗██╔══██╗██║░░░██║██║██╔════╝░██║░░██╗░░██║
   ██║░░╚═╝███████║███████║█████═╝░██████╔╝███████║╚██╗░██╔╝██║█████╗░░░╚██╗████╗██╔╝
   ██║░░██╗██╔══██║██╔══██║██╔═██╗░██╔══██╗██╔══██║░╚████╔╝░██║██╔══╝░░░░████╔═████║░
   ╚█████╔╝██║░░██║██║░░██║██║░╚██╗██║░░██║██║░░██║░░╚██╔╝░░██║███████╗░░╚██╔╝░╚██╔╝░
   ░╚════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚══════╝░░░╚═╝░░░╚═╝░
"""


def print_slow(text, delay=TYPEWRITER_DELAY):
    """Print text character by character for a typewriter effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def draw_box(lines):
    """Draw a box around a list of text lines."""
    print(f"  ╔{'═' * BOX_WIDTH}╗")
    for line in lines:
        padding = BOX_WIDTH - len(line) - 4
        print_slow(f"  ║  {line}{' ' * padding}  ║")
    print(f"  ╚{'═' * BOX_WIDTH}╝")


def print_status(label, status="ready"):
    """Print a status line with dots alignment."""
    dots = "." * (44 - len(label))
    print_slow(f"   [✓] {label} {dots} {status}")


def startup():
    """Display the ChakraView startup sequence."""
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

    separator = f"  {'═' * (BOX_WIDTH + 2)}"
    print(separator)
    print_slow(f"  ▸ Started {APP_NAME} v{VERSION} on Python {sys.version.split()[0]}")
    print_slow(f"  ▸ Awaiting target — No scan in progress.")
    print(separator)
    print()


if __name__ == "__main__":
    startup()
