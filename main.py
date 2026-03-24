import sys
import time

VERSION = "0.1.0"

BANNER = r"""
  ::::::::  :::    :::     :::     :::    ::: :::::::::      :::
 :+:    :+: :+:    :+:   :+: :+:  :+:   :+:  :+:    :+:   :+: :+:
 +:+        +:+    +:+  +:+   +:+ +:+  +:+   +:+    +:+  +:+   +:+
 +#+        +#++:++#++ +#++:++#++:+#++:++    +#++:++#:  +#++:++#++:
 +#+        +#+    +#+ +#+     +#++#+  +#+    +#+    +#+ +#+     +#+
 #+#    #+# #+#    #+# #+#     #+##+#   #+#   #+#    #+# #+#     #+#
  ########  ###    ### ###     ######    ### ###    ### ###     ###

 :::     ::: ::::::::::: :::::::::: :::       :::
 :+:     :+:     :+:     :+:        :+:       :+:
 +:+     +:+     +:+     +:+        +:+       +:+
 +#+     +:+     +#+     +#++:++#   +#+  +:+  +#+
  +#+   +#+      +#+     +#+        +#+ +#+#+ +#+
   #+#+#+#       #+#     #+#         #+#+# #+#+#
     ###     ########### ##########   ###   ###
"""

SEPARATOR = "═" * 62


def print_slow(text, delay=0.008):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def startup():
    print(BANNER)
    W = 60
    tag = f":: ChakraView ::  (v{VERSION})"
    desc = "Vibe Audit -- Web Application Vulnerability Scanner"
    pad1 = W - len(tag) - 4
    pad2 = W - len(desc) - 4
    print(f"  ╔{'═' * W}╗")
    print_slow(f"  ║  {tag}{' ' * pad1}  ║")
    print_slow(f"  ║  {desc}{' ' * pad2}  ║")
    print(f"  ╚{'═' * W}╝")
    print()
    print_slow("   ● OWASP Top 10 detection engine ............. ready")
    print_slow("   ● Custom rule engine ........................ ready")
    print_slow("   ● Report generator .......................... ready")
    print()
    print(f"  {SEPARATOR}")
    print_slow(f"  ▸ Started ChakraView v{VERSION} on Python {sys.version.split()[0]}")
    print_slow("  ▸ Awaiting target — No scan in progress.")
    print(f"  {SEPARATOR}")
    print()


if __name__ == "__main__":
    startup()
