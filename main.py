"""
main.py
-------
Run the scanner straight from a checkout:

    python main.py 127.0.0.1 -p 1-1024

The program itself lives in the portscanner package (portscanner/cli.py).

FOR AUTHORIZED TESTING ONLY. Do not scan hosts you do not own
or have explicit written permission to test.
"""

import sys

from portscanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
