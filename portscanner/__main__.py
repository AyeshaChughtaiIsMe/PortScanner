"""Allows `python -m portscanner ...`."""

import sys

from .cli import main

sys.exit(main())
