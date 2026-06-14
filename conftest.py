"""Make the packetql package importable in tests without an editable install."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
