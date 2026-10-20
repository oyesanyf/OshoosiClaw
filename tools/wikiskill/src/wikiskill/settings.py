"""Packaged read-only resources and caller-owned data paths."""
import os
from pathlib import Path
from importlib.resources import files  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
RESOURCES = Path(str(files("wikiskill") / "resources"))
DATA_ROOT = Path(os.environ.get("WIKISKILL_DATA_DIR", "data")).resolve()
