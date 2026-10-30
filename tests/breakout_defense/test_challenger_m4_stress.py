"""
tests/breakout_defense/test_challenger_m4_stress.py

Milestone 4 Independent Adversarial Challenge & Empirical Stress Test Harness
Conducted by teamwork_challenger_m4_r2_1 (Empirical Challenger).

Exposes Milestone4AdversarialStressHarness for breakout_defense discovery.
"""

import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))
sys.path.insert(0, str(WORKSPACE_ROOT / "tests"))

from adversarial_m4_stress_harness import Milestone4AdversarialStressHarness

__all__ = ["Milestone4AdversarialStressHarness"]

if __name__ == "__main__":
    import unittest
    unittest.main()
