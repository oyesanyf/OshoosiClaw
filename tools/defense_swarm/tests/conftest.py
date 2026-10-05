import sys
import os

# Automatically add defense_swarm src directory to sys.path for all pytest suites
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
