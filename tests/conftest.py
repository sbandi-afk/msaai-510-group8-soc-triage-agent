"""Pytest path setup: make src/soc_agent importable without installation.

Graders can run `pytest` from the repo root after
`pip install -r requirements.txt` -- no editable install needed.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Force mock mode for the whole test session -- tests must never need creds.
os.environ.setdefault("SOC_MOCK_MODE", "1")
