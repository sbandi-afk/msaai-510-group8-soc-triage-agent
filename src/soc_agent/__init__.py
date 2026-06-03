"""SOC Triage Agent — reusable package (Marston Ward, AIE / Team Lead).

This package holds all the logic the notebooks import so nothing is duplicated
across `notebooks/03_agent_loop.ipynb`, `04_api_clients.ipynb`,
`05_evaluation.ipynb`, and `00_run_all.ipynb`.

Everything defaults to MOCK_MODE so the whole project runs end-to-end with ZERO
API keys and ZERO live Databricks connection. Flip the documented env vars
(see `docs/SETUP.md` / `.env.example`) to go live.
"""

from . import config  # noqa: F401

__all__ = [
    "config",
    "mocks",
    "api_clients",
    "gold_tools",
    "llm",
    "agent",
    "eval_helpers",
]

__version__ = "0.1.0"
