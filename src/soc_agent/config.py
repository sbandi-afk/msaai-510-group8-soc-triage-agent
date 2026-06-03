"""Central configuration — everything is driven by environment variables.

Design goals (locked decisions from the project owner):

* **LOCAL Python.** Notebooks + this package run locally. We talk to Databricks
  via env-configured connections only when creds are present.
* **MOCK_MODE ON by default.** A grader can execute every notebook with zero
  API keys and zero live Databricks connection.
* **Fully configurable LLM.** Provider AND model(s) are selected purely via env
  vars — no code edits required to switch between Databricks Model Serving,
  OpenAI, or the creds-free `mock` provider.

Nothing here ever hardcodes a secret. Defaults are safe placeholders; real
values come from the environment (a `.env` file is auto-loaded if present).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Optionally load a local .env file (never committed). No-op if python-dotenv
# is missing or no .env exists.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - convenience only
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # noqa: BLE001
    pass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    return val


# ---------------------------------------------------------------------------
# Sensible defaults
# ---------------------------------------------------------------------------
# Default LLM provider is Databricks Model Serving (the locked default). We
# point the OpenAI-compatible client at the Databricks serving base URL.
DEFAULT_LLM_PROVIDER = "databricks"

# Two Databricks-served models for the dual-LLM evaluation. These are common
# pay-per-token Foundation Model API names; override via env for your workspace.
DEFAULT_DBX_MODEL_A = "databricks-meta-llama-3-1-70b-instruct"
DEFAULT_DBX_MODEL_B = "databricks-dbrx-instruct"

# OpenAI alternates (only used when LLM_PROVIDER=openai).
DEFAULT_OPENAI_MODEL_A = "gpt-4o-mini"
DEFAULT_OPENAI_MODEL_B = "gpt-4o"


@dataclass
class Settings:
    """Resolved configuration snapshot. Build with ``Settings.from_env()``."""

    # --- run mode ---------------------------------------------------------
    mock_mode: bool = True

    # --- LLM selection (provider + models) --------------------------------
    llm_provider: str = DEFAULT_LLM_PROVIDER
    llm_base_url: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_model: str = DEFAULT_DBX_MODEL_A          # primary model
    llm_model_b: str = DEFAULT_DBX_MODEL_B        # second model for dual-LLM eval
    llm_temperature: float = 0.0
    llm_max_tokens: int = 1024
    llm_timeout: int = 60

    # --- Databricks workspace / compute ----------------------------------
    databricks_host: Optional[str] = None
    databricks_token: Optional[str] = None
    databricks_cluster_id: Optional[str] = None
    databricks_warehouse_id: Optional[str] = None
    uc_catalog: str = "soc_intelligence"
    uc_gold_schema: str = "gold"
    uc_silver_schema: str = "silver"

    # --- external threat-intel APIs --------------------------------------
    vt_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    nvd_api_key: Optional[str] = None  # NVD is keyless; key only raises rate limit

    # --- agent loop -------------------------------------------------------
    max_tool_iterations: int = 5
    anomaly_z_threshold: float = 2.5
    min_confidence_to_ticket: float = 0.7
    prompt_field_max_chars: int = 256  # prompt-injection input sanitization

    # --- mlflow -----------------------------------------------------------
    mlflow_tracking_uri: str = "file:./mlruns"
    mlflow_experiment: str = "soc_triage_agent"

    extra: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls) -> "Settings":
        provider = (_env("LLM_PROVIDER", DEFAULT_LLM_PROVIDER) or "databricks").lower()

        # Per-provider model defaults so a bare LLM_PROVIDER=openai still works.
        if provider == "openai":
            default_a, default_b = DEFAULT_OPENAI_MODEL_A, DEFAULT_OPENAI_MODEL_B
        else:  # databricks or mock
            default_a, default_b = DEFAULT_DBX_MODEL_A, DEFAULT_DBX_MODEL_B

        host = _env("DATABRICKS_HOST")
        # The serving base URL defaults to <host>/serving-endpoints when a host
        # is configured but LLM_BASE_URL is not set explicitly.
        base_url = _env("LLM_BASE_URL")
        if base_url is None and host and provider == "databricks":
            base_url = host.rstrip("/") + "/serving-endpoints"

        # Token resolution: LLM_API_KEY wins, else DATABRICKS_TOKEN for dbx,
        # else OPENAI_API_KEY for openai.
        token = _env("DATABRICKS_TOKEN")
        if provider == "databricks":
            api_key = _env("LLM_API_KEY", token)
        elif provider == "openai":
            api_key = _env("LLM_API_KEY", _env("OPENAI_API_KEY"))
        else:  # mock
            api_key = _env("LLM_API_KEY")

        return cls(
            mock_mode=_env_bool("SOC_MOCK_MODE", True),
            llm_provider=provider,
            llm_base_url=base_url,
            llm_api_key=api_key,
            llm_model=_env("LLM_MODEL", default_a),
            llm_model_b=_env("LLM_MODEL_B", default_b),
            llm_temperature=float(_env("LLM_TEMPERATURE", "0.0")),
            llm_max_tokens=int(_env("LLM_MAX_TOKENS", "1024")),
            llm_timeout=int(_env("LLM_TIMEOUT", "60")),
            databricks_host=host,
            databricks_token=token,
            databricks_cluster_id=_env("DATABRICKS_CLUSTER_ID"),
            databricks_warehouse_id=_env("DATABRICKS_WAREHOUSE_ID"),
            uc_catalog=_env("UC_CATALOG", "soc_intelligence"),
            uc_gold_schema=_env("UC_GOLD_SCHEMA", "gold"),
            uc_silver_schema=_env("UC_SILVER_SCHEMA", "silver"),
            vt_api_key=_env("VT_API_KEY", _env("VIRUSTOTAL_API_KEY")),
            shodan_api_key=_env("SHODAN_API_KEY"),
            nvd_api_key=_env("NVD_API_KEY"),
            max_tool_iterations=int(_env("MAX_TOOL_ITERATIONS", "5")),
            anomaly_z_threshold=float(_env("ANOMALY_Z_THRESHOLD", "2.5")),
            min_confidence_to_ticket=float(_env("MIN_CONFIDENCE_TO_TICKET", "0.7")),
            mlflow_tracking_uri=_env("MLFLOW_TRACKING_URI", "file:./mlruns"),
            mlflow_experiment=_env("MLFLOW_EXPERIMENT", "soc_triage_agent"),
        )

    # ------------------------------------------------------------------
    # Effective provider: if the configured provider has no usable creds we
    # transparently fall back to the creds-free `mock` provider so notebooks
    # still execute end-to-end. This is what makes "runs with zero creds" work
    # while keeping `databricks` as the documented default.
    # ------------------------------------------------------------------
    def llm_creds_present(self) -> bool:
        if self.llm_provider == "mock":
            return True
        if self.llm_provider == "databricks":
            return bool(self.llm_base_url and self.llm_api_key)
        if self.llm_provider == "openai":
            return bool(self.llm_api_key)
        return False

    def effective_llm_provider(self) -> str:
        """Provider actually used at runtime (mock if creds are missing)."""
        if self.mock_mode:
            return "mock"
        if self.llm_provider == "mock":
            return "mock"
        return self.llm_provider if self.llm_creds_present() else "mock"

    def databricks_creds_present(self) -> bool:
        return bool(self.databricks_host and self.databricks_token)

    def use_live_databricks(self) -> bool:
        """True only when not in mock mode AND Databricks creds are present."""
        return (not self.mock_mode) and self.databricks_creds_present()

    # ------------------------------------------------------------------
    def summary(self) -> dict:
        """Redacted, printable view of the active configuration."""

        def redact(v: Optional[str]) -> str:
            if not v:
                return "<unset>"
            return f"set (••••{v[-4:]})" if len(v) >= 4 else "set"

        return {
            "mock_mode": self.mock_mode,
            "llm_provider (configured)": self.llm_provider,
            "llm_provider (effective)": self.effective_llm_provider(),
            "llm_model": self.llm_model,
            "llm_model_b": self.llm_model_b,
            "llm_base_url": self.llm_base_url or "<unset>",
            "llm_api_key": redact(self.llm_api_key),
            "databricks_host": self.databricks_host or "<unset>",
            "databricks_token": redact(self.databricks_token),
            "databricks_cluster_id": self.databricks_cluster_id or "<unset>",
            "databricks_warehouse_id": self.databricks_warehouse_id or "<unset>",
            "use_live_databricks": self.use_live_databricks(),
            "vt_api_key": redact(self.vt_api_key),
            "shodan_api_key": redact(self.shodan_api_key),
            "nvd_api_key": redact(self.nvd_api_key),
            "uc_catalog": self.uc_catalog,
        }

    def gold_fqn(self, name: str) -> str:
        return f"{self.uc_catalog}.{self.uc_gold_schema}.{name}"

    def silver_fqn(self, name: str) -> str:
        return f"{self.uc_catalog}.{self.uc_silver_schema}.{name}"


def get_settings() -> Settings:
    """Build a fresh Settings snapshot from the current environment."""
    return Settings.from_env()
