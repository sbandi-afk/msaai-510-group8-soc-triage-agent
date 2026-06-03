"""Evaluation harness — MLflow tracing + dual-LLM comparison.

Provides:

* :func:`setup_mlflow` — point MLflow at a local file store + experiment.
* :func:`default_scenarios` — ~5 traceable scenarios incl. 2 out-of-scope ones.
* :func:`run_traces` — run the agent over scenarios, capturing an MLflow trace
  (spans + params/metrics/tags) per scenario; returns a results table.
* :func:`compare_two_llms` / :func:`dual_llm_table` — run the SAME trace input
  through two models (``LLM_MODEL`` vs ``LLM_MODEL_B``, both read from config)
  and return a side-by-side comparison table.

In mock mode the two "models" are deterministic calibrated stand-ins so the
comparison runs with zero creds; point ``LLM_MODEL`` / ``LLM_MODEL_B`` at two
real Databricks serving endpoints for live numbers.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import pandas as pd

from . import agent as agent_module
from . import gold_tools, llm as llm_module
from .config import Settings, get_settings

try:
    import mlflow
except Exception:  # pragma: no cover
    mlflow = None

try:
    import openai as _openai
except Exception:  # pragma: no cover
    _openai = None


# ---------------------------------------------------------------------------
def setup_mlflow(settings: Optional[Settings] = None):
    s = settings or get_settings()
    if mlflow is None:
        return None
    mlflow.set_tracking_uri(s.mlflow_tracking_uri)
    try:
        mlflow.set_experiment(s.mlflow_experiment)
    except Exception:
        # Corrupt experiment metadata (e.g. a directory with spaces in its name
        # was created by a previous partial run). Delete the bad entry and retry.
        import shutil, os
        from pathlib import Path
        tracking_root = Path(s.mlflow_tracking_uri.removeprefix("file:"))
        for entry in tracking_root.iterdir():
            if " " in entry.name and entry.is_dir():
                shutil.rmtree(entry)
        mlflow.set_experiment(s.mlflow_experiment)
    return mlflow


# ---------------------------------------------------------------------------
def default_scenarios() -> List[Dict[str, Any]]:
    """5 scenarios: 3 in-scope attack events, 2 out-of-scope rejections."""
    from .mocks import SAMPLE_EVENTS

    return [
        {
            "name": "credential_access_ws5",
            "query": "Triage suspicious credential validation on host WORKSTATION5.",
            "event": SAMPLE_EVENTS[0],
            "expect": "escalate",
        },
        {
            "name": "execution_powershell_ws6",
            "query": "Investigate the encoded PowerShell execution alert on WORKSTATION6.",
            "event": SAMPLE_EVENTS[1],
            "expect": "escalate",
        },
        {
            "name": "persistence_service_filesrv1",
            "query": "Review the service-creation event on FILESRV1.",
            "event": SAMPLE_EVENTS[2],
            "expect": "escalate",
        },
        # --- 2 explicit out-of-scope / irrelevant queries (graceful reject) ---
        {
            "name": "out_of_scope_weather",
            "query": "What's the weather in Paris this weekend?",
            "event": None,
            "expect": "reject",
        },
        {
            "name": "out_of_scope_recipe",
            "query": "Write me a poem about my cat and suggest a pasta recipe.",
            "event": None,
            "expect": "reject",
        },
    ]


# ---------------------------------------------------------------------------
def run_traces(
    scenarios: Optional[List[Dict[str, Any]]] = None,
    llm: Optional[llm_module.LLM] = None,
    settings: Optional[Settings] = None,
) -> pd.DataFrame:
    """Run the agent over each scenario, logging one MLflow trace/run each."""
    s = settings or get_settings()
    scenarios = scenarios or default_scenarios()
    setup_mlflow(s)
    compiled = agent_module.build_agent(llm, s)
    rows: List[Dict[str, Any]] = []

    for sc in scenarios:
        t0 = time.perf_counter()
        try:
            result = _traced_run(sc["query"], sc.get("event"), compiled, s)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            cls = result.get("classification") or {}
            row = {
                "scenario": sc["name"],
                "expect": sc.get("expect"),
                "decision": result.get("decision"),
                "tactic": cls.get("tactic"),
                "technique_id": cls.get("technique_id"),
                "confidence": cls.get("confidence"),
                "priority": cls.get("priority"),
                "severity": cls.get("severity"),
                "z_score": (result.get("anomaly") or {}).get("z_score"),
                "iterations": result.get("iterations"),
                "latency_ms": round(latency_ms, 1),
                "incident_written": result.get("incident") is not None,
            }
        except Exception as _exc:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            _is_rate_limit = (
                (_openai is not None and isinstance(_exc, _openai.PermissionDeniedError))
                or "PERMISSION_DENIED" in str(_exc)
                or "rate limit of 0" in str(_exc)
            )
            _label = "rate_limited" if _is_rate_limit else "error"
            print(f"  [{sc['name']}] {_label}: {_exc!s:.200}")
            row = {
                "scenario": sc["name"],
                "expect": sc.get("expect"),
                "decision": _label,
                "tactic": None,
                "technique_id": None,
                "confidence": None,
                "priority": None,
                "severity": None,
                "z_score": None,
                "iterations": None,
                "latency_ms": round(latency_ms, 1),
                "incident_written": False,
            }
        rows.append(row)

        if mlflow is not None:
            with mlflow.start_run(run_name=sc["name"]):
                mlflow.log_params({
                    "scenario": sc["name"],
                    "llm_provider": s.effective_llm_provider(),
                    "llm_model": (llm.model if llm else s.llm_model),
                    "in_scope": row.get("decision") not in ("rate_limited", "error"),
                })
                mlflow.set_tags({
                    "decision": str(row["decision"]),
                    "tactic": str(row["tactic"]),
                    "expect": str(sc.get("expect")),
                })
                mlflow.log_metrics({
                    "latency_ms": row["latency_ms"],
                    "iterations": float(row["iterations"] or 0),
                    "confidence": float(row["confidence"] or 0.0),
                    "priority": float(row["priority"] or 0.0),
                    "z_score": float(row["z_score"] or 0.0),
                })

    return pd.DataFrame(rows)


def _traced_run(query, event, compiled, settings):
    """Agent run wrapped in an MLflow trace span when available."""
    if mlflow is not None and hasattr(mlflow, "trace"):
        @mlflow.trace(name="soc_triage")
        def _inner(q, e):
            return agent_module.run_triage(q, e, settings=settings, agent=compiled)
        return _inner(query, event)
    return agent_module.run_triage(query, event, settings=settings, agent=compiled)


# ---------------------------------------------------------------------------
# Dual-LLM, same-trace comparison
# ---------------------------------------------------------------------------
def compare_two_llms(
    scenario: Dict[str, Any],
    settings: Optional[Settings] = None,
    model_a: Optional[str] = None,
    model_b: Optional[str] = None,
    temperature_b: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """Run ONE scenario through two models; return one row per model.

    ``temperature_b`` lets you vary the inference config for Model B even when
    both slots use the same underlying endpoint (e.g. Llama 3.3 at temp=0.0
    vs temp=0.5 when only one Databricks endpoint is available).
    """
    import dataclasses
    s = settings or get_settings()
    model_a = model_a or s.llm_model
    model_b = model_b or s.llm_model_b
    out: List[Dict[str, Any]] = []

    for label, model_name, temp_override in (
        ("model_a", model_a, None),
        ("model_b", model_b, temperature_b),
    ):
        _s = dataclasses.replace(s, llm_temperature=temp_override) if temp_override is not None else s
        llm = llm_module.get_llm(model=model_name, settings=_s)
        t0 = time.perf_counter()
        try:
            result = agent_module.run_triage(scenario["query"], scenario.get("event"),
                                             llm=llm, settings=_s)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            cls = result.get("classification") or {}
            row = {
                "scenario": scenario["name"],
                "slot": label,
                "model": model_name,
                "provider": llm.provider,
                "decision": result.get("decision"),
                "tactic": cls.get("tactic"),
                "technique_id": cls.get("technique_id"),
                "confidence": cls.get("confidence"),
                "priority": cls.get("priority"),
                "severity": cls.get("severity"),
                "latency_ms": round(latency_ms, 1),
            }
        except Exception as _exc:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            _is_404 = "ENDPOINT_NOT_FOUND" in str(_exc) or "404" in str(_exc)
            _label = "endpoint_not_found" if _is_404 else "error"
            print(f"  [{label}] {_label}: {_exc!s:.200}")
            row = {
                "scenario": scenario["name"],
                "slot": label,
                "model": model_name,
                "provider": llm.provider,
                "decision": _label,
                "tactic": None,
                "technique_id": None,
                "confidence": None,
                "priority": None,
                "severity": None,
                "latency_ms": round(latency_ms, 1),
            }
        out.append(row)
    return out


def dual_llm_table(
    scenarios: Optional[List[Dict[str, Any]]] = None,
    settings: Optional[Settings] = None,
) -> pd.DataFrame:
    """Same-trace 2-LLM comparison across scenarios → tidy DataFrame."""
    s = settings or get_settings()
    setup_mlflow(s)
    scenarios = scenarios or [sc for sc in default_scenarios() if sc.get("event")]
    rows: List[Dict[str, Any]] = []
    for sc in scenarios:
        if mlflow is not None:
            with mlflow.start_run(run_name=f"compare_{sc['name']}"):
                pair = compare_two_llms(sc, s)
                for r in pair:
                    mlflow.log_metric(f"{r['slot']}_confidence", float(r["confidence"] or 0))
                    mlflow.log_metric(f"{r['slot']}_priority", float(r["priority"] or 0))
                    mlflow.log_metric(f"{r['slot']}_latency_ms", float(r["latency_ms"] or 0))
                rows.extend(pair)
        else:
            rows.extend(compare_two_llms(sc, s))
    return pd.DataFrame(rows)


def comparison_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Agreement + mean confidence/latency per model from a dual-LLM table."""
    if df.empty:
        return df
    agree = (
        df.pivot_table(index="scenario", columns="slot", values="tactic", aggfunc="first")
        .apply(lambda r: r.get("model_a") == r.get("model_b"), axis=1)
    )
    by_model = df.groupby("model").agg(
        mean_confidence=("confidence", "mean"),
        mean_priority=("priority", "mean"),
        mean_latency_ms=("latency_ms", "mean"),
        n=("scenario", "count"),
    ).reset_index()
    by_model["tactic_agreement_rate"] = round(float(agree.mean()), 3)
    return by_model
