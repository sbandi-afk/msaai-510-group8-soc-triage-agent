"""Wrappers around Sai's (DE) gold-layer Unity Catalog functions.

These adapt to the **actual shipped** signatures in ``soc_etl_pipeline.ipynb``,
which drifted from the proposal's interface contract:

================  =================================  ============================
Function          Proposal contract                  ACTUALLY shipped (adapted here)
================  =================================  ============================
score_anomaly     ``(src_ip, window_days)`` →         **TABLE-VALUED**
                  ``{z_score, baseline_mean,          ``score_anomaly(p_host_ip STRING,
                  baseline_std}``                      p_window_min INT)`` →
                                                       rows of (host_ip, event_count,
                                                       baseline_mean, baseline_std,
                                                       z_score, window_start,
                                                       computed_at). Window is in
                                                       **MINUTES**, not days.
classify_threat   (not in proposal contract)          scalar Python UC, JSON in →
                                                       JSON ``{tactic, technique_id,
                                                       confidence}`` out.
get_exposed_assets(not in proposal contract)          TABLE-VALUED, no args →
                                                       (host_ip, risk_flag, assessed_at).
================  =================================  ============================

Each wrapper runs against MOCK fixtures by default, and against live Unity
Catalog (via databricks-connect or the Databricks SDK Statement Execution API)
when ``use_live_databricks()`` is true. The agent only ever sees normalized
Python dicts, so it never depends on a live Spark session.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from . import mocks
from .config import Settings, get_settings

# ``gold.incident`` column order (exact schema from the ETL notebook).
INCIDENT_COLUMNS = [
    "incident_id", "host_ip", "user_id", "tactic", "technique_id",
    "confidence", "z_score", "severity", "payload_json", "created_at", "resolved_at",
]

# In-memory incident store used in mock mode (stands in for gold.incident).
_INCIDENT_STORE: List[Dict[str, Any]] = []


def reset_incident_store() -> None:
    _INCIDENT_STORE.clear()


def get_incident_store() -> List[Dict[str, Any]]:
    return list(_INCIDENT_STORE)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ===========================================================================
# Live Databricks SQL backend (lazy; never imported in mock mode)
# ===========================================================================

# Cached warehouse id discovered at runtime when neither DATABRICKS_WAREHOUSE_ID
# nor DATABRICKS_CLUSTER_ID is set in the environment.
_AUTO_WAREHOUSE_ID: Optional[str] = None


def _discover_warehouse(settings: "Settings") -> str:
    """Return the id of the first available SQL warehouse in the workspace.

    Result is cached for the process lifetime so repeated calls do not incur
    additional API round-trips.
    """
    global _AUTO_WAREHOUSE_ID
    if _AUTO_WAREHOUSE_ID:
        return _AUTO_WAREHOUSE_ID
    from databricks.sdk import WorkspaceClient

    w = WorkspaceClient(host=settings.databricks_host, token=settings.databricks_token)
    warehouses = list(w.warehouses.list())
    if not warehouses:
        raise RuntimeError(
            "Auto-discovery found no SQL warehouses in the Databricks workspace. "
            "Set DATABRICKS_WAREHOUSE_ID manually in .env."
        )
    # Prefer a warehouse that is already running or starting.
    for wh in warehouses:
        state = str(getattr(wh, "state", "")).upper()
        if state in ("RUNNING", "STARTING"):
            _AUTO_WAREHOUSE_ID = wh.id
            return _AUTO_WAREHOUSE_ID
    # Fall back to the first warehouse regardless of state.
    _AUTO_WAREHOUSE_ID = warehouses[0].id
    return _AUTO_WAREHOUSE_ID


def _run_sql(sql: str, settings: Settings) -> List[Dict[str, Any]]:
    """Execute SQL on Databricks, return list-of-dicts.

    Tries three paths in order:
      A) databricks-connect (Spark) — requires DATABRICKS_CLUSTER_ID
      B) SDK Statement Execution API — uses DATABRICKS_WAREHOUSE_ID
      C) SDK Statement Execution API — auto-discovers first available warehouse
    """
    # --- Option A: databricks-connect (Spark) ---
    if settings.databricks_cluster_id:
        try:
            from databricks.connect import DatabricksSession

            spark = (
                DatabricksSession.builder.remote(
                    host=settings.databricks_host,
                    token=settings.databricks_token,
                    cluster_id=settings.databricks_cluster_id,
                ).getOrCreate()
            )
            pdf = spark.sql(sql).toPandas()
            return pdf.to_dict(orient="records")
        except Exception:  # noqa: BLE001 - fall through to SDK
            pass

    # --- Option B / C: Databricks SDK Statement Execution API ---
    from databricks.sdk import WorkspaceClient

    warehouse_id = settings.databricks_warehouse_id or _discover_warehouse(settings)
    w = WorkspaceClient(host=settings.databricks_host, token=settings.databricks_token)
    resp = w.statement_execution.execute_statement(
        warehouse_id=warehouse_id,
        statement=sql,
        wait_timeout="30s",
    )
    cols = [c.name for c in resp.manifest.schema.columns] if resp.manifest and resp.manifest.schema else []
    data = resp.result.data_array if resp.result and resp.result.data_array else []
    return [dict(zip(cols, row)) for row in data]


def _sql_str(v: str) -> str:
    return "'" + str(v).replace("'", "''") + "'"


# ===========================================================================
# Tool wrappers
# ===========================================================================
def score_anomaly(
    host_ip: str,
    window_min: int = 60,
    settings: Optional[Settings] = None,
) -> List[Dict[str, Any]]:
    """Adapter for the table-valued ``gold.score_anomaly(p_host_ip, p_window_min)``.

    NOTE the window is in MINUTES (shipped reality), not days (proposal).
    Returns the raw rows; use :func:`top_anomaly` for a single normalized dict.
    """
    s = settings or get_settings()
    if not s.use_live_databricks():
        return mocks.mock_score_anomaly(host_ip, window_min)
    fqn = s.gold_fqn("score_anomaly")
    sql = f"SELECT * FROM {fqn}({_sql_str(host_ip)}, {int(window_min)})"
    return _run_sql(sql, s)


def top_anomaly(host_ip: str, window_min: int = 60, settings: Optional[Settings] = None) -> Dict[str, Any]:
    """Normalize ``score_anomaly`` rows to the single highest-z_score dict.

    Bridges the shipped TVF back to a proposal-style ``{z_score, baseline_mean,
    baseline_std, ...}`` dict the agent reasons over.
    """
    rows = score_anomaly(host_ip, window_min, settings)
    if not rows:
        return {"host_ip": host_ip, "z_score": 0.0, "baseline_mean": None,
                "baseline_std": None, "event_count": 0, "rows": 0}
    top = max(rows, key=lambda r: r.get("z_score", 0) or 0)
    return {
        "host_ip": top.get("host_ip", host_ip),
        "z_score": float(top.get("z_score", 0.0) or 0.0),
        "baseline_mean": top.get("baseline_mean"),
        "baseline_std": top.get("baseline_std"),
        "event_count": top.get("event_count"),
        "rows": len(rows),
    }


def classify_threat(
    event_payload: Union[str, Dict[str, Any]],
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Scalar UC ``gold.classify_threat(event_payload)`` → parsed dict."""
    s = settings or get_settings()
    payload_str = event_payload if isinstance(event_payload, str) else json.dumps(event_payload)
    if not s.use_live_databricks():
        return json.loads(mocks.mock_classify_threat(payload_str))
    fqn = s.gold_fqn("classify_threat")
    sql = f"SELECT {fqn}({_sql_str(payload_str)}) AS r"
    rows = _run_sql(sql, s)
    return json.loads(rows[0]["r"]) if rows else {"tactic": "unknown", "technique_id": "T0000", "confidence": 0.0}


def get_exposed_assets(settings: Optional[Settings] = None) -> List[Dict[str, Any]]:
    """Table-valued ``gold.get_exposed_assets()`` → list of dicts."""
    s = settings or get_settings()
    if not s.use_live_databricks():
        return mocks.mock_get_exposed_assets()
    fqn = s.gold_fqn("get_exposed_assets")
    return _run_sql(f"SELECT * FROM {fqn}()", s)


def write_incident(
    incident: Dict[str, Any],
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Write one incident row matching the ``gold.incident`` schema.

    In mock mode it appends to the in-memory store; live it INSERTs into
    ``gold.incident``. Returns the fully-populated row.
    """
    s = settings or get_settings()
    row = build_incident_row(incident)
    if not s.use_live_databricks():
        _INCIDENT_STORE.append(row)
        return row
    fqn = s.gold_fqn("incident")
    cols = ", ".join(INCIDENT_COLUMNS)
    vals = ", ".join(_sql_value(row[c]) for c in INCIDENT_COLUMNS)
    _run_sql(f"INSERT INTO {fqn} ({cols}) VALUES ({vals})", s)
    return row


def build_incident_row(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce an arbitrary classification result into a gold.incident row."""
    return {
        "incident_id": incident.get("incident_id") or str(uuid.uuid4()),
        "host_ip": incident.get("host_ip"),
        "user_id": incident.get("user_id"),
        "tactic": incident.get("tactic"),
        "technique_id": incident.get("technique_id"),
        "confidence": float(incident.get("confidence", 0.0) or 0.0),
        "z_score": float(incident.get("z_score", 0.0) or 0.0),
        "severity": incident.get("severity"),
        "payload_json": incident.get("payload_json")
        or json.dumps(incident.get("event_payload", {})),
        "created_at": incident.get("created_at") or _utcnow(),
        "resolved_at": incident.get("resolved_at"),
    }


def _sql_value(v: Any) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    return _sql_str(str(v))
