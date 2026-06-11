#!/usr/bin/env python3
"""
demo_attack.py -- One-command live demo of the SOC Triage Agent.

Simulates a credential-access brute-force attack against a demo host, then drives
the live Databricks pipeline end-to-end and narrates each step for a screen
recording:

    1. INJECT  ~50 failed-login events (Windows EventID 4625) into
               soc_intelligence.silver.siem_normalized via the SQL Statements API.
    2. TRIGGER the soc_agent_live job (LangGraph ReAct agent) with run-now.
    3. POLL    the run to a terminal state with a live status line.
    4. REVEAL  the incident the agent wrote to gold.incident, then run the
               incident_eval_agent and print the quality grade from
               gold.incident_eval.

If no incident is created, the script exits non-zero and prints the max z-score
from gold.score_anomaly() for the demo host as a diagnostic.

Detection design notes
----------------------
gold.score_anomaly() builds a *p90-capped* per-minute baseline over the last 24h
and z-scores the most recent minute-windows. We therefore inject the whole burst
into the **current minute** for an **existing host (WS5)** that already has an
organic baseline. WS5 also maps to a known-bad Tor exit node in the agent's
HOST_IP_MAP, so AbuseIPDB returns a malicious verdict -> the LLM classifies with
high confidence (> 0.7) and the incident escalates. Measured z for a 50-event
burst on WS5 is ~4.3 -- above both the 1.5 escalation gate and the 2.5 eval gate.

Usage
-----
    python demo_attack.py            # run the full demo
    python demo_attack.py --cleanup  # delete injected rows + demo incidents
    python demo_attack.py --host WS5 --events 50

Reads DATABRICKS_HOST / DATABRICKS_TOKEN / DATABRICKS_WAREHOUSE_ID from the
process environment or the repo's .env (never prints the token). Stdlib + requests.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Static workspace facts (overridable via env) ──────────────────────────────
JOB_AGENT_LIVE = int(os.environ.get("SOC_JOB_AGENT_LIVE", "813551535938471"))
JOB_EVAL_AGENT = int(os.environ.get("SOC_JOB_EVAL_AGENT", "90645831680247"))

DEMO_HOST_DEFAULT = "WS5"
DEMO_EVENTS_DEFAULT = 50
DEMO_MARKER = "demo_attack"          # _source value + payload marker for cleanup
SILVER = "soc_intelligence.silver.siem_normalized"
INCIDENT = "soc_intelligence.gold.incident"
INCIDENT_EVAL = "soc_intelligence.gold.incident_eval"

ENV_PATH = Path(__file__).resolve().parent / ".env"


# ── Console helpers ───────────────────────────────────────────────────────────
class C:
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    CYN = "\033[36m"
    RST = "\033[0m"


_T0 = time.time()


def _elapsed() -> str:
    return f"{time.time() - _T0:6.1f}s"


def banner(step: str, title: str) -> None:
    bar = "═" * 70
    print(f"\n{C.CYN}{bar}{C.RST}")
    print(f"{C.CYN}║{C.RST} {C.BOLD}{step}{C.RST}  {title}")
    print(f"{C.CYN}║{C.RST} {C.DIM}t+{_elapsed()}  ·  {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC{C.RST}")
    print(f"{C.CYN}{bar}{C.RST}")


def info(msg: str) -> None:
    print(f"  {C.DIM}t+{_elapsed()}{C.RST}  {msg}")


def ok(msg: str) -> None:
    print(f"  {C.GRN}✓{C.RST} {msg}")


def warn(msg: str) -> None:
    print(f"  {C.YEL}!{C.RST} {msg}")


def fail(msg: str) -> None:
    print(f"  {C.RED}✗{C.RST} {msg}")


# ── Config ────────────────────────────────────────────────────────────────────
def load_config() -> dict:
    # The repo's .env is the authoritative source (direnv-mapped). It takes
    # precedence over the process environment, which on this machine may carry a
    # stale DATABRICKS_TOKEN from a login LaunchAgent/~/.secrets. Env vars are
    # used only as a fallback for keys the .env does not define.
    cfg = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in ("DATABRICKS_HOST", "DATABRICKS_TOKEN", "DATABRICKS_WAREHOUSE_ID"):
        if not cfg.get(k) and os.environ.get(k):
            cfg[k] = os.environ[k]
    missing = [k for k in ("DATABRICKS_HOST", "DATABRICKS_TOKEN", "DATABRICKS_WAREHOUSE_ID") if not cfg.get(k)]
    if missing:
        fail(f"Missing required config: {', '.join(missing)} (set in .env or env)")
        sys.exit(2)
    cfg["DATABRICKS_HOST"] = cfg["DATABRICKS_HOST"].rstrip("/")
    return cfg


# ── Databricks REST clients ───────────────────────────────────────────────────
class Databricks:
    def __init__(self, cfg: dict):
        self.host = cfg["DATABRICKS_HOST"]
        self.warehouse = cfg["DATABRICKS_WAREHOUSE_ID"]
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {cfg['DATABRICKS_TOKEN']}"})

    # --- SQL Statements API ---
    def sql(self, statement: str, timeout: int = 300) -> list[dict]:
        """Execute SQL on the configured warehouse; return list of row dicts."""
        r = self.s.post(
            f"{self.host}/api/2.0/sql/statements",
            json={
                "statement": statement,
                "warehouse_id": self.warehouse,
                "wait_timeout": "30s",
                "format": "JSON_ARRAY",
                "disposition": "INLINE",
            },
            timeout=60,
        )
        r.raise_for_status()
        d = r.json()
        stmt_id = d.get("statement_id")
        deadline = time.time() + timeout
        while d["status"]["state"] in ("PENDING", "RUNNING"):
            if time.time() > deadline:
                raise TimeoutError(f"SQL statement {stmt_id} timed out")
            time.sleep(1.5)
            r = self.s.get(f"{self.host}/api/2.0/sql/statements/{stmt_id}", timeout=60)
            r.raise_for_status()
            d = r.json()
        state = d["status"]["state"]
        if state != "SUCCEEDED":
            err = d["status"].get("error", {}).get("message", "unknown error")
            raise RuntimeError(f"SQL failed ({state}): {err}")
        manifest = d.get("manifest", {})
        cols = [c["name"] for c in manifest.get("schema", {}).get("columns", [])]
        data = d.get("result", {}).get("data_array", []) or []
        return [dict(zip(cols, row)) for row in data]

    # --- Jobs API ---
    def run_now(self, job_id: int) -> int:
        r = self.s.post(
            f"{self.host}/api/2.1/jobs/run-now",
            json={"job_id": job_id},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()["run_id"]

    def get_run(self, run_id: int) -> dict:
        r = self.s.get(
            f"{self.host}/api/2.1/jobs/runs/get",
            params={"run_id": run_id},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()

    def poll_run(self, run_id: int, label: str, timeout: int = 900) -> dict:
        """Poll a job run to terminal state with a live status line."""
        start = time.time()
        run_url = f"{self.host}/#job/?/run/{run_id}"
        info(f"{label} run_id={run_id}  ({run_url})")
        last = ""
        while True:
            run = self.get_run(run_id)
            life = run["state"]["life_cycle_state"]
            result = run["state"].get("result_state", "")
            el = time.time() - start
            line = f"  ⏱  {label}: {life:<14} {result:<10} elapsed={el:6.1f}s"
            pad = " " * max(0, len(last) - len(line))
            sys.stdout.write("\r" + line + pad)
            sys.stdout.flush()
            last = line
            if life in ("TERMINATED", "SKIPPED", "INTERNAL_ERROR"):
                sys.stdout.write("\n")
                sys.stdout.flush()
                return run
            if el > timeout:
                sys.stdout.write("\n")
                raise TimeoutError(f"{label} run {run_id} did not finish in {timeout}s")
            time.sleep(4)


# ── Demo steps ────────────────────────────────────────────────────────────────
def inject(db: Databricks, host: str, n: int) -> None:
    banner("STEP 1/4 · INJECT", f"{n}× failed-login (EventID 4625) → {host}")
    info(f"Target table : {SILVER}")
    info(f"Strategy     : burst into the CURRENT minute on existing host '{host}'")
    info(f"               (p90-capped baseline + concentrated spike → high z)")
    users = ["administrator", "admin", "svc_backup", "sqlsvc",
             "helpdesk", "root", "jsmith", "aadmin"]
    user_arr = "array(" + ", ".join(f"'{u}'" for u in users) + ")"
    stmt = f"""
INSERT INTO {SILVER}
  (EventID, host_ip, user_id, ProcessName, CommandLine, ParentProcessName,
   event_ts, event_type, _ingest_ts, _source)
SELECT
  4625                                                            AS EventID,
  '{host}'                                                        AS host_ip,
  element_at({user_arr}, CAST(pmod(i, {len(users)}) AS INT) + 1) AS user_id,
  'C:\\\\Windows\\\\System32\\\\lsass.exe'                          AS ProcessName,
  'demo_attack: failed RDP logon attempt (NTLM)'                  AS CommandLine,
  'C:\\\\Windows\\\\System32\\\\svchost.exe'                        AS ParentProcessName,
  DATEADD(SECOND, CAST(i AS INT), DATE_TRUNC('minute', CURRENT_TIMESTAMP())) AS event_ts,
  'Microsoft-Windows-Security-Auditing'                          AS event_type,
  DATEADD(SECOND, CAST(i AS INT), DATE_TRUNC('minute', CURRENT_TIMESTAMP())) AS _ingest_ts,
  '{DEMO_MARKER}'                                                 AS _source
FROM (SELECT explode(sequence(0, {n - 1})) AS i)
"""
    db.sql(stmt)
    rows = db.sql(
        f"SELECT COUNT(*) AS c, MIN(event_ts) AS first_ts, MAX(event_ts) AS last_ts "
        f"FROM {SILVER} WHERE _source = '{DEMO_MARKER}'"
    )[0]
    ok(f"Injected {rows['c']} events  (window {rows['first_ts']} → {rows['last_ts']})")


def trigger_and_poll_agent(db: Databricks) -> dict:
    banner("STEP 2/4 · TRIGGER", "soc_agent_live  (LangGraph ReAct + dual-LLM)")
    run_id = db.run_now(JOB_AGENT_LIVE)
    ok(f"run-now accepted  job_id={JOB_AGENT_LIVE}")
    banner("STEP 3/4 · POLL", "waiting for the agent run to finish")
    run = db.poll_run(run_id, "soc_agent_live")
    result = run["state"].get("result_state", "")
    if result == "SUCCESS":
        ok(f"Agent run finished: {result}")
    else:
        warn(f"Agent run finished: {result} (continuing to inspect incidents)")
    return run


def max_z(db: Databricks, host: str) -> float:
    try:
        rows = db.sql(
            f"SELECT MAX(z_score) AS z FROM soc_intelligence.gold.score_anomaly('{host}', 60)"
        )
        z = rows[0]["z"] if rows else None
        return float(z) if z is not None else 0.0
    except Exception as exc:  # diagnostic path only
        warn(f"score_anomaly diagnostic failed: {exc}")
        return 0.0


def reveal_incident(db: Databricks, host: str, since_iso: str) -> dict | None:
    banner("STEP 4/4 · REVEAL", "the incident the agent created")
    rows = db.sql(f"""
        SELECT incident_id, host_ip, user_id, tactic, technique_id, severity,
               z_score, confidence, model_used, created_at, payload_json
        FROM {INCIDENT}
        WHERE host_ip = '{host}'
          AND created_at >= TIMESTAMP '{since_iso}'
          AND payload_json LIKE '%{DEMO_MARKER}%'
        ORDER BY created_at DESC
        LIMIT 1
    """)
    if not rows:
        return None
    inc = rows[0]
    print(f"\n  {C.BOLD}{C.GRN}🚨 INCIDENT CREATED{C.RST}")
    print(f"  {C.DIM}{'─' * 60}{C.RST}")
    fields = [
        ("Incident ID", inc["incident_id"]),
        ("Host", inc["host_ip"]),
        ("User (latest)", inc.get("user_id") or "-"),
        ("MITRE Tactic", inc["tactic"]),
        ("Technique", inc["technique_id"]),
        ("Severity", inc["severity"]),
        ("z-score", f"{float(inc['z_score']):.3f}"),
        ("Confidence", f"{float(inc['confidence']):.2f}"),
        ("Model", inc["model_used"]),
        ("Created (UTC)", inc["created_at"]),
    ]
    for label, val in fields:
        print(f"  {C.CYN}{label:<14}{C.RST} {C.BOLD}{val}{C.RST}")
    print(f"  {C.DIM}{'─' * 60}{C.RST}")
    return inc


def reveal_eval(db: Databricks, incident_id: str) -> None:
    banner("STEP 4/4 · EVAL", "incident_eval_agent quality grade")
    run_id = db.run_now(JOB_EVAL_AGENT)
    ok(f"run-now accepted  job_id={JOB_EVAL_AGENT}")
    db.poll_run(run_id, "incident_eval")
    rows = db.sql(f"""
        SELECT quality_grade, quality_score, tactic_valid, technique_valid,
               confidence_valid, severity_valid, zscore_valid, notes, evaluated_at
        FROM {INCIDENT_EVAL}
        WHERE incident_id = '{incident_id}'
        ORDER BY evaluated_at DESC
        LIMIT 1
    """)
    if not rows:
        warn("No eval row found for this incident yet (eval window is <30 min).")
        return
    e = rows[0]
    grade = e["quality_grade"]
    colour = C.GRN if grade in ("A", "B") else C.YEL if grade == "C" else C.RED
    print(f"\n  {C.BOLD}QUALITY GRADE: {colour}{grade}{C.RST}  "
          f"(score {float(e['quality_score']):.2f})")
    checks = [
        ("tactic", e["tactic_valid"]),
        ("technique", e["technique_valid"]),
        ("confidence", e["confidence_valid"]),
        ("severity", e["severity_valid"]),
        ("z>=2.5", e["zscore_valid"]),
    ]
    line = "  ".join(
        f"{C.GRN}✓{C.RST}{name}" if val in (True, "true") else f"{C.RED}✗{C.RST}{name}"
        for name, val in checks
    )
    print(f"  {line}")
    if e.get("notes") and e["notes"] not in ("[]", None):
        print(f"  {C.DIM}notes: {e['notes']}{C.RST}")


def cleanup(db: Databricks, host: str, drop_incidents: bool = True) -> None:
    banner("CLEANUP", "removing injected demo state for repeatability")
    before = db.sql(f"SELECT COUNT(*) AS c FROM {SILVER} WHERE _source = '{DEMO_MARKER}'")[0]["c"]
    db.sql(f"DELETE FROM {SILVER} WHERE _source = '{DEMO_MARKER}'")
    ok(f"Deleted {before} injected event(s) from silver.siem_normalized")
    if drop_incidents:
        inc_ids = [r["incident_id"] for r in db.sql(
            f"SELECT incident_id FROM {INCIDENT} "
            f"WHERE host_ip = '{host}' AND payload_json LIKE '%{DEMO_MARKER}%'"
        )]
        if inc_ids:
            id_list = ", ".join(f"'{i}'" for i in inc_ids)
            db.sql(f"DELETE FROM {INCIDENT_EVAL} WHERE incident_id IN ({id_list})")
            db.sql(f"DELETE FROM {INCIDENT} WHERE incident_id IN ({id_list})")
            ok(f"Deleted {len(inc_ids)} demo incident(s) + their eval rows")
        else:
            info("No demo incidents to delete.")


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description="Live SOC Triage Agent demo / attack injector.")
    ap.add_argument("--host", default=DEMO_HOST_DEFAULT, help="Demo host (default: WS5)")
    ap.add_argument("--events", type=int, default=DEMO_EVENTS_DEFAULT,
                    help="Number of failed-login events to inject (default: 50)")
    ap.add_argument("--cleanup", action="store_true",
                    help="Delete injected rows + demo incidents and exit")
    ap.add_argument("--keep-incident", action="store_true",
                    help="With --cleanup, keep demo incidents (only delete silver rows)")
    args = ap.parse_args()

    cfg = load_config()
    db = Databricks(cfg)
    print(f"{C.BOLD}SOC Triage Agent — Live Demo{C.RST}")
    print(f"{C.DIM}workspace: {cfg['DATABRICKS_HOST']}  ·  warehouse: {cfg['DATABRICKS_WAREHOUSE_ID']}{C.RST}")

    if args.cleanup:
        cleanup(db, args.host, drop_incidents=not args.keep_incident)
        print(f"\n{C.GRN}Cleanup complete.{C.RST}")
        return 0

    since_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    inject(db, args.host, args.events)
    trigger_and_poll_agent(db)
    inc = reveal_incident(db, args.host, since_iso)

    if not inc:
        z = max_z(db, args.host)
        banner("RESULT", "no incident created")
        fail(f"No incident written for host '{args.host}'.")
        fail(f"Diagnostic: max z-score from score_anomaly('{args.host}', 60) = {z:.3f} "
             f"(escalation gate is z > 1.5).")
        return 1

    reveal_eval(db, inc["incident_id"])
    banner("DONE", "demo complete")
    ok(f"Incident {inc['incident_id'][:8]} created, classified, and evaluated.")
    info(f"Re-run repeatable: python demo_attack.py --cleanup && python demo_attack.py")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
