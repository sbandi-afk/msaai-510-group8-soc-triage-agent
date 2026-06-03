"""Mock fixtures — let the whole project run with ZERO creds.

These fixtures stand in for:

1. **Sai's gold UC functions** (`score_anomaly`, `classify_threat`,
   `get_exposed_assets`) — mocked so the agent loop runs without a live
   Databricks connection.
2. **External threat-intel APIs** (VirusTotal, Shodan) — mocked because no API
   keys are available *and* because the gold `host_ip` column actually holds a
   Windows hostname (e.g. ``WORKSTATION5``), not a routable IP, so a real VT/IP
   or Shodan lookup would be meaningless anyway.
3. **NVD/CVE** — a static fallback used only when offline.
4. **LLM completions** — deterministic canned outputs so the dual-LLM eval and
   the ReAct loop run without any model endpoint.

All values are clearly synthetic and documented as such in the notebooks.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Sample SIEM events (shape matches silver.siem_normalized columns the agent
# reads). EventIDs are real Windows/Sysmon IDs the ETL filters to.
# ---------------------------------------------------------------------------
SAMPLE_EVENTS: List[Dict[str, Any]] = [
    {
        "EventID": 4776,
        "host_ip": "WORKSTATION5",       # NB: a hostname, not an IP (gold reality)
        "user_id": "svc_backup",
        "ProcessName": "lsass.exe",
        "CommandLine": "",
        "event_type": "Security",
        "event_ts": "2026-05-31T02:14:07Z",
    },
    {
        "EventID": 4688,
        "host_ip": "WORKSTATION6",
        "user_id": "jdoe",
        "ProcessName": "powershell.exe",
        "CommandLine": "powershell -enc SQBFAFgA...",
        "event_type": "Security",
        "event_ts": "2026-05-31T03:41:22Z",
    },
    {
        "EventID": 4697,
        "host_ip": "FILESRV1",
        "user_id": "administrator",
        "ProcessName": "services.exe",
        "CommandLine": "sc create evil binpath= C:\\temp\\x.exe",
        "event_type": "Security",
        "event_ts": "2026-05-31T05:02:51Z",
    },
    {
        "EventID": 4624,
        "host_ip": "DC01",
        "user_id": "admin_remote",
        "ProcessName": "winlogon.exe",
        "CommandLine": "",
        "event_type": "Security",
        "event_ts": "2026-05-31T06:18:30Z",
    },
    {
        "EventID": 4688,
        "host_ip": "WORKSTATION2",
        "user_id": "analyst1",
        "ProcessName": "excel.exe",
        "CommandLine": "EXCEL.EXE /dde",
        "event_type": "Security",
        "event_ts": "2026-05-31T09:55:10Z",
    },
]

# z-scores keyed by host so anomalous hosts cross the 2.5 threshold and a
# benign one stays under it (drives true/false positive behaviour in eval).
_MOCK_ZSCORES: Dict[str, float] = {
    "WORKSTATION5": 3.82,
    "WORKSTATION6": 4.51,
    "FILESRV1": 3.10,
    "DC01": 2.95,
    "WORKSTATION2": 0.61,   # benign — should NOT escalate
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Gold UC function mocks — return shapes match the ACTUAL shipped signatures.
# ---------------------------------------------------------------------------
def mock_score_anomaly(p_host_ip: str, p_window_min: int = 60) -> List[Dict[str, Any]]:
    """Mock of the TABLE-VALUED ``gold.score_anomaly(p_host_ip, p_window_min)``.

    Returns a list of rows with the real column set:
    host_ip, event_count, baseline_mean, baseline_std, z_score, window_start,
    computed_at.
    """
    z = _MOCK_ZSCORES.get(p_host_ip, 1.2)
    base_mean = 8.0
    base_std = 3.0
    event_count = int(round(base_mean + z * base_std))
    return [
        {
            "host_ip": p_host_ip,
            "event_count": event_count,
            "baseline_mean": base_mean,
            "baseline_std": base_std,
            "z_score": round(z, 4),
            "window_start": _now(),
            "computed_at": _now(),
        }
    ]


def mock_get_exposed_assets() -> List[Dict[str, Any]]:
    """Mock of TABLE-VALUED ``gold.get_exposed_assets()`` (no args)."""
    rows = []
    for host in ["WORKSTATION5", "WORKSTATION6", "FILESRV1", "DC01", "WORKSTATION2"]:
        up = host.upper()
        if "DC" in up:
            flag = "Domain Controller -- high value target"
        elif "SRV" in up or "SVR" in up:
            flag = "Server -- elevated risk"
        else:
            flag = "Workstation -- standard risk"
        rows.append({"host_ip": host, "risk_flag": flag, "assessed_at": _now()})
    return rows


def mock_classify_threat(event_payload: str) -> str:
    """Local re-implementation of Sai's ``gold.classify_threat`` rule engine.

    Mirrors the exact rules shipped in the ETL notebook so behaviour matches
    the live UC function. Input: JSON string. Output: JSON string with
    ``{tactic, technique_id, confidence}``.
    """
    try:
        p = json.loads(event_payload)
    except Exception:  # noqa: BLE001
        return json.dumps({"tactic": "unknown", "technique_id": "T0000", "confidence": 0.0})

    eid = int(p.get("EventID", 0) or 0)
    proc = str(p.get("ProcessName", "")).lower()

    if eid in (4776, 4625):
        return json.dumps({"tactic": "Credential Access", "technique_id": "T1110", "confidence": 0.85})
    if eid == 4624:
        return json.dumps({"tactic": "Lateral Movement", "technique_id": "T1078", "confidence": 0.70})
    if eid == 4688 and any(x in proc for x in ["powershell", "wmic", "cmd", "mshta", "rundll32", "regsvr32"]):
        return json.dumps({"tactic": "Execution", "technique_id": "T1059", "confidence": 0.82})
    if eid == 4688:
        return json.dumps({"tactic": "Execution", "technique_id": "T1106", "confidence": 0.65})
    if eid == 4697:
        return json.dumps({"tactic": "Persistence", "technique_id": "T1543", "confidence": 0.88})
    if eid == 4720:
        return json.dumps({"tactic": "Persistence", "technique_id": "T1136", "confidence": 0.90})
    if eid in (7, 8, 10):
        return json.dumps({"tactic": "Defense Evasion", "technique_id": "T1055", "confidence": 0.78})
    if eid in (11, 13):
        return json.dumps({"tactic": "Discovery", "technique_id": "T1083", "confidence": 0.60})
    if eid == 3:
        return json.dumps({"tactic": "Lateral Movement", "technique_id": "T1021", "confidence": 0.72})
    if eid == 1 and any(x in proc for x in ["powershell", "wmic", "cmd"]):
        return json.dumps({"tactic": "Execution", "technique_id": "T1059", "confidence": 0.80})
    return json.dumps({"tactic": "unknown", "technique_id": "T0000", "confidence": 0.30})


# ---------------------------------------------------------------------------
# External API mocks
# ---------------------------------------------------------------------------
def mock_virustotal(ip_or_host: str) -> Dict[str, Any]:
    """Synthetic VirusTotal IP-reputation response (normalized)."""
    # Make a couple of hosts look bad so enrichment is meaningful.
    bad = ip_or_host in {"WORKSTATION6", "FILESRV1"}
    return {
        "indicator": ip_or_host,
        "malicious": 7 if bad else 0,
        "suspicious": 3 if bad else 1,
        "harmless": 40 if bad else 62,
        "undetected": 12,
        "reputation": -34 if bad else 5,
        "verdict": "malicious" if bad else "clean",
        "source": "mock",
    }


def mock_shodan(ip_or_host: str) -> Dict[str, Any]:
    """Synthetic Shodan host response (normalized)."""
    catalog = {
        "FILESRV1": {"ports": [445, 3389, 139], "banners": ["SMB", "RDP", "NetBIOS"]},
        "DC01": {"ports": [88, 389, 636, 445], "banners": ["Kerberos", "LDAP", "LDAPS", "SMB"]},
        "WORKSTATION6": {"ports": [3389], "banners": ["RDP"]},
    }
    info = catalog.get(ip_or_host, {"ports": [], "banners": []})
    return {
        "indicator": ip_or_host,
        "ports": info["ports"],
        "banners": info["banners"],
        "os": "Windows",
        "source": "mock",
    }


def mock_nvd(software_or_keyword: str) -> List[Dict[str, Any]]:
    """Static CVE fixture used when offline (or VT/Shodan are mocked)."""
    table = {
        "RDP": [
            {"cve_id": "CVE-2019-0708", "cvss": 9.8, "summary": "BlueKeep RDP RCE in Remote Desktop Services."},
        ],
        "SMB": [
            {"cve_id": "CVE-2017-0144", "cvss": 8.1, "summary": "EternalBlue SMBv1 remote code execution."},
        ],
        "LDAP": [
            {"cve_id": "CVE-2022-26923", "cvss": 8.8, "summary": "AD CS privilege escalation via certificate templates."},
        ],
    }
    key = (software_or_keyword or "").upper()
    for k, v in table.items():
        if k in key:
            return v
    return [
        {"cve_id": "CVE-2021-34527", "cvss": 8.8, "summary": "PrintNightmare Windows Print Spooler RCE (generic fallback)."}
    ]


# ---------------------------------------------------------------------------
# Mock LLM completions
# ---------------------------------------------------------------------------
# Two calibrations so the dual-LLM comparison shows differences even offline.
# Documented in the eval notebook as a simulated comparison; a grader points
# LLM_MODEL / LLM_MODEL_B at two real Databricks endpoints to get live numbers.
_MODEL_CALIBRATION = {
    # model_name_substring -> (confidence_delta, priority_bias, verbosity)
    "70b": (0.00, 0, "concise"),
    "dbrx": (-0.07, 0, "verbose"),
    "gpt-4o-mini": (0.03, 0, "concise"),
    "gpt-4o": (0.05, 1, "verbose"),
}


def _calibration_for(model: str):
    m = (model or "").lower()
    for key, val in _MODEL_CALIBRATION.items():
        if key in m:
            return val
    return (0.0, 0, "concise")


def mock_classify_and_ticket_completion(context: Dict[str, Any], model: str) -> Dict[str, Any]:
    """Deterministic stand-in for the LLM call inside ``classify_and_ticket``.

    Uses the rule-based classifier for the tactic/technique (realistic), then
    derives a priority (1-5) from z-score + reputation, applying a small
    per-model calibration so two models differ on the same input.
    """
    conf_delta, prio_bias, verbosity = _calibration_for(model)

    payload = context.get("event_payload", {})
    base = json.loads(mock_classify_threat(json.dumps(payload)))

    z = float(context.get("z_score", 0.0) or 0.0)
    rep = context.get("reputation", {}) or {}
    malicious = int(rep.get("malicious", 0) or 0)

    # Priority heuristic 1-5.
    priority = 1
    if z >= 2.5:
        priority += 2
    if z >= 4.0:
        priority += 1
    if malicious >= 5:
        priority += 1
    priority = max(1, min(5, priority + prio_bias))

    severity = {1: "LOW", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}[priority]
    confidence = round(min(0.99, max(0.0, float(base["confidence"]) + conf_delta)), 3)

    summary = (
        f"[{model}] {base['tactic']} ({base['technique_id']}) on "
        f"{context.get('host_ip')} — z={z:.2f}, VT malicious={malicious}."
    )
    if verbosity == "verbose":
        summary += " Recommend isolating host and rotating affected credentials."

    return {
        "tactic": base["tactic"],
        "technique_id": base["technique_id"],
        "confidence": confidence,
        "priority": priority,
        "severity": severity,
        "summary": summary,
    }
