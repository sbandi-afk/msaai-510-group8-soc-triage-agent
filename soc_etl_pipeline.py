# Databricks notebook source
# /// script
# [tool.databricks.environment]
# environment_version = "2"
# ///
# MAGIC %md
# MAGIC # SOC Intelligence -- ETL Pipeline
# MAGIC ---
# MAGIC **Project:** MSAAI-510 Group 8 -- AI-Powered SOC Triage Agent
# MAGIC **Workspace:** `soc_intelligence` (Unity Catalog)
# MAGIC **Notebook:** `soc_etl_pipeline`
# MAGIC **Last updated:** 2026-05-31
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Use Case
# MAGIC This pipeline ingests real-world Windows attack simulation data from the
# MAGIC [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) and builds a
# MAGIC production-ready Delta Lake medallion architecture that powers an AI threat detection agent.
# MAGIC
# MAGIC The agent autonomously:
# MAGIC - Detects anomalous host behaviour using statistical z-score analysis
# MAGIC - Classifies threats using MITRE ATT&CK tactics and techniques
# MAGIC - Cross-references live CVE intelligence from the NIST NVD API
# MAGIC - Generates structured incident tickets for SOC analyst review
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Architecture -- Medallion Lakehouse
# MAGIC
# MAGIC ```
# MAGIC GitHub (OTRF)                    Unity Catalog: soc_intelligence
# MAGIC -------------                    --------------------------------------------------
# MAGIC                                  BRONZE              SILVER            GOLD
# MAGIC credential_access  |             siem_raw_event  ->  siem_normalized  score_anomaly()
# MAGIC defense_evasion    |  ETL        (51,400 rows)   ->  host             classify_threat()
# MAGIC execution          |  Pipeline   (raw JSON,      ->  user_account     get_exposed_assets()
# MAGIC lateral_movement   |             all fields)                           incident (tickets)
# MAGIC persistence        |
# MAGIC privilege_escal.   |
# MAGIC discovery          |
# MAGIC ```
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Pipeline Steps
# MAGIC
# MAGIC | Step | Description | Output |
# MAGIC |------|-------------|--------|
# MAGIC | 0 | Create catalog, schemas, and UC Volume (idempotent DDL) | Infrastructure |
# MAGIC | 1 | Download OTRF attack scenario ZIPs from GitHub API | UC Volume |
# MAGIC | 2 | Extract JSON from ZIPs, ingest to bronze Delta table | `bronze.siem_raw_event` |
# MAGIC | 3 | Filter priority EventIDs, normalize to silver tables | `silver.*` (3 tables) |
# MAGIC | 4 | Register z-score anomaly detection function | `gold.score_anomaly()` |
# MAGIC | 5 | Register MITRE ATT&CK rule-based classifier | `gold.classify_threat()` |
# MAGIC | 6 | Register exposed asset risk assessment function | `gold.get_exposed_assets()` |
# MAGIC | 7 | Create incident tracking table | `gold.incident` |
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Reproducibility
# MAGIC This notebook is **fully idempotent** -- safe to re-run at any time.
# MAGIC To rebuild the entire stack from scratch:
# MAGIC ```sql
# MAGIC DROP CATALOG soc_intelligence CASCADE;
# MAGIC ```
# MAGIC Then re-run this notebook. Everything is recreated automatically -- no manual steps required.
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Dependencies
# MAGIC - `requests` -- HTTP calls to GitHub API and NVD API
# MAGIC - All other imports (`zipfile`, `shutil`, `io`, `os`, `json`) are Python standard library
# MAGIC - PySpark and `dbutils` are provided by the Databricks runtime

# COMMAND ----------

# MAGIC %md
# MAGIC ## Install Dependencies

# COMMAND ----------

# MAGIC %pip install requests --quiet

# COMMAND ----------

# Confirm runtime environment
import sys, requests, pyspark
print(f"Python        : {sys.version.split()[0]}")
print(f"PySpark       : {pyspark.__version__}")
print(f"requests      : {requests.__version__}")
print(f"Databricks UC : soc_intelligence (target catalog)")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 0 -- Infrastructure Setup
# MAGIC > Creates the Unity Catalog catalog, three medallion schemas, and the raw file Volume.
# MAGIC > All statements use `IF NOT EXISTS` -- safe to re-run on an existing workspace.

# COMMAND ----------

print("Setting up infrastructure...")

spark.sql("""
    CREATE CATALOG IF NOT EXISTS soc_intelligence
    COMMENT 'Cybersecurity threat detection agent -- OTRF + MCP pipeline'
""")
print("  [OK] catalog  : soc_intelligence")

for schema, comment in [
    ("bronze", "Raw ingest layer -- OTRF Windows Event Log JSON"),
    ("silver", "Normalized layer -- filtered, typed, standardized events"),
    ("gold",   "Computed outputs -- UC functions, anomaly scores, incidents"),
]:
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS soc_intelligence.{schema} COMMENT '{comment}'")
    print(f"  [OK] schema   : soc_intelligence.{schema}")

spark.sql("""
    CREATE VOLUME IF NOT EXISTS soc_intelligence.bronze.otrf_raw
    COMMENT 'Raw OTRF Security Dataset ZIP files'
""")
print("  [OK] volume   : soc_intelligence.bronze.otrf_raw")
print("\nInfrastructure ready.")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 1 -- Download OTRF Datasets from GitHub
# MAGIC > Queries the GitHub API for the OTRF Security Datasets repository and downloads
# MAGIC > up to 2 ZIP files per ATT&CK tactic (7 tactics = up to 14 ZIPs).
# MAGIC > Already-cached ZIPs are skipped on re-runs for efficiency.

# COMMAND ----------

import os, io, json, zipfile, requests, shutil
from pyspark.sql.functions import col, lit, current_timestamp
from pyspark.sql.types import IntegerType

VOLUME_PATH  = "/Volumes/soc_intelligence/bronze/otrf_raw"
EXTRACT_BASE = "/Volumes/soc_intelligence/bronze/otrf_raw/extracted"
GITHUB_API   = "https://api.github.com/repos/OTRF/Security-Datasets/contents/datasets/atomic/windows"

# ATT&CK tactics to pull from OTRF
TACTIC_PATHS = [
    "datasets/atomic/windows/credential_access/host",
    "datasets/atomic/windows/defense_evasion/host",
    "datasets/atomic/windows/execution/host",
    "datasets/atomic/windows/lateral_movement/host",
    "datasets/atomic/windows/persistence/host",
    "datasets/atomic/windows/privilege_escalation/host",
    "datasets/atomic/windows/discovery/host",
]

os.makedirs(VOLUME_PATH,  exist_ok=True)
os.makedirs(EXTRACT_BASE, exist_ok=True)

session = requests.Session()
session.headers.update({"User-Agent": "soc-agent-etl/1.0"})

downloaded, skipped = [], []

for tactic_path in TACTIC_PATHS:
    tactic_name = tactic_path.split("/")[3]
    sub_path    = "/".join(tactic_path.split("/")[3:])
    print(f"\nFetching: {tactic_name}")

    try:
        resp = session.get(f"{GITHUB_API}/{sub_path}", timeout=15)
        resp.raise_for_status()
        files = resp.json()
    except Exception as e:
        print(f"  WARNING: Could not list tactic: {e}")
        continue

    zips = [f for f in files if isinstance(f, dict) and f.get("name","").endswith(".zip")][:2]
    for z in zips:
        dest = f"{VOLUME_PATH}/{z['name']}"
        if os.path.exists(dest) and os.path.getsize(dest) > 1000:
            print(f"  Cached   : {z['name']}")
            skipped.append(z['name'])
            continue
        try:
            r = session.get(z["download_url"], timeout=60)
            r.raise_for_status()
            with open(dest, "wb") as f:
                f.write(r.content)
            print(f"  Downloaded: {z['name']} ({round(os.path.getsize(dest)/1024, 1)} KB)")
            downloaded.append(z['name'])
        except Exception as e:
            print(f"  FAILED    : {z['name']} -- {e}")

all_zips = [f for f in os.listdir(VOLUME_PATH) if f.endswith(".zip")]
print(f"\n{'-'*50}")
print(f"  Downloaded : {len(downloaded):>3} new ZIPs")
print(f"  Cached     : {len(skipped):>3} skipped")
print(f"  Total ZIPs : {len(all_zips):>3} in Volume")
print(f"{'-'*50}")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 2 -- Bronze Ingestion
# MAGIC > Extracts JSON event logs from each ZIP and ingests them into the bronze Delta table.
# MAGIC > Uses `_metadata.file_path` (UC-compatible) to track the source file per row.
# MAGIC > Write mode is **overwrite** -- the table is fully refreshed on each run.

# COMMAND ----------

# Clear extraction staging area for a clean run
if os.path.exists(EXTRACT_BASE):
    shutil.rmtree(EXTRACT_BASE)
os.makedirs(EXTRACT_BASE, exist_ok=True)

total_files = 0
for zip_name in all_zips:
    out_dir = f"{EXTRACT_BASE}/{zip_name.replace('.zip', '')}"
    os.makedirs(out_dir, exist_ok=True)
    try:
        with open(f"{VOLUME_PATH}/{zip_name}", "rb") as f:
            zf = zipfile.ZipFile(io.BytesIO(f.read()))
            members = [m for m in zf.namelist() if m.endswith((".json", ".jsonl"))]
            for m in members:
                with open(f"{out_dir}/{os.path.basename(m)}", "wb") as out:
                    out.write(zf.read(m))
                total_files += 1
        print(f"  [OK] {zip_name:<60} {len(members):>2} file(s)")
    except Exception as e:
        print(f"  [FAILED] {zip_name}: {e}")

print(f"\n  Total JSON files extracted: {total_files}")
if total_files == 0:
    raise Exception("No JSON files extracted -- check ZIP contents in Volume.")

df_bronze = (
    spark.read
        .option("recursiveFileLookup", "true")
        .option("inferSchema", "true")
        .option("multiLine", "true")
        .json(EXTRACT_BASE)
        .withColumn("_ingest_ts", current_timestamp())
        .withColumn("_source",    col("_metadata.file_path"))
)
bronze_count = df_bronze.count()

df_bronze.write.format("delta") \
    .mode("overwrite") \
    .option("mergeSchema", "true") \
    .saveAsTable("soc_intelligence.bronze.siem_raw_event")

print(f"\n  [OK] bronze.siem_raw_event written -- {bronze_count:,} rows")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 3 -- Silver Normalization
# MAGIC > Filters to 13 priority Windows EventIDs covering 85%+ of MITRE ATT&CK tactics.
# MAGIC > Renames fields to standard names and produces three Silver tables:
# MAGIC > - `siem_normalized` -- event-level records
# MAGIC > - `host` -- unique asset inventory with criticality tier
# MAGIC > - `user_account` -- unique identities from logon/creation events

# COMMAND ----------

# Priority EventIDs -- Windows Security + Sysmon
PRIORITY_EVENT_IDS = [
    4624,  # Successful logon
    4625,  # Failed logon
    4688,  # Process creation
    4697,  # Service installation
    4720,  # User account created
    4776,  # Credential validation
    1,     # Sysmon: process create
    3,     # Sysmon: network connection
    7,     # Sysmon: image loaded
    8,     # Sysmon: CreateRemoteThread
    10,    # Sysmon: process access
    11,    # Sysmon: file create
    13,    # Sysmon: registry value set
]

df_raw = spark.read.table("soc_intelligence.bronze.siem_raw_event")
avail  = set(df_raw.columns)

def sc(name, alias, cast=None):
    """Return column by name if it exists, else null (typed as STRING) -- always with an explicit alias.
    Casting lit(None) to StringType ensures Parquet writes the column physically,
    preventing Delta schema/index mismatches on columns absent from source data."""
    if name not in avail:
        c = lit(None).cast("string")
    else:
        c = col(f"`{name}`") if name.startswith("@") else col(name)
        if cast:
            c = c.cast(cast)
    return c.alias(alias)

df_normalized = (
    df_raw
        .withColumn("EventID_int", col("EventID").cast(IntegerType()))
        .filter(col("EventID_int").isin(PRIORITY_EVENT_IDS))
        .select(
            col("EventID_int").alias("EventID"),
            sc("Hostname",          "host_ip"),
            sc("SubjectUserName",   "user_id"),
            sc("ProcessName",       "ProcessName"),
            sc("CommandLine",       "CommandLine"),
            sc("ParentProcessName", "ParentProcessName"),
            sc("@timestamp",        "event_ts",   cast="timestamp"),
            sc("Channel",           "event_type"),
            col("_ingest_ts"),
            col("_source")
        )
)

norm_count = df_normalized.count()
df_normalized.write.format("delta").mode("overwrite").option("mergeSchema", "true") \
    .saveAsTable("soc_intelligence.silver.siem_normalized")
print(f"  [OK] silver.siem_normalized  -- {norm_count:,} rows")

df_host = (
    df_normalized.select("host_ip").distinct()
        .withColumn("criticality_tier", lit("medium"))
        .withColumn("os", lit("Windows"))
)
df_host.write.format("delta").mode("overwrite").saveAsTable("soc_intelligence.silver.host")
print(f"  [OK] silver.host             -- {df_host.count():,} rows")

df_users = (
    df_normalized.filter(col("EventID").isin([4624, 4720]))
        .select("user_id", "host_ip", "event_ts").distinct()
)
df_users.write.format("delta").mode("overwrite").saveAsTable("soc_intelligence.silver.user_account")
print(f"  [OK] silver.user_account     -- {df_users.count():,} rows")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 4 -- Register `score_anomaly()` SQL UC Function
# MAGIC > Table-valued SQL function that computes a **z-score** for event volume on a given host
# MAGIC > over a rolling time window versus a 24-hour baseline.
# MAGIC > A z-score above **2.5** is treated as an anomaly by the agent.

# COMMAND ----------

spark.sql("""
CREATE OR REPLACE FUNCTION soc_intelligence.gold.score_anomaly(
  p_host_ip    STRING  COMMENT 'Host IP or hostname to score',
  p_window_min INT     COMMENT 'Rolling window in minutes'
)
RETURNS TABLE (
  host_ip       STRING,
  event_count   BIGINT,
  baseline_mean DOUBLE,
  baseline_std  DOUBLE,
  z_score       DOUBLE,
  window_start  TIMESTAMP,
  computed_at   TIMESTAMP
)
COMMENT 'Computes z-score anomaly for event volume on a given host over the last 24h.'
RETURN
  WITH windowed AS (
    SELECT host_ip, COUNT(*) AS event_count,
           DATE_TRUNC('minute', event_ts) AS window_start
    FROM soc_intelligence.silver.siem_normalized
    WHERE host_ip = p_host_ip
      AND event_ts >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP())
    GROUP BY host_ip, DATE_TRUNC('minute', event_ts)
  ),
  stats AS (
    SELECT host_ip,
           AVG(event_count)    AS baseline_mean,
           STDDEV(event_count) AS baseline_std
    FROM windowed GROUP BY host_ip
  ),
  latest AS (
    SELECT * FROM windowed
    WHERE window_start >= DATEADD(MINUTE, -p_window_min, CURRENT_TIMESTAMP())
  )
  SELECT l.host_ip, l.event_count, s.baseline_mean, s.baseline_std,
    CASE WHEN s.baseline_std = 0 OR s.baseline_std IS NULL THEN 0
         ELSE (l.event_count - s.baseline_mean) / s.baseline_std
    END AS z_score,
    l.window_start,
    CURRENT_TIMESTAMP() AS computed_at
  FROM latest l JOIN stats s ON l.host_ip = s.host_ip
""")
test_rows = spark.sql("SELECT COUNT(*) FROM soc_intelligence.gold.score_anomaly('WORKSTATION5', 60)").collect()[0][0]
print(f"  [OK] score_anomaly() registered -- smoke test returned {test_rows} row(s)")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 5 -- Register `classify_threat()` Python UC Function
# MAGIC > Scalar Python UC function that maps a raw SIEM event JSON payload to a
# MAGIC > **MITRE ATT&CK tactic, technique ID, and confidence score**.
# MAGIC > Currently uses a deterministic rule engine keyed on EventID and process name.
# MAGIC > Replace the body with an MLflow model call to upgrade to an ML-based classifier.

# COMMAND ----------

classify_logic = '''
import json

def classify_threat(event_payload: str) -> str:
    try:
        p = json.loads(event_payload)
    except Exception:
        return json.dumps({"tactic": "unknown", "technique_id": "T0000", "confidence": 0.0})

    eid  = int(p.get("EventID", 0))
    proc = str(p.get("ProcessName", "")).lower()

    # Credential Access
    if eid in [4776, 4625]:
        return json.dumps({"tactic": "Credential Access", "technique_id": "T1110", "confidence": 0.85})
    # Lateral Movement via valid accounts
    if eid == 4624:
        return json.dumps({"tactic": "Lateral Movement",  "technique_id": "T1078", "confidence": 0.70})
    # Execution via scripting interpreter
    if eid == 4688 and any(x in proc for x in ["powershell","wmic","cmd","mshta","rundll32","regsvr32"]):
        return json.dumps({"tactic": "Execution",         "technique_id": "T1059", "confidence": 0.82})
    # Execution via native API
    if eid == 4688:
        return json.dumps({"tactic": "Execution",         "technique_id": "T1106", "confidence": 0.65})
    # Persistence via service creation
    if eid == 4697:
        return json.dumps({"tactic": "Persistence",       "technique_id": "T1543", "confidence": 0.88})
    # Persistence via account creation
    if eid == 4720:
        return json.dumps({"tactic": "Persistence",       "technique_id": "T1136", "confidence": 0.90})
    # Defense Evasion via process injection
    if eid in [7, 8, 10]:
        return json.dumps({"tactic": "Defense Evasion",   "technique_id": "T1055", "confidence": 0.78})
    # Discovery via file/registry enumeration
    if eid in [11, 13]:
        return json.dumps({"tactic": "Discovery",         "technique_id": "T1083", "confidence": 0.60})
    # Lateral Movement via remote services
    if eid == 3:
        return json.dumps({"tactic": "Lateral Movement",  "technique_id": "T1021", "confidence": 0.72})
    # Execution via Sysmon process create
    if eid == 1 and any(x in proc for x in ["powershell","wmic","cmd"]):
        return json.dumps({"tactic": "Execution",         "technique_id": "T1059", "confidence": 0.80})

    return json.dumps({"tactic": "unknown", "technique_id": "T0000", "confidence": 0.30})
'''

spark.sql(f"""
CREATE OR REPLACE FUNCTION soc_intelligence.gold.classify_threat(event_payload STRING)
RETURNS STRING
LANGUAGE PYTHON
COMMENT 'Rule-based MITRE ATT&CK tactic classifier. Input: JSON event payload. Output: JSON with tactic, technique_id, confidence.'
AS $$
{classify_logic}
return classify_threat(event_payload)
$$
""")
test = spark.sql("""
    SELECT soc_intelligence.gold.classify_threat('{"EventID":4697,"ProcessName":"services.exe"}') AS r
""").collect()[0]["r"]
print(f"  [OK] classify_threat() registered")
print(f"       Smoke test -> EventID 4697: {test}")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 6 -- Register `get_exposed_assets()` SQL UC Function
# MAGIC > Table-valued SQL function that returns all hosts from the silver asset inventory
# MAGIC > with a risk flag derived from hostname naming patterns.
# MAGIC > Extend this to join against a live Shodan snapshot once the API key is configured.

# COMMAND ----------

spark.sql("""
CREATE OR REPLACE FUNCTION soc_intelligence.gold.get_exposed_assets()
RETURNS TABLE (
  host_ip     STRING,
  risk_flag   STRING,
  assessed_at TIMESTAMP
)
COMMENT 'Returns hosts from silver.host with a risk flag based on hostname naming patterns. Extend with Shodan join for live port data.'
RETURN
  SELECT
    host_ip,
    CASE
      WHEN UPPER(host_ip) LIKE '%DC%'  THEN 'Domain Controller -- high value target'
      WHEN UPPER(host_ip) LIKE '%SRV%' THEN 'Server -- elevated risk'
      WHEN UPPER(host_ip) LIKE '%SVR%' THEN 'Server -- elevated risk'
      ELSE                                   'Workstation -- standard risk'
    END AS risk_flag,
    CURRENT_TIMESTAMP() AS assessed_at
  FROM soc_intelligence.silver.host
""")
test_count = spark.sql("SELECT COUNT(*) FROM soc_intelligence.gold.get_exposed_assets()").collect()[0][0]
print(f"  [OK] get_exposed_assets() registered -- {test_count} asset(s) assessed")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Step 7 -- Create `gold.incident` Delta Table
# MAGIC > Stores all agent-generated ATT&CK-labeled incident tickets.
# MAGIC > Written by `soc_agent` when: **z-score > 2.5 AND classifier confidence > 0.7**.
# MAGIC > Uses `IF NOT EXISTS` -- existing incidents are never overwritten by the ETL.

# COMMAND ----------

spark.sql("""
CREATE TABLE IF NOT EXISTS soc_intelligence.gold.incident (
  incident_id  STRING    COMMENT 'UUID generated at creation time',
  host_ip      STRING    COMMENT 'Affected host identifier',
  user_id      STRING    COMMENT 'Associated user identity (if available)',
  tactic       STRING    COMMENT 'MITRE ATT&CK tactic (e.g. Credential Access)',
  technique_id STRING    COMMENT 'MITRE ATT&CK technique ID (e.g. T1110)',
  confidence   DOUBLE    COMMENT 'Classifier confidence score (0.0 - 1.0)',
  z_score      DOUBLE    COMMENT 'Anomaly z-score at time of detection',
  severity     STRING    COMMENT 'Severity level: LOW / MEDIUM / HIGH / CRITICAL',
  payload_json STRING    COMMENT 'Raw event payload JSON that triggered this incident',
  created_at   TIMESTAMP COMMENT 'UTC timestamp when incident was created',
  resolved_at  TIMESTAMP COMMENT 'UTC timestamp when resolved -- NULL if still open'
)
USING DELTA
COMMENT 'Agent-generated ATT&CK-labeled incident tickets. Written by soc_agent notebook.'
""")
open_count = spark.sql("SELECT COUNT(*) FROM soc_intelligence.gold.incident WHERE resolved_at IS NULL").collect()[0][0]
print(f"  [OK] gold.incident table ready -- {open_count} open incident(s)")

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Run Summary

# COMMAND ----------

from datetime import datetime

print("=" * 60)
print("  SOC Intelligence ETL -- Completed Successfully")
print(f"  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
print("=" * 60)

print("\n  Infrastructure")
for obj in ["catalog  soc_intelligence",
            "schema   bronze / silver / gold",
            "volume   bronze.otrf_raw"]:
    print(f"    [OK] {obj}")

print("\n  Table Row Counts")
for label, sql in [
    ("bronze.siem_raw_event",  "SELECT COUNT(*) FROM soc_intelligence.bronze.siem_raw_event"),
    ("silver.siem_normalized", "SELECT COUNT(*) FROM soc_intelligence.silver.siem_normalized"),
    ("silver.host",            "SELECT COUNT(*) FROM soc_intelligence.silver.host"),
    ("silver.user_account",    "SELECT COUNT(*) FROM soc_intelligence.silver.user_account"),
    ("gold.incident",          "SELECT COUNT(*) FROM soc_intelligence.gold.incident"),
]:
    n = spark.sql(sql).collect()[0][0]
    print(f"    {'soc_intelligence.' + label:<45} {int(n):>8,} rows")

print("\n  UC Functions Registered")
for fn in ["score_anomaly(p_host_ip, p_window_min)",
           "classify_threat(event_payload)",
           "get_exposed_assets()"]:
    print(f"    [OK] soc_intelligence.gold.{fn}")
