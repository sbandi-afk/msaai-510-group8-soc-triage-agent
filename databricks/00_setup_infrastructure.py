# Databricks notebook source
# MAGIC %md
# MAGIC # SOC Intelligence -- Infrastructure Setup
# MAGIC
# MAGIC **Run once** to bootstrap the entire stack from scratch.
# MAGIC Safe to re-run at any time -- every statement is idempotent.
# MAGIC
# MAGIC Creates:
# MAGIC - Unity Catalog: `soc_intelligence` + schemas `bronze / silver / gold`
# MAGIC - UC Volume: `bronze.otrf_raw`
# MAGIC - Delta tables: `gold.incident`, `gold.incident_eval`
# MAGIC - UC Functions (5): `score_anomaly`, `classify_threat`, `get_exposed_assets`,
# MAGIC   `check_ip_reputation`, `lookup_exposed_ports`
# MAGIC
# MAGIC To rebuild everything from scratch:
# MAGIC ```sql
# MAGIC DROP CATALOG soc_intelligence CASCADE;
# MAGIC ```
# MAGIC Then re-run this notebook.

# COMMAND ----------
# MAGIC %md ## Step 1 -- Catalog, Schemas, Volume

# COMMAND ----------
print("Creating catalog and schemas...")
spark.sql("CREATE CATALOG IF NOT EXISTS soc_intelligence COMMENT 'SOC triage agent -- OTRF + MCP pipeline'")
print("  [OK] catalog: soc_intelligence")

for schema, comment in [
    ("bronze", "Raw ingest layer -- OTRF Windows Event Log JSON"),
    ("silver", "Normalized layer -- filtered, typed, standardized events"),
    ("gold",   "Computed outputs -- UC functions, anomaly scores, incidents"),
]:
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS soc_intelligence.{schema} COMMENT '{comment}'")
    print(f"  [OK] schema:  soc_intelligence.{schema}")

spark.sql("CREATE VOLUME IF NOT EXISTS soc_intelligence.bronze.otrf_raw COMMENT 'Raw OTRF Security Dataset ZIP files'")
print("  [OK] volume:  soc_intelligence.bronze.otrf_raw")
# COMMAND ----------
# MAGIC %md ## Step 2b -- Empty Silver Tables (required before UC function registration)
# MAGIC
# MAGIC score_anomaly() SQL body references silver.siem_normalized.
# MAGIC Databricks validates SQL function bodies at CREATE time, so the table must exist.
# MAGIC The ETL pipeline will populate these with real data.

# COMMAND ----------
spark.sql("USE CATALOG soc_intelligence")

spark.sql("""
CREATE TABLE IF NOT EXISTS soc_intelligence.silver.siem_normalized (
  EventID           INT,
  host_ip           STRING,
  user_id           STRING,
  ProcessName       STRING,
  CommandLine       STRING,
  ParentProcessName STRING,
  event_ts          TIMESTAMP,
  event_type        STRING,
  _ingest_ts        TIMESTAMP,
  _source           STRING
) USING DELTA COMMENT 'Normalized SIEM events -- populated by soc_etl_pipeline'
""")
print("  [OK] silver.siem_normalized (empty shell)")

spark.sql("""
CREATE TABLE IF NOT EXISTS soc_intelligence.silver.host (
  host_ip           STRING,
  criticality_tier  STRING,
  os                STRING
) USING DELTA COMMENT 'Asset inventory -- populated by soc_etl_pipeline'
""")
print("  [OK] silver.host (empty shell)")

spark.sql("""
CREATE TABLE IF NOT EXISTS soc_intelligence.silver.user_account (
  user_id    STRING,
  host_ip    STRING,
  event_ts   TIMESTAMP
) USING DELTA COMMENT 'User identities -- populated by soc_etl_pipeline'
""")
print("  [OK] silver.user_account (empty shell)")


# COMMAND ----------
# MAGIC %md ## Step 2 -- Gold Delta Tables

# COMMAND ----------
spark.sql("USE CATALOG soc_intelligence")
spark.sql("USE SCHEMA gold")

spark.sql("""
CREATE TABLE IF NOT EXISTS soc_intelligence.gold.incident (
  incident_id  STRING    COMMENT 'UUID generated at creation time',
  host_ip      STRING    COMMENT 'Affected host identifier',
  user_id      STRING    COMMENT 'Associated user identity (if available)',
  tactic       STRING    COMMENT 'MITRE ATT&CK tactic',
  technique_id STRING    COMMENT 'MITRE ATT&CK technique ID',
  confidence   DOUBLE    COMMENT 'Classifier confidence score 0.0-1.0',
  z_score      DOUBLE    COMMENT 'Anomaly z-score at detection time',
  severity     STRING    COMMENT 'LOW / MEDIUM / HIGH / CRITICAL',
  payload_json STRING    COMMENT 'Raw event payload JSON',
  created_at   TIMESTAMP COMMENT 'UTC timestamp of creation',
  resolved_at  TIMESTAMP COMMENT 'UTC timestamp of resolution -- NULL if open',
  model_used   STRING    COMMENT 'LLM model that generated the classification'
) USING DELTA COMMENT 'Agent-generated ATT&CK-labeled incident tickets'
""")
print("[OK] gold.incident")

spark.sql("""
CREATE TABLE IF NOT EXISTS soc_intelligence.gold.incident_eval (
  eval_id           STRING    COMMENT 'UUID for this eval run',
  incident_id       STRING    COMMENT 'FK to gold.incident',
  evaluated_at      TIMESTAMP COMMENT 'When this eval was run',
  tactic_valid      BOOLEAN   COMMENT 'Tactic is a known MITRE value',
  technique_valid   BOOLEAN   COMMENT 'Technique ID matches T#### pattern',
  confidence_valid  BOOLEAN   COMMENT 'Confidence between 0.0 and 1.0',
  severity_valid    BOOLEAN   COMMENT 'Severity is LOW/MEDIUM/HIGH/CRITICAL',
  zscore_valid      BOOLEAN   COMMENT 'z_score >= 1.5 (met escalation gate)',
  quality_score     DOUBLE    COMMENT 'Overall score 0.0-1.0',
  quality_grade     STRING    COMMENT 'A/B/C/F',
  notes             STRING    COMMENT 'JSON array of failed checks'
) USING DELTA COMMENT 'Automated quality evaluation of agent-generated incidents'
""")
print("[OK] gold.incident_eval")

# COMMAND ----------
# MAGIC %md ## Step 3 -- UC Function: score_anomaly()

# COMMAND ----------
spark.sql("""
CREATE OR REPLACE FUNCTION soc_intelligence.gold.score_anomaly(
  p_host_ip    STRING COMMENT 'Host IP or hostname to score',
  p_window_min INT    COMMENT 'Rolling window in minutes'
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
COMMENT 'Z-score anomaly detection using p90-capped baseline (robust to historical spikes).'
RETURN
  WITH windowed AS (
    SELECT host_ip, COUNT(*) AS event_count,
           DATE_TRUNC('minute', event_ts) AS window_start
    FROM soc_intelligence.silver.siem_normalized
    WHERE host_ip = p_host_ip
      AND event_ts >= DATEADD(HOUR, -24, CURRENT_TIMESTAMP())
    GROUP BY host_ip, DATE_TRUNC('minute', event_ts)
  ),
  cutoff AS (
    SELECT host_ip,
      PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY event_count) AS p90
    FROM windowed GROUP BY host_ip
  ),
  stats AS (
    SELECT w.host_ip,
      AVG(w.event_count)    AS baseline_mean,
      STDDEV(w.event_count) AS baseline_std
    FROM windowed w
    JOIN cutoff c ON w.host_ip = c.host_ip
    WHERE w.event_count <= c.p90
    GROUP BY w.host_ip
  ),
  latest AS (
    SELECT * FROM windowed
    WHERE window_start >= DATEADD(MINUTE, -p_window_min, CURRENT_TIMESTAMP())
  )
  SELECT l.host_ip, l.event_count, s.baseline_mean, s.baseline_std,
    CASE WHEN s.baseline_std = 0 OR s.baseline_std IS NULL THEN 0.0
         ELSE (l.event_count - s.baseline_mean) / s.baseline_std END AS z_score,
    l.window_start, CURRENT_TIMESTAMP() AS computed_at
  FROM latest l JOIN stats s ON l.host_ip = s.host_ip
""")
print("[OK] gold.score_anomaly() -- p90-filtered robust baseline")

# COMMAND ----------
# MAGIC %md ## Step 4 -- UC Function: classify_threat()

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
    if eid in [4776, 4625]:
        return json.dumps({"tactic": "Credential Access", "technique_id": "T1110", "confidence": 0.85})
    if eid == 4624:
        return json.dumps({"tactic": "Lateral Movement",  "technique_id": "T1078", "confidence": 0.70})
    if eid == 4688 and any(x in proc for x in ["powershell","wmic","cmd","mshta","rundll32","regsvr32"]):
        return json.dumps({"tactic": "Execution",         "technique_id": "T1059", "confidence": 0.82})
    if eid == 4688:
        return json.dumps({"tactic": "Execution",         "technique_id": "T1106", "confidence": 0.65})
    if eid == 4697:
        return json.dumps({"tactic": "Persistence",       "technique_id": "T1543", "confidence": 0.88})
    if eid == 4720:
        return json.dumps({"tactic": "Persistence",       "technique_id": "T1136", "confidence": 0.90})
    if eid in [7, 8, 10]:
        return json.dumps({"tactic": "Defense Evasion",   "technique_id": "T1055", "confidence": 0.78})
    if eid in [11, 13]:
        return json.dumps({"tactic": "Discovery",         "technique_id": "T1083", "confidence": 0.60})
    if eid == 3:
        return json.dumps({"tactic": "Lateral Movement",  "technique_id": "T1021", "confidence": 0.72})
    if eid == 1 and any(x in proc for x in ["powershell","wmic","cmd"]):
        return json.dumps({"tactic": "Execution",         "technique_id": "T1059", "confidence": 0.80})
    return json.dumps({"tactic": "unknown", "technique_id": "T0000", "confidence": 0.30})
'''
spark.sql(f"""
CREATE OR REPLACE FUNCTION classify_threat(event_payload STRING)
RETURNS STRING LANGUAGE PYTHON
COMMENT 'Rule-based MITRE ATT&CK classifier. Input: JSON event payload. Output: tactic, technique_id, confidence.'
AS $$
{classify_logic}
return classify_threat(event_payload)
$$
""")
print("[OK] gold.classify_threat()")

# COMMAND ----------
# MAGIC %md ## Step 5 -- UC Function: get_exposed_assets()

# COMMAND ----------
spark.sql("""
CREATE OR REPLACE FUNCTION get_exposed_assets()
RETURNS TABLE (host_ip STRING, risk_flag STRING, assessed_at TIMESTAMP)
COMMENT 'Host risk flags from silver.host based on hostname patterns.'
RETURN
  SELECT host_ip,
    CASE WHEN UPPER(host_ip) LIKE '%DC%'  THEN 'Domain Controller -- high value target'
         WHEN UPPER(host_ip) LIKE '%SRV%' THEN 'Server -- elevated risk'
         WHEN UPPER(host_ip) LIKE '%SVR%' THEN 'Server -- elevated risk'
         ELSE 'Workstation -- standard risk' END AS risk_flag,
    CURRENT_TIMESTAMP() AS assessed_at
  FROM soc_intelligence.silver.host
""")
print("[OK] gold.get_exposed_assets()")

# COMMAND ----------
# MAGIC %md ## Step 6 -- Governed HTTP Connections (External Access)
# MAGIC
# MAGIC Unity Catalog HTTP connections are host-locked, auditable securables.
# MAGIC The `bearer_token` option is required to skip the default OIDC/DCR auto-
# MAGIC registration (these APIs use API-key auth, not OAuth). The real per-call
# MAGIC keys are injected at query time via SECRET() in the UC functions below --
# MAGIC never hardcoded.

# COMMAND ----------
spark.sql("""
CREATE CONNECTION IF NOT EXISTS abuseipdb_http TYPE HTTP
OPTIONS (host 'https://api.abuseipdb.com', port '443', base_path '/', bearer_token 'unused')
""")
print("[OK] connection: abuseipdb_http (host-locked to api.abuseipdb.com)")

spark.sql("""
CREATE CONNECTION IF NOT EXISTS shodan_http TYPE HTTP
OPTIONS (host 'https://api.shodan.io', port '443', base_path '/', bearer_token 'unused')
""")
print("[OK] connection: shodan_http (host-locked to api.shodan.io)")

# COMMAND ----------
# MAGIC %md ## Step 6b -- UC Function: check_ip_reputation() via AbuseIPDB
# MAGIC
# MAGIC SQL function (NOT Python UDF). Python UDFs run in a network-sandboxed
# MAGIC environment and cannot reach the internet. A SQL function using
# MAGIC http_request() over the governed connection CAN. Key from SECRET().

# COMMAND ----------
# Drop any prior Python-UDF version first (cannot replace Python fn with SQL fn)
spark.sql("DROP FUNCTION IF EXISTS soc_intelligence.gold.check_ip_reputation")
spark.sql("""
CREATE FUNCTION soc_intelligence.gold.check_ip_reputation(ip_address STRING)
RETURNS STRING
COMMENT 'IP reputation via AbuseIPDB over governed connection abuseipdb_http. Key from SECRET(mcp-keys,abuseipdb-key). Returns raw AbuseIPDB JSON (nested .data) or skip marker.'
RETURN
  CASE
    WHEN ip_address IS NULL OR ip_address IN ('WS5','WS6','FILESRV1','localhost','127.0.0.1')
      THEN '{"data":{"abuseConfidenceScore":0},"source":"skipped_private_host"}'
    ELSE http_request(
      conn => 'abuseipdb_http', method => 'GET', path => '/api/v2/check',
      params => map('ipAddress', ip_address, 'maxAgeInDays', '90'),
      headers => map('Key', SECRET('mcp-keys','abuseipdb-key'), 'Accept','application/json')
    ).text
  END
""")
print("[OK] gold.check_ip_reputation() -- SQL/http_request")

# COMMAND ----------
# MAGIC %md ## Step 7 -- UC Function: lookup_exposed_ports() via Shodan

# COMMAND ----------
spark.sql("DROP FUNCTION IF EXISTS soc_intelligence.gold.lookup_exposed_ports")
spark.sql("""
CREATE FUNCTION soc_intelligence.gold.lookup_exposed_ports(ip_address STRING)
RETURNS STRING
COMMENT 'Open ports via Shodan over governed connection shodan_http. Key from SECRET(mcp-keys,shodan-key). Returns raw Shodan JSON or skip marker.'
RETURN
  CASE
    WHEN ip_address IS NULL OR ip_address IN ('WS5','WS6','FILESRV1','localhost','127.0.0.1')
      THEN '{"ports":[],"source":"skipped_private_host"}'
    ELSE http_request(
      conn => 'shodan_http', method => 'GET', path => '/shodan/host/' || ip_address,
      params => map('key', SECRET('mcp-keys','shodan-key'))
    ).text
  END
""")
print("[OK] gold.lookup_exposed_ports() -- SQL/http_request")

# COMMAND ----------
# MAGIC %md ### Smoke test the governed enrichment functions

# COMMAND ----------
import json
rep = spark.sql("SELECT soc_intelligence.gold.check_ip_reputation('185.220.101.1') AS r").collect()[0]["r"]
rep_d = json.loads(rep).get("data", {})
print(f"check_ip_reputation(185.220.101.1): score={rep_d.get('abuseConfidenceScore')} country={rep_d.get('countryCode')} isTor={rep_d.get('isTor')}")

ports = spark.sql("SELECT soc_intelligence.gold.lookup_exposed_ports('8.8.8.8') AS r").collect()[0]["r"]
ports_d = json.loads(ports)
print(f"lookup_exposed_ports(8.8.8.8): ports={ports_d.get('ports')} org={ports_d.get('org')}")

# COMMAND ----------
# MAGIC %md ## Setup Complete

# COMMAND ----------
print("=" * 55)
print("  Infrastructure setup complete")
print("=" * 55)
print("\n  Catalog / Schemas / Volume")
for obj in ["catalog soc_intelligence",
            "schema  bronze / silver / gold",
            "volume  bronze.otrf_raw"]:
    print(f"    [OK] {obj}")
print("\n  Delta Tables")
for tbl in ["gold.incident", "gold.incident_eval"]:
    print(f"    [OK] {tbl}")
print("\n  UC Functions (soc_intelligence.gold.*)")
for fn in ["score_anomaly(host, window_min)",
           "classify_threat(event_payload)",
           "get_exposed_assets()",
           "check_ip_reputation(ip)",
           "lookup_exposed_ports(ip)"]:
    print(f"    [OK] {fn}")
print("\n  Next: run soc_etl_pipeline to ingest data")
print("=" * 55)
